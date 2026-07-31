/*
* GoScans, a collection of network scan modules for infrastructure discovery and information gathering.
*
* Copyright (c) Siemens AG, 2016-2026.
*
* This work is licensed under the terms of the MIT license. For a copy, see the LICENSE file in the top-level
* directory or visit <https://opensource.org/licenses/MIT>.
*
 */

package nuclei

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	nucleitemplates "github.com/projectdiscovery/nuclei/v3/pkg/templates"
	nucleitemplatetypes "github.com/projectdiscovery/nuclei/v3/pkg/templates/types"
	nucleiyaml "github.com/projectdiscovery/nuclei/v3/pkg/utils/yaml"
	"github.com/siemens/GoScans/utils"
	yamlv2 "gopkg.in/yaml.v2"
)

var templateCatalogsMu sync.Mutex                        // Protects the catalog map during lookup and invalidation
var templateCatalogs = make(map[string]*templateCatalog) // Stores one shared catalog for each canonical template root

// templateIgnoreFolders lists top level folders that cannot contain executable scan templates
var templateIgnoreFolders = map[string]struct{}{
	".github": {}, "cloud": {}, "code": {}, "dast": {}, "file": {}, "helpers": {}, "profiles": {}, "workflows": {},
}

// templateIgnoreFiles lists metadata files that must never be parsed as templates
var templateIgnoreFiles = map[string]struct{}{
	".pre-commit-config.yml": {}, "wappalyzer-mapping.yml": {},
}

// templateSource contains the immutable metadata retained by the selection cache
type templateSource struct {
	id   string
	path string
}

// templateCatalog contains the resources shared between isolated Scanner instances
type templateCatalog struct {
	root            string
	parser          *nucleitemplates.Parser
	helperAllowlist map[string]struct{}
	variants        map[string][]string

	selectionMu sync.RWMutex
	portCache   map[int][]templateSource
	hostCache   []templateSource
	hostCached  bool
}

// canonicalTemplateRoot returns the absolute cleaned key used for catalog isolation
func canonicalTemplateRoot(pathTemplates string) (string, error) {

	// Resolve the path once so acquisition and invalidation always use the same key
	root, errRoot := filepath.Abs(filepath.Clean(pathTemplates))
	if errRoot != nil {
		return "", fmt.Errorf("could not resolve absolute path: %w", errRoot)
	}

	// Return the canonical catalog key
	return root, nil
}

// acquireTemplateCatalog returns the process wide cache for pathTemplates
func acquireTemplateCatalog(pathTemplates string) (*templateCatalog, error) {

	// Resolve the canonical cache key before acquiring the shared lock
	root, errRoot := canonicalTemplateRoot(pathTemplates)
	if errRoot != nil {
		return nil, fmt.Errorf("could not resolve templates path: %w", errRoot)
	}

	// Serialize construction to retain only one parser for each template root
	templateCatalogsMu.Lock()
	defer templateCatalogsMu.Unlock()
	if existing := templateCatalogs[root]; existing != nil {
		return existing, nil
	}

	// Discover the immutable helper and template variant metadata eagerly
	helperAllowlist, errHelperAllowlist := discoverHelperFiles(root)
	if errHelperAllowlist != nil {
		return nil, fmt.Errorf("could not discover helper files: %w", errHelperAllowlist)
	}

	variants, errVariants := discoverTemplateVariants(root)
	if errVariants != nil {
		return nil, fmt.Errorf("could not discover split template variants: %w", errVariants)
	}

	// Create and retain the catalog for subsequent scanners
	catalog := &templateCatalog{
		root:            root,
		parser:          nucleitemplates.NewParser(),
		helperAllowlist: helperAllowlist,
		variants:        variants,
		portCache:       make(map[int][]templateSource),
	}
	templateCatalogs[root] = catalog

	// Return the shared catalog
	return catalog, nil
}

// invalidateTemplateCatalog removes a catalog from future lookups
func invalidateTemplateCatalog(pathTemplates string) error {

	// Resolve the same canonical key used during catalog acquisition
	root, errRoot := canonicalTemplateRoot(pathTemplates)
	if errRoot != nil {
		return fmt.Errorf("could not resolve templates path: %w", errRoot)
	}

	// Remove only the matching catalog while active scanners retain their existing pointer
	templateCatalogsMu.Lock()
	delete(templateCatalogs, root)
	templateCatalogsMu.Unlock()

	// Return nil as everything went fine
	return nil
}

// newExecutionParser creates a private parser with the shared parsed template cache
func (catalog *templateCatalog) newExecutionParser() *nucleitemplates.Parser {
	return nucleitemplates.NewParserWithParsedCache(catalog.parser.Cache())
}

// portSources selects templates for a port and caches only their identifiers and paths
func (catalog *templateCatalog) portSources(logger utils.Logger, port int) ([]templateSource, error) {

	// Return an existing immutable selection through the shared read lock
	catalog.selectionMu.RLock()
	cached, exists := catalog.portCache[port]
	catalog.selectionMu.RUnlock()
	if exists {
		return cached, nil
	}

	// Serialize cache misses to avoid concurrent full directory walks during a scan burst
	catalog.selectionMu.Lock()
	defer catalog.selectionMu.Unlock()
	if cached, exists := catalog.portCache[port]; exists {
		return cached, nil
	}

	// Select templates without compiling their protocol requests
	selected := make([]templateSource, 0)
	errWalk := walkTemplateDefinitions(logger, catalog.root, func(path string, template *nucleitemplates.Template) error {

		// Retain only the metadata needed for later engine construction
		if templateRelevantForPort(template, port) {
			selected = append(selected, templateSource{id: template.ID, path: path})
		}

		// Continue walking the template root
		return nil
	})
	if errWalk != nil {
		return nil, fmt.Errorf("could not select templates for port '%d': %w", port, errWalk)
	}

	// Cache and return the immutable selection
	catalog.portCache[port] = selected
	return selected, nil
}

// hostSources selects and caches templates for host scans
func (catalog *templateCatalog) hostSources(logger utils.Logger) ([]templateSource, error) {

	// Return the immutable host selection through the shared read lock
	catalog.selectionMu.RLock()
	cached := catalog.hostCache
	isCached := catalog.hostCached
	catalog.selectionMu.RUnlock()
	if isCached {
		return cached, nil
	}

	// Serialize the initial host selection with other catalog cache misses
	catalog.selectionMu.Lock()
	defer catalog.selectionMu.Unlock()
	if catalog.hostCached {
		return catalog.hostCache, nil
	}

	// Select only protocols supported by host scans
	selected := make([]templateSource, 0)
	errWalk := walkTemplateDefinitions(logger, catalog.root, func(path string, template *nucleitemplates.Template) error {

		// Retain host templates while dropping each parsed body after this callback
		templateType := template.Type()
		if templateType == nucleitemplatetypes.DNSProtocol || templateType == nucleitemplatetypes.WHOISProtocol {
			selected = append(selected, templateSource{id: template.ID, path: path})
		}

		// Continue walking the template root
		return nil
	})
	if errWalk != nil {
		return nil, fmt.Errorf("could not select host templates: %w", errWalk)
	}

	// Cache and return the immutable selection
	catalog.hostCache = selected
	catalog.hostCached = true
	return selected, nil
}

// expandTemplateIds applies the existing split variant behavior without another directory walk
func (catalog *templateCatalog) expandTemplateIds(includeIds, excludeIds []string) ([]string, []string) {
	return expandIds(includeIds, catalog.variants), expandIds(excludeIds, catalog.variants)
}

// expandIds appends cached split variants while preserving the original identifier order
func expandIds(ids []string, variants map[string][]string) []string {

	// Preserve empty input without allocating a replacement slice
	if len(ids) == 0 {
		return ids
	}

	// Copy the input so callers retain ownership of their original slice
	result := append([]string(nil), ids...)
	seen := make(map[string]struct{}, len(result))
	for _, templateId := range result {
		seen[templateId] = struct{}{}
	}

	// Append every unseen variant belonging to a requested base identifier
	for _, templateId := range ids {
		for _, variant := range variants[templateId] {
			if _, exists := seen[variant]; exists {
				continue
			}
			seen[variant] = struct{}{}
			result = append(result, variant)
		}
	}

	// Return the expanded identifier list
	return result
}

// filterTemplateSources applies caller identifier filters to an immutable cached selection
func filterTemplateSources(sources []templateSource, includeIds, excludeIds []string) ([]string, []string) {

	// Prepare fast membership checks for both caller filters
	include := make(map[string]struct{}, len(includeIds))
	for _, templateId := range includeIds {
		include[templateId] = struct{}{}
	}

	exclude := make(map[string]struct{}, len(excludeIds))
	for _, templateId := range excludeIds {
		exclude[templateId] = struct{}{}
	}

	// Copy matching identifiers and paths into slices owned by the caller
	ids := make([]string, 0, len(sources))
	paths := make([]string, 0, len(sources))
	for _, source := range sources {
		if _, blocked := exclude[source.id]; blocked {
			continue
		}
		if len(include) > 0 {
			if _, allowed := include[source.id]; !allowed {
				continue
			}
		}
		ids = append(ids, source.id)
		paths = append(paths, source.path)
	}

	// Return both synchronized selections
	return ids, paths
}

// templateDirIgnored reports whether the given directory is an ignored top level folder
func templateDirIgnored(root, path string) (bool, error) {

	// Resolve the folder relative to the template root
	relativePath, errRelativePath := filepath.Rel(root, path)
	if errRelativePath != nil {
		return false, errRelativePath
	}

	// Only the first path segment decides whether the whole subtree is skipped
	parts := strings.Split(relativePath, string(filepath.Separator))
	if len(parts) > 0 {
		if _, ignored := templateIgnoreFolders[parts[0]]; ignored {
			return true, nil
		}
	}

	// Return that the directory may contain templates
	return false, nil
}

// templateFileSupported reports whether the file name is a parseable template definition
func templateFileSupported(name string) bool {

	// Reject known metadata files that must never be parsed as templates
	if _, ignored := templateIgnoreFiles[name]; ignored {
		return false
	}

	// Accept only the supported YAML extensions
	extension := strings.ToLower(filepath.Ext(name))
	return extension == ".yaml" || extension == ".yml"
}

// discoverTemplateVariants builds the filename based mapping used to expand split variant identifiers
func discoverTemplateVariants(root string) (map[string][]string, error) {

	// Walk all supported template files because split variants can reside in any scan folder
	variants := make(map[string][]string)
	errWalk := filepath.Walk(root, func(path string, info os.FileInfo, errVisit error) error {

		// Forward filesystem errors to the caller
		if errVisit != nil {
			return errVisit
		}

		// Skip ignored top level folders and unsupported files to match the selection walk
		if info.IsDir() {
			ignored, errIgnored := templateDirIgnored(root, path)
			if errIgnored != nil {
				return errIgnored
			}
			if ignored {
				return filepath.SkipDir
			}
			return nil
		}
		if !templateFileSupported(info.Name()) {
			return nil
		}

		// Derive the base identifier from the established underscore suffix format
		templateId := strings.TrimSuffix(info.Name(), filepath.Ext(info.Name()))
		parts := strings.Split(templateId, "_")
		if len(parts) < 2 {
			return nil
		}
		baseId := strings.Join(parts[:len(parts)-1], "_")
		variants[baseId] = append(variants[baseId], templateId)

		// Continue walking the template root
		return nil
	})
	if errWalk != nil {
		return nil, fmt.Errorf("could not discover template variants: %w", errWalk)
	}

	// Return the completed variant mapping
	return variants, nil
}

// walkTemplateDefinitions parses one YAML definition at a time without retaining template bodies
func walkTemplateDefinitions(
	logger utils.Logger,
	root string,
	callback func(path string, template *nucleitemplates.Template) error,
) error {

	// Walk and parse one supported template file at a time
	errWalk := filepath.Walk(root, func(path string, info os.FileInfo, errVisit error) error {

		// Forward filesystem errors to the caller
		if errVisit != nil {
			return errVisit
		}

		// Skip ignored top level folders before visiting their contents
		if info.IsDir() {
			ignored, errIgnored := templateDirIgnored(root, path)
			if errIgnored != nil {
				return errIgnored
			}
			if ignored {
				return filepath.SkipDir
			}
			return nil
		}

		// Skip known metadata and unsupported file types
		if !templateFileSupported(info.Name()) {
			return nil
		}

		// Read and preprocess only the current template definition
		data, errData := os.ReadFile(path)
		if errData != nil {
			return fmt.Errorf("could not read template '%s': %w", path, errData)
		}
		data, errData = nucleiyaml.PreProcess(data)
		if errData != nil {
			logger.Warningf("Could not preprocess Nuclei template '%s': %v", path, errData)
			return nil
		}

		// Decode selection metadata without compiling protocol requests
		template := new(nucleitemplates.Template)
		errDecode := yamlv2.UnmarshalStrict(data, template)
		if errDecode != nil {
			logger.Warningf("Could not parse Nuclei template '%s': %v", path, errDecode)
			return nil
		}

		// Pass the temporary definition to the caller
		return callback(path, template)
	})
	if errWalk != nil {
		return fmt.Errorf("could not walk templates directory: %w", errWalk)
	}

	// Return nil as everything went fine
	return nil
}
