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
	"regexp"
	"strings"

	"github.com/logrusorgru/aurora/v4"
	"github.com/mohae/deepcopy"
	nucleiconfig "github.com/projectdiscovery/nuclei/v3/pkg/catalog/config"
	nucleidisk "github.com/projectdiscovery/nuclei/v3/pkg/catalog/disk"
	nulcleioutput "github.com/projectdiscovery/nuclei/v3/pkg/output"
	nucleiprotocols "github.com/projectdiscovery/nuclei/v3/pkg/protocols"
	nucleiprotocolinit "github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolinit"
	nucleiprotocolstate "github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
	nucleihttp "github.com/projectdiscovery/nuclei/v3/pkg/protocols/http"
	nucleinetwork "github.com/projectdiscovery/nuclei/v3/pkg/protocols/network"
	nucleissl "github.com/projectdiscovery/nuclei/v3/pkg/protocols/ssl"
	nucleitemplates "github.com/projectdiscovery/nuclei/v3/pkg/templates"
	nucleitypes "github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/siemens/GoScans/utils"
)

// portRegex matches port specifications in Nuclei templates
var portRegex = regexp.MustCompile(`:(\d+)`)

// walkTemplates walks the files and folders within the template path to identify, load and parse template files.
// The templateCallback function passed, allows to run certain logic on each of the successfully loaded template files.
// This function walks until an error is returned by fnTemplateCallback.
func walkTemplates(
	logger utils.Logger,
	pathTemplates string,
	fnWalkCallback func(tplPath string, tpl *nucleitemplates.Template) error,
) error {

	// Build minimal options for template parsing: no output, no downloads, no updates
	options := &nucleitypes.Options{
		NoColor:                       true,
		PublicTemplateDisableDownload: true,
	}

	// Initialize protocol state and protocols so templates can be parsed
	_ = nucleiprotocolstate.Init(options)
	_ = nucleiprotocolinit.Init(options)

	// Convert to absolute path to support Nuclei with templates sandbox verification
	pathTemplatesAbs, errPathTemplatesAbs := filepath.Abs(pathTemplates)
	if errPathTemplatesAbs != nil {
		return errPathTemplatesAbs
	}

	// Point Nuclei's sandbox resolver to our template root so helper files are resolved relative to it.
	nucleiconfig.DefaultConfig.SetTemplatesDir(pathTemplatesAbs)

	// Prepare an ExecutorOptions instance which templates.Parse expects
	executorOpts := &nucleiprotocols.ExecutorOptions{
		Output:  new(noopWriter), // No-op: we only parse templates, not execute them
		Options: options,
		Catalog: nucleidisk.NewCatalog(pathTemplatesAbs), // Catalog pointing to the custom template path
		Parser:  nucleitemplates.NewParser(),             // Parser used to read and parse templates
	}

	// Walk templates recursively
	errWalk := filepath.Walk(pathTemplatesAbs, func(tplPath string, tplPathInfo os.FileInfo, err error) error {

		// Check if err holds an error now
		if err != nil {
			return err
		}

		// If the current path is a directory, check if it's an ignored top-level folder
		if tplPathInfo.IsDir() {

			// Skip ignored top level folders while their subtree stays untouched
			ignored, errIgnored := templateDirIgnored(pathTemplatesAbs, tplPath)
			if errIgnored != nil {
				return errIgnored
			}
			if ignored {
				return filepath.SkipDir // SkipDir error will not cause walk to abort but tell it to ignore this path
			}

			// Continue walking
			return nil
		}

		// Skip non-YAML or ignored files
		if !templateFileSupported(tplPathInfo.Name()) {
			return nil
		}

		// Parse template, warn about templates that cannot be parsed but continue walking
		tpl, errTpl := nucleitemplates.Parse(tplPath, nil, executorOpts)
		if errTpl != nil {
			logger.Warningf("Could not parse Nuclei template '%s': %v", tplPath, errTpl)
			return nil
		}

		// Execute action on template
		return fnWalkCallback(tplPath, tpl)
	})

	// Return result
	return errWalk
}

// splitTemplates iterates Nuclei templates and splits files targeting multiple ports
// (splitting SSL, Network and Http requests, etc...)
func splitTemplates(logger utils.Logger, pathTemplates string) error {

	// Prepare action to take on each loaded template
	fnWalkCallback := func(tplPath string, tpl *nucleitemplates.Template) error {

		// Handle SSL request
		if len(tpl.RequestsSSL) > 0 {
			errSplitSsl := splitTemplateSsl(logger, tplPath, tpl)
			if errSplitSsl != nil {
				return errSplitSsl
			}
		}

		// Handle Network request
		if len(tpl.RequestsNetwork) > 0 {
			errSplitNetwork := splitTemplateNetwork(logger, tplPath, tpl)
			if errSplitNetwork != nil {
				return errSplitNetwork
			}
		}

		// Handle HTTP request
		if len(tpl.RequestsHTTP) > 0 {
			errSplitHttp := splitTemplateHttp(logger, tplPath, tpl)
			if errSplitHttp != nil {
				return errSplitHttp
			}
		}

		// Return nil to keep walking
		return nil
	}

	// Walk templates
	errWalk := walkTemplates(logger, pathTemplates, fnWalkCallback)
	if errWalk != nil {
		return errWalk
	}

	// Return nil as everything went fine
	return nil
}

// splitTemplateSsl splits SSL requests into multiple templates if needed.
// A split is performed in the following cases:
//  1. There are multiple hardcoded ports that differ.
//  2. There is at least one hardcoded port and one placeholder port.
//
// If splitting is not needed, the function returns early.
// Otherwise, the default template keeps only placeholder requests,
// and new templates are created for each hardcoded port.
func splitTemplateSsl(logger utils.Logger, path string, tpl *nucleitemplates.Template) error {

	// Get the directory where output files will be written
	dir := filepath.Dir(path)

	// Track placeholder requests, hardcoded requests, and group hardcoded by port
	var placeholderReqs []*nucleissl.Request
	var hardcodedReqs []*nucleissl.Request
	portToReqs := make(map[string][]*nucleissl.Request)

	// Classify each SSL request
	for _, req := range tpl.RequestsSSL {
		if strings.Contains(req.Address, "{{Port}}") {

			// Placeholder request (e.g. {{Port}})
			placeholderReqs = append(placeholderReqs, req)
		} else if portRegex.MatchString(req.Address) {

			// Hardcoded port request (e.g. :443)
			m := portRegex.FindStringSubmatch(req.Address)
			if m != nil && m[1] != "" {
				port := m[1]
				hardcodedReqs = append(hardcodedReqs, req)
				portToReqs[port] = append(portToReqs[port], req)
			}
		}
	}

	// Decide whether splitting is required
	splitNeeded := false
	if len(placeholderReqs) > 0 && len(hardcodedReqs) > 0 {

		// Case 1: mix of placeholder and hardcoded ports
		splitNeeded = true
	} else if len(hardcodedReqs) > 1 {

		// Case 2: multiple different hardcoded ports
		uniq := make(map[string]struct{})
		for _, req := range hardcodedReqs {
			m := portRegex.FindStringSubmatch(req.Address)
			if m != nil && m[1] != "" {
				uniq[m[1]] = struct{}{}
			}
		}
		if len(uniq) > 1 {
			splitNeeded = true
		}
	}

	// Nothing to do if no split required
	if !splitNeeded {
		return nil
	}

	// Rewrite default template: keep only placeholder requests
	if len(placeholderReqs) > 0 {

		// Write template clone
		defaultClone := deepcopy.Copy(tpl).(*nucleitemplates.Template)
		defaultClone.RequestsSSL = placeholderReqs
		defaultClone.ID = tpl.ID // preserve ID for default version
		errWrite := writeTemplate(defaultClone, path)
		if errWrite != nil {
			return fmt.Errorf("could not write default SSL template: %w", errWrite)
		}
	}

	// Create a new template for each hardcoded port
	for port, reqs := range portToReqs {

		// Write template clone
		clone := deepcopy.Copy(tpl).(*nucleitemplates.Template)
		clone.RequestsSSL = reqs
		clone.ID = fmt.Sprintf("%s_%s", tpl.ID, port)
		outPath := filepath.Join(dir, fmt.Sprintf("%s.yaml", clone.ID))
		errWrite := writeTemplate(clone, outPath)
		if errWrite != nil {
			return fmt.Errorf("could not write SSL template for port %s: %w", port, errWrite)
		}
		logger.Debugf("Split template %s into %s", tpl.ID, clone.ID)
	}

	// Return nil as everything went fine
	return nil
}

// splitTemplateNetwork splits network requests into multiple templates if needed.
// A split is performed in the following cases:
//  1. There are multiple distinct hardcoded ports.
//  2. There is at least one hardcoded port and one placeholder port ({{Port}}).
//
// The default template keeps only {{Port}} requests if they exist.
// Otherwise, the first hardcoded port is used as the default, and the remaining
// ports each get their own new template file.
func splitTemplateNetwork(logger utils.Logger, path string, tpl *nucleitemplates.Template) error {

	// Track placeholder requests and group hardcoded requests by port
	var defaultRequests []*nucleinetwork.Request
	portBuckets := make(map[string][]*nucleinetwork.Request)

	// Classify each network request
	for _, req := range tpl.RequestsNetwork {
		if strings.Contains(req.Port, "{{Port}}") {

			// Placeholder port ({{Port}})
			defaultRequests = append(defaultRequests, req)
		} else {

			// Hardcoded or comma-separated ports
			ports := strings.Split(req.Port, ",")
			for _, p := range ports {
				p = strings.TrimSpace(p)
				if p != "" {
					clone := deepcopy.Copy(req).(*nucleinetwork.Request)
					clone.Port = p
					portBuckets[p] = append(portBuckets[p], clone)
				}
			}
		}
	}

	// Decide whether splitting is required
	splitNeeded := false
	if len(defaultRequests) > 0 && len(portBuckets) > 0 {

		// Case 1: mix of placeholder + hardcoded
		splitNeeded = true
	} else if len(portBuckets) > 1 {

		// Case 2: multiple distinct hardcoded ports
		splitNeeded = true
	}

	// Nothing to do if no split required
	if !splitNeeded {
		return nil
	}

	// Get the directory where output files will be written
	dir := filepath.Dir(path)

	// Case A: keep original template with {{Port}} requests
	if len(defaultRequests) > 0 {

		// Write template clone
		defaultClone := deepcopy.Copy(tpl).(*nucleitemplates.Template)
		defaultClone.RequestsWithTCP = defaultRequests
		defaultClone.RequestsNetwork = nil
		defaultClone.ID = tpl.ID
		errWrite := writeTemplate(defaultClone, path)
		if errWrite != nil {
			return fmt.Errorf("could not write default network template: %w", errWrite)
		}
	} else if len(portBuckets) > 0 {

		// Case B: no {{Port}}, pick the first bucket as the default
		var firstPort string
		for p := range portBuckets {
			firstPort = p
			break
		}

		// Write template clone
		defaultClone := deepcopy.Copy(tpl).(*nucleitemplates.Template)
		defaultClone.RequestsWithTCP = portBuckets[firstPort]
		defaultClone.RequestsNetwork = nil
		defaultClone.ID = tpl.ID
		errWrite := writeTemplate(defaultClone, path)
		if errWrite != nil {
			return fmt.Errorf("could not write default network template: %w", errWrite)
		}

		// Remove the port used as default from the buckets
		delete(portBuckets, firstPort)
	}

	// Create one new file per remaining explicit port
	for port, reqs := range portBuckets {

		// Write template clone
		explicitClone := deepcopy.Copy(tpl).(*nucleitemplates.Template)
		explicitClone.RequestsWithTCP = reqs
		explicitClone.RequestsNetwork = nil
		explicitClone.ID = fmt.Sprintf("%s_%s", tpl.ID, port)
		outPath := filepath.Join(dir, fmt.Sprintf("%s.yaml", explicitClone.ID))
		errWrite := writeTemplate(explicitClone, outPath)
		if errWrite != nil {
			return fmt.Errorf("could not write explicit network template for port %s: %w", port, errWrite)
		}
		logger.Debugf("Split template %s into %s", tpl.ID, explicitClone.ID)
	}

	// Return nil as everything went fine
	return nil
}

// splitTemplateHttp splits HTTP requests into multiple templates if needed.
// A split is performed in the following cases:
//  1. There are multiple distinct hardcoded ports.
//  2. There is at least one hardcoded port and one placeholder entry ({{Port}}, {{BaseURL}}, {{RootURL}}, {{Hostname}}).
//
// The default template keeps only placeholder entries per block.
// Each distinct hardcoded port gets its own template, keeping only that port's entries per block.
// Request blocks that become empty after filtering are dropped from the respective template.
func splitTemplateHttp(logger utils.Logger, path string, tpl *nucleitemplates.Template) error {

	// Get the directory where output files will be written
	dir := filepath.Dir(path)

	// --- Pass 1: classify ALL entries across ALL request blocks ---
	//
	// For each request block we record:
	//   - which entries are placeholders ({{BaseURL}}, {{Port}}, etc.)
	//   - which entries are hardcoded, keyed by port
	//
	// We also collect the global set of distinct hardcoded ports and whether
	// any placeholder entry exists at all, so we can decide once whether a
	// split is needed.

	type classifiedBlock struct {
		req              *nucleihttp.Request
		placeholderPaths []string
		placeholderRaws  []string
		portPaths        map[string][]string // port → path entries
		portRaws         map[string][]string // port → raw entries
	}

	var blocks []classifiedBlock
	globalPlaceholderCount := 0
	globalPortSet := make(map[string]struct{})

	for _, req := range tpl.RequestsHTTP {
		cb := classifiedBlock{
			req:       req,
			portPaths: make(map[string][]string),
			portRaws:  make(map[string][]string),
		}

		classifyEntry := func(entry string, isPath bool) {
			// Check for hardcoded port attached to a host placeholder
			if (strings.Contains(entry, "{{Host}}:") ||
				strings.Contains(entry, "{{Hostname}}:") ||
				strings.Contains(entry, "{{BaseURL}}:")) &&
				portRegex.MatchString(entry) {

				m := portRegex.FindStringSubmatch(entry)
				if m != nil && m[1] != "" {
					port := m[1]
					globalPortSet[port] = struct{}{}
					if isPath {
						cb.portPaths[port] = append(cb.portPaths[port], entry)
					} else {
						cb.portRaws[port] = append(cb.portRaws[port], entry)
					}
					return // classified as hardcoded → skip placeholder check
				}
			}

			// Check for placeholder entries
			if strings.Contains(entry, "{{Port}}") ||
				strings.Contains(entry, "{{BaseURL}}") ||
				strings.Contains(entry, "{{RootURL}}") ||
				strings.Contains(entry, "{{Hostname}}") {
				globalPlaceholderCount++
				if isPath {
					cb.placeholderPaths = append(cb.placeholderPaths, entry)
				} else {
					cb.placeholderRaws = append(cb.placeholderRaws, entry)
				}
			}
		}

		for _, p := range req.Path {
			classifyEntry(p, true)
		}
		for _, r := range req.Raw {
			classifyEntry(r, false)
		}

		blocks = append(blocks, cb)
	}

	// --- Decide whether a split is needed ---
	splitNeeded := false
	if globalPlaceholderCount > 0 && len(globalPortSet) > 0 {
		// Mix of placeholder + hardcoded ports
		splitNeeded = true
	} else if len(globalPortSet) > 1 {
		// Multiple distinct hardcoded ports
		splitNeeded = true
	}

	if !splitNeeded {
		return nil
	}

	// --- Pass 2: write one file per output variant ---
	//
	// Variant "default": keep placeholder entries in each block (if any).
	// Variant per port:  keep only that port's entries in each block (if any).
	// Blocks that end up with no entries at all are omitted from that variant.

	// buildRequests assembles the []*nucleihttp.Request slice for a given variant.
	// pickEntries selects the right path/raw slices from a classified block.
	buildRequests := func(pickEntries func(cb classifiedBlock) (paths, raws []string)) []*nucleihttp.Request {
		var result []*nucleihttp.Request
		for _, cb := range blocks {
			paths, raws := pickEntries(cb)
			if len(paths) == 0 && len(raws) == 0 {
				// This block contributes nothing to this variant → skip it
				continue
			}
			rClone := deepcopy.Copy(cb.req).(*nucleihttp.Request)
			rClone.Path = paths
			rClone.Raw = raws
			result = append(result, rClone)
		}
		return result
	}

	// Write default template (placeholder entries)
	if globalPlaceholderCount > 0 {
		defaultReqs := buildRequests(func(cb classifiedBlock) ([]string, []string) {
			return cb.placeholderPaths, cb.placeholderRaws
		})
		if len(defaultReqs) > 0 {
			defaultClone := deepcopy.Copy(tpl).(*nucleitemplates.Template)
			defaultClone.RequestsWithHTTP = defaultReqs
			defaultClone.RequestsHTTP = nil
			defaultClone.ID = tpl.ID
			defaultClone.Flow = "" // Drop the flow as we just split the requests and it no longer makes sense
			if errWrite := writeTemplate(defaultClone, path); errWrite != nil {
				return fmt.Errorf("could not write default HTTP template: %w", errWrite)
			}
		}
	}

	// Write one template per distinct hardcoded port
	for port := range globalPortSet {
		portReqs := buildRequests(func(cb classifiedBlock) ([]string, []string) {
			return cb.portPaths[port], cb.portRaws[port]
		})
		if len(portReqs) == 0 {
			// No block has an entry for this port → nothing to write
			continue
		}

		clone := deepcopy.Copy(tpl).(*nucleitemplates.Template)
		clone.RequestsWithHTTP = portReqs
		clone.RequestsHTTP = nil
		clone.ID = fmt.Sprintf("%s_%s", tpl.ID, port)
		clone.Flow = "" // Drop the flow as we just split the requests and it no longer makes sense
		outPath := filepath.Join(dir, fmt.Sprintf("%s.yaml", clone.ID))
		if errWrite := writeTemplate(clone, outPath); errWrite != nil {
			return fmt.Errorf("could not write HTTP template for port %s: %w", port, errWrite)
		}
		logger.Debugf("Split template %s into %s", tpl.ID, clone.ID)
	}

	// Return nil as everything went fine
	return nil
}

// writeTemplate writes a template to disk using its MarshalYAML representation.
func writeTemplate(tpl *nucleitemplates.Template, outPath string) error {
	data, errData := tpl.MarshalYAML()
	if errData != nil {
		return fmt.Errorf("could not marshal template %s: %w", tpl.ID, errData)
	}
	return os.WriteFile(outPath, data, 0o644)
}

// noopWriter satisfies output.Writer with no side effects. It is used only during template parsing.
type noopWriter struct{}

func (*noopWriter) Close() {}
func (*noopWriter) Colorizer() *aurora.Aurora {
	return aurora.New(aurora.WithColors(false), aurora.WithHyperlinks(false))
}
func (*noopWriter) Write(*nulcleioutput.ResultEvent) error                 { return nil }
func (*noopWriter) WriteFailure(*nulcleioutput.InternalWrappedEvent) error { return nil }
func (*noopWriter) Request(string, string, string, error)                  {}
func (*noopWriter) RequestStatsLog(string, string)                         {}
func (*noopWriter) WriteStoreDebugData(string, string, string, string)     {}
func (*noopWriter) ResultCount() int                                       { return 0 }
