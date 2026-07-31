/*
* GoScans, a collection of network scan modules for infrastructure discovery and information gathering.
*
* Copyright (c) Siemens AG, 2016-2026.
*
* This work is licensed under the terms of the MIT license. For a copy, see the LICENSE file in the top-level
* directory or visit <https://opensource.org/licenses/MIT>.
*
 */

// Package nuclei implements a scan module for running Nuclei vulnerability templates.
package nuclei

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	nucleigoflags "github.com/projectdiscovery/goflags"
	nucleilib "github.com/projectdiscovery/nuclei/v3/lib"
	nucleicatalog "github.com/projectdiscovery/nuclei/v3/pkg/catalog"
	nucleiconfig "github.com/projectdiscovery/nuclei/v3/pkg/catalog/config"
	nucleiseverity "github.com/projectdiscovery/nuclei/v3/pkg/model/types/severity"
	nulcleioutput "github.com/projectdiscovery/nuclei/v3/pkg/output"
	nucleitemplatetypes "github.com/projectdiscovery/nuclei/v3/pkg/templates/types"
	nucleitypes "github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/rs/xid"
	"github.com/siemens/GoScans/utils"
)

// Label identifies the scan module in logs and results
const Label = "Nuclei"

// Setup configures the environment accordingly, if the scan module has some special requirements.
// A successful setup is required before a scan can be started.
// It resolves the latest nuclei-templates release tag from the GitHub API at runtime, wipes any
// existing templates directory, and downloads a fresh copy into the given templatesDir before
// applying preprocessing rules (admin-on-demand, always-current model).
func Setup(logger utils.Logger, pathTemplates string) error {

	// Prepare HTTP client shared between the release-tag lookup and the template download
	client := &http.Client{Timeout: 120 * time.Second}

	// Resolve the latest release tag from the GitHub releases API
	releaseTag, errReleaseTag := fetchLatestReleaseTag(client, "https://api.github.com/repos/projectdiscovery/nuclei-templates/releases/latest")
	if errReleaseTag != nil {
		return fmt.Errorf("could not resolve latest Nuclei templates release: %w", errReleaseTag)
	}

	// Wipe the existing templates directory to guarantee a clean re-download
	info, errInfo := os.Stat(pathTemplates)
	if errInfo == nil && info.IsDir() {
		if errRemove := os.RemoveAll(pathTemplates); errRemove != nil {
			return fmt.Errorf("could not remove existing Nuclei templates directory: %w", errRemove)
		}
	} else if errInfo != nil && !os.IsNotExist(errInfo) {
		return fmt.Errorf("could not stat Nuclei templates directory: %w", errInfo)
	}

	// Log action
	logger.Infof("Installing Nuclei templates into '%s'.", pathTemplates)

	// Create the folder if it does not exist
	errMkdir := os.MkdirAll(pathTemplates, 0700)
	if errMkdir != nil {
		return fmt.Errorf("could not create Nuclei templates directory: %w", errMkdir)
	} else {

		// Get first folder of path
		path := filepath.Clean(pathTemplates)
		pathParts := strings.Split(path, string(os.PathSeparator))
		if len(pathParts) > 0 {
			path = pathParts[0]
		}

		// Set correct ownership
		errChown := chownDirTree(logger, path)
		if errChown != nil {
			return fmt.Errorf("could not chown Nuclei template path: %w", errChown)
		}
	}

	// Download Nuclei templates ZIP directly into templates directory
	logger.Debugf("Downloading Nuclei templates '%s'.", releaseTag)
	downloadUrl := fmt.Sprintf("https://github.com/projectdiscovery/nuclei-templates/archive/refs/tags/%s.zip", releaseTag)
	downloadPath := filepath.Join(pathTemplates, fmt.Sprintf("nuclei-templates-%s.zip", releaseTag))

	// Fetch the archive from GitHub
	resp, errResp := client.Get(downloadUrl)
	if errResp != nil {
		return fmt.Errorf("could not download Nuclei templates: %w", errResp)
	}

	// Make sure client gets closed again
	defer func() { _ = resp.Body.Close() }()

	// Create the zip file directly
	outFile, errOutFile := os.Create(downloadPath)
	if errOutFile != nil {
		return fmt.Errorf("could not create Nuclei zip file: %w", errOutFile)
	}

	// Stream HTTP response into the file
	_, errCopy := io.Copy(outFile, resp.Body)
	if errCopy != nil {
		_ = outFile.Close()
		return fmt.Errorf("could not save Nuclei zip: %w", errCopy)
	}

	// Close the zip file before extracting
	_ = outFile.Close()

	// Extract the downloaded archive into the templates' directory
	logger.Debugf("Extracting Nuclei templates.")
	errUnzip := utils.Unzip(downloadPath, pathTemplates)
	if errUnzip != nil {
		return fmt.Errorf("could not unzip Nuclei templates: %w", errUnzip)
	}

	// Remove the downloaded zip file
	errRemove := os.Remove(downloadPath)
	if errRemove != nil {
		logger.Debugf("Could not remove Nuclei zip file '%s': %v", downloadPath, errRemove)
	}

	// GitHub zips always unpack into a subfolder like "nuclei-templates-version"
	baseDir := filepath.Join(pathTemplates, fmt.Sprintf("nuclei-templates-%s", strings.TrimPrefix(releaseTag, "v")))

	// Move contents safely (cross-platform)
	entries, errEntries := os.ReadDir(baseDir)
	if errEntries != nil {
		return fmt.Errorf("could not read unzipped Nuclei folder: %w", errEntries)
	}

	// Iterate entries
	logger.Debugf("Moving Nuclei templates into position.")
	for _, e := range entries {

		// Prepare source and destination paths
		src := filepath.Join(baseDir, e.Name())
		dst := filepath.Join(pathTemplates, e.Name())

		// Move directory or file safely
		errMove := utils.MoveDirSafe(src, dst)
		if errMove != nil {

			// Continue to the next entry
			logger.Debugf("could not move Nuclei template '%s': %s", e.Name(), errMove)
			continue
		}
	}

	// Remove the now-empty subfolder
	errRemoveAll := os.RemoveAll(baseDir)
	if errRemoveAll != nil {
		return fmt.Errorf("could not remove Nuclei temp folder: %w", errRemoveAll)
	}

	// Run preprocessing on the templates directory
	logger.Debugf("Processing Nuclei templates.")
	errProcess := splitTemplates(logger, pathTemplates)
	if errProcess != nil {
		return fmt.Errorf("could not preprocess Nuclei templates: %w", errProcess)
	}

	// Fix folder ownership to parent folder's owner, if setup is run as root on Linux
	errChown := chownDirTree(logger, pathTemplates)
	if errChown != nil {
		return fmt.Errorf("could not chown Nuclei templates: %w", errChown)
	}

	// Invalidate cached metadata after successfully replacing the installed templates
	errInvalidate := invalidateTemplateCatalog(pathTemplates)
	if errInvalidate != nil {
		return fmt.Errorf("could not invalidate Nuclei template catalog: %w", errInvalidate)
	}

	// Return nil as everything went fine
	return nil
}

// CheckSetup checks whether Setup() executed accordingly. Scan arguments should be checked by the scanner.
func CheckSetup(logger utils.Logger, pathTemplates string) error {

	// Check if the folder exists
	info, errInfo := os.Stat(pathTemplates)
	if errInfo != nil {
		return fmt.Errorf("invalid template path '%s'", pathTemplates)
	}

	// Check if directory contains files
	if info.IsDir() {

		// Check if folder contains expected ignore file
		errTemplates := utils.IsValidFile(filepath.Join(pathTemplates, ".nuclei-ignore"))
		if errTemplates != nil {
			return fmt.Errorf("could not find '.nuclei-ignore' in template path '%s'", pathTemplates)
		}

		// Folder exists, check if it's empty
		entries, errEntries := os.ReadDir(pathTemplates)
		if errEntries != nil {
			return fmt.Errorf("invalid template path '%s': %w", pathTemplates, errEntries)
		}

		// Check if folder is not empty
		if len(entries) > 0 {

			// Run preprocessing on the templates directory
			logger.Debugf("Processing Nuclei templates.")
			errProcess := splitTemplates(logger, pathTemplates)
			if errProcess != nil {
				return fmt.Errorf("could not preprocess Nuclei templates: %w", errProcess)
			}

			// Invalidate cached metadata after replacing the installed templates
			errInvalidate := invalidateTemplateCatalog(pathTemplates)
			if errInvalidate != nil {
				return fmt.Errorf("could not invalidate Nuclei template catalog: %w", errInvalidate)
			}

			// Return nil as everything went fine
			return nil
		}
	}

	// Return error as templates are now available
	return fmt.Errorf("invalid template path '%s'", pathTemplates)
}

// ResultData holds Nuclei result events produced during a scan.
type ResultData struct {
	Findings []*nulcleioutput.ResultEvent
}

// Result describes the final state of a single scan run.
type Result struct {
	Data      *ResultData
	Status    string // Final scan status (success or graceful error). Should be stored along with the scan results.
	Exception bool   // Indicates if something went wrong badly and results shall be discarded. This should never be
	// true, because all errors should be handled gracefully. Logging an error message should always precede setting
	// this flag! This flag may additionally come along with a message put into the status attribute.
}

// Scanner holds configuration and runtime state for a single Nuclei scan.
type Scanner struct {
	Label             string
	Started           time.Time
	Finished          time.Time
	logger            utils.Logger
	target            string           // Address to be scanned (might be IPv4, IPv6 or hostname)
	port              *int             // Pointer to differentiate between service- and host-based scans
	pathTemplates     string           // Path to the templates
	catalog           *templateCatalog // Shared catalog selection and parser cache for pathTemplates
	includeSeverities string           // Filter by including severities (CSV: info,low,medium,high,critical)
	excludeSeverities string           // Filter by excluding severities (CSV: info,low,medium,high,critical)
	includeTags       []string         // Filter by including tags present in template
	excludeTags       []string         // Filter by excluding tags present in template
	includeIds        []string         // Filter by template IDs
	excludeIds        []string         // Filter by excluding template IDs
	includeProtocols  string           // Filter by including protocol types
	excludeProtocols  string           // Filter by excluding protocol types (CSV: tcp,http,dns)
	username          string           // (Optional) will be included in templates requiring it as variable
	password          string           // (Optional) will be included in templates requiring it as variable
	proxy             *url.URL

	contextInner       context.Context    // Context for the scan, within which the scan should execute. Might optionally wrap an outer context. If outer context is cancelled, inner one should cancel too, but not the other way around.
	contextInnerCancel context.CancelFunc // Context cancel function of inner context, not impacting optional outer one.
}

// NewScanner constructs a Scanner instance
func NewScanner(
	logger utils.Logger, // Can be any logger implementing our minimalistic interface. Wrap your logger to satisfy the interface, if necessary (like utils.LoggerTest).
	target string,
	port *int,
	pathTemplates string,
	includeSeverities string,
	excludeSeverities string,
	includeTags []string,
	excludeTags []string,
	includeIds []string,
	excludeIds []string,
	includeProtocols string,
	excludeProtocols string,
	username string,
	password string,
	proxy string,
) (*Scanner, error) {

	// Sanitize target before validation so leading/trailing whitespace does not cause false rejects
	target = strings.TrimSpace(target)

	// Check if the folder exists
	_, errInfo := os.Stat(pathTemplates)
	if errInfo != nil {
		return nil, fmt.Errorf("invalid template path '%s'", pathTemplates)
	}

	// First, check if we have a custom templates directory
	errTemplates := utils.IsValidFile(filepath.Join(pathTemplates, ".nuclei-ignore"))
	if errTemplates != nil {
		return nil, fmt.Errorf("could not find '.nuclei-ignore' in template path '%s'", pathTemplates)
	}

	// Acquire the shared cache and expand split variants from its index
	catalog, errCatalog := acquireTemplateCatalog(pathTemplates)
	if errCatalog != nil {
		return nil, fmt.Errorf("could not acquire template catalog: %w", errCatalog)
	}
	includeIds, excludeIds = catalog.expandTemplateIds(includeIds, excludeIds)

	// Prepare proxy, *url.URL with appropriate scheme required
	proxyUrl, errProxyUrl := utils.ProxyStringToUrl(proxy) // Returns nil proxy on empty input
	if errProxyUrl != nil {
		return nil, errProxyUrl
	}

	// Initiate scanner with sanitized input values
	scan := Scanner{
		Label,
		time.Time{}, // zero time
		time.Time{}, // zero time
		logger,
		target, // Address to be scanned (might be IPv4, IPv6 or hostname)
		port,
		catalog.root,
		catalog,
		includeSeverities,
		excludeSeverities,
		includeTags,
		excludeTags,
		includeIds,
		excludeIds,
		includeProtocols,
		excludeProtocols,
		username,
		password,
		proxyUrl,
		nil,
		nil,
	}

	// Return scan struct
	return &scan, nil
}

// SetContext can be used to pass an existing context from outside.
// If timeout is supplied later when calling Run() the external context and the deadline context will be combined.
// Once set, the context cannot be changed anymore, because it might have been wrapped internally already.
func (s *Scanner) SetContext(ctx context.Context) {
	if s.contextInner == nil {
		s.contextInner = ctx
	}
}

// Run starts scan execution. This must either be executed as a goroutine, or another thread must be active listening
// on the scan's result channel, in order to avoid a deadlock situation.
func (s *Scanner) Run(timeout time.Duration) (res *Result) {

	// Recover potential panics to gracefully shut down scan
	defer func() {
		if r := recover(); r != nil {

			// Log exception with stacktrace
			s.logger.Errorf(fmt.Sprintf("Unexpected error: %s", r))

			// Build error status from error message and formatted stacktrace
			errMsg := fmt.Sprintf("%s%s", r, utils.StacktraceIndented("\t"))

			// Return result set indicating exception
			res = &Result{
				nil,
				errMsg,
				true,
			}
		}
	}()

	// Set scan started flag
	s.Started = time.Now()

	// Create initial context
	contextInner := context.Background()

	// Replace context with external one if set
	if s.contextInner != nil {
		contextInner = s.contextInner
	}

	// Add timeout to context if desired
	var contextInnerCancel context.CancelFunc
	if timeout > 0 {
		contextInner, contextInnerCancel = context.WithTimeout(contextInner, timeout)
	}

	// Set context for scan
	s.contextInner = contextInner
	s.contextInnerCancel = contextInnerCancel

	// Execute scan logic
	s.logger.Infof("Started  scan of %s.", s.targetAddr())
	res = s.execute()

	// Log scan completion message
	s.Finished = time.Now()
	duration := s.Finished.Sub(s.Started).Minutes()
	s.logger.Infof("Finished scan of %s in %fm.", s.targetAddr(), duration)

	// Return result set
	return res
}

// execute runs one isolated Nuclei engine and returns its local findings
func (s *Scanner) execute() *Result {

	// Cleanup inner context if set
	if s.contextInnerCancel != nil {
		defer s.contextInnerCancel()
	}

	// Declare result variable to be returned
	results := &ResultData{}

	// Protects findings slice from concurrent writes by the callback
	var findingsMutex sync.Mutex

	// Check whether scan timeout is reached
	if utils.ContextExpired(s.contextInner) {
		s.logger.Debugf("Scan ran into timeout.")
		return &Result{
			nil,
			utils.StatusDeadline,
			false,
		}
	}

	// Prepare execution inputs
	var target string
	var templatePaths []string

	// Check which type of scan to run
	if s.port != nil {

		// Service-based scan -------------------------------------------------

		// Define target. Currently, Nuclei has no support to limit scans to
		// specific ports. One can only out filter templates with unwanted ports.
		// See https://github.com/orgs/projectdiscovery/discussions/3712
		// see https://github.com/orgs/projectdiscovery/discussions/5159
		target = strings.Join([]string{s.target, ":", strconv.Itoa(*s.port)}, "")

		// Enforce exclusion of host-based protocols
		s.excludeProtocols = mergeCsv(s.excludeProtocols, "dns,whois")

		// Explicitly include only templates that have matching port or dynamic port
		s.logger.Debugf("Loading relevant templates.")
		_, portTemplatePaths, errPort := selectPortTemplates(
			s.logger,
			s.catalog,
			*s.port,
			s.includeIds,
			s.excludeIds,
		)
		if errPort != nil {
			s.logger.Debugf("Could not filter templates by port %d: %v", *s.port, errPort)
		}

		// Abort early if no template is relevant for this port
		if len(portTemplatePaths) == 0 {
			s.logger.Debugf("Could not find matching templates for port %d", *s.port)
			return &Result{
				nil,
				"No matching templates for scan",
				false,
			}
		}

		// Load exactly the templates selected for this port
		templatePaths = portTemplatePaths

	} else {

		// Host-based scan ----------------------------------------------------
		target = s.target

		// Enforce allow-list: dns,whois
		if s.includeProtocols == "" {
			// Case no user preference (default: all protocols allowed) → enforce dns,whois
			s.includeProtocols = "dns,whois"
		} else {
			// Case user set something → only keep dns,whois intersection
			s.includeProtocols = filterIntersection(s.includeProtocols, "dns,whois")

			// An empty intersection means no Host scan
			if s.includeProtocols == "" {
				s.logger.Debugf("Could not find matching templates")
				return &Result{
					nil,
					"No matching templates for scan",
					false,
				}
			}
		}

		hostSources, errHostSources := s.catalog.hostSources(s.logger)
		if errHostSources != nil {
			s.logger.Debugf("Could not select host templates: %v", errHostSources)
			return &Result{nil, fmt.Sprintf("Could not select host templates: %v", errHostSources), false}
		}
		_, templatePaths = filterTemplateSources(hostSources, s.includeIds, s.excludeIds)
		if len(templatePaths) == 0 {
			return &Result{nil, "No matching templates for scan", false}
		}
	}

	// Log information about templates to be loaded
	s.logger.Debugf("Selected %d include tags.", len(s.includeTags))
	s.logger.Debugf("Selected %d exclude tags.", len(s.excludeTags))
	s.logger.Debugf("Selected %d include IDs.", len(s.includeIds))
	s.logger.Debugf("Selected %d exclude IDs.", len(s.excludeIds))
	s.logger.Debugf("Selected include protocols: %s", s.includeProtocols)
	s.logger.Debugf("Selected exclude protocols: %s", s.excludeProtocols)
	s.logger.Debugf("Selected include severities: %s", s.includeSeverities)
	s.logger.Debugf("Selected exclude severities: %s", s.excludeSeverities)

	// Build a private engine while injecting only the shared parser cache
	options, errOptions := s.prepareNucleiOptions(templatePaths)
	if errOptions != nil {
		s.logger.Errorf("Could not prepare Nuclei options: %v", errOptions)
		return &Result{nil, fmt.Sprintf("Could not prepare options: %v", errOptions), false}
	}

	// Create the private engine for this Scanner
	engine, errEngine := nucleilib.NewNucleiEngineCtx(s.contextInner, options...)
	if errEngine != nil {
		s.logger.Errorf("Could not create Nuclei engine for %s: %s", s.target, errEngine)
		return &Result{nil, fmt.Sprintf("Could not create engine: %v", errEngine), true}
	}
	defer engine.Close()

	// Load only the paths selected for this scan
	errLoad := engine.LoadAllTemplates()
	if errLoad != nil {
		s.logger.Errorf("Could not load Nuclei templates: %s", errLoad)
		return &Result{nil, fmt.Sprintf("Could not load templates: %v", errLoad), true}
	}
	engine.LoadTargets([]string{target}, false)

	// Collect findings through this engine's local callback
	resultCallback := func(event *nulcleioutput.ResultEvent) {

		// Retain successful matcher events in this scan's result
		if event.MatcherStatus {
			findingsMutex.Lock()
			results.Findings = append(results.Findings, event)
			findingsMutex.Unlock()
		}
	}

	// Execute the selected templates on this scan's private engine
	s.logger.Debugf("Executing Nuclei scan of '%s'", target)
	errExec := engine.ExecuteCallbackWithCtx(s.contextInner, resultCallback)
	if errExec != nil {
		if errors.Is(errExec, context.DeadlineExceeded) {
			s.logger.Debugf("Stopped scan of '%s' due to timeout", target)
		} else if errors.Is(errExec, nucleilib.ErrNoTemplatesAvailable) {
			s.logger.Debugf("Could not execute Nuclei: %s", errExec)
			return &Result{nil, "No matching templates for scan", false}
		} else {
			s.logger.Errorf("Could not execute Nuclei: %s", errExec)
			return &Result{nil, errExec.Error(), true}
		}
	}

	// Return pointer to result struct
	s.logger.Debugf("Returning scan result.")
	return &Result{
		results,
		utils.StatusCompleted,
		false,
	}
}

// prepareNucleiOptions builds the complete options for one private engine
//
// Nuclei SDK helpers mutate one options instance while WithOptions replaces that instance completely
// Building one base value keeps runtime limits, filters, selected paths, credentials and parser configuration together
// The parsed cache is shared because Nuclei provides it for reuse across engines
// Compiled executors remain private because Nuclei rebinds their request options to the active engine
func (s *Scanner) prepareNucleiOptions(templatePaths []string) ([]nucleilib.NucleiSDKOptions, error) {

	// Prepare options variable
	var opts = []nucleilib.NucleiSDKOptions{
		nucleilib.DisableUpdateCheck(),
	}

	// Create and merge base options
	base := nucleitypes.DefaultOptions()

	// Apply proxy policy
	if s.proxy == nil {
		base.Proxy = nil
		base.ProxyInternal = false
	} else {
		base.Proxy = []string{s.proxy.String()}
		base.ProxyInternal = true
	}

	// Apply the customizations to avoid overwhelming targets and misinterpreting them as unresponsive
	base.ExecutionId = xid.New().String()
	base.RateLimit = 30
	base.TemplateThreads = 10
	base.BulkSize = 10
	base.Timeout = 15
	base.MaxHostError = 30

	// Restrict helper-file loading to the dynamically discovered allowlist
	base.AllowLocalFileAccess = false
	base.LoadHelperFileFunction = makeHelperFileLoader(s.pathTemplates, s.catalog.helperAllowlist)

	// Disable Template Updates
	base.PublicTemplateDisableDownload = true
	base.UpdateTemplates = false

	// Template source
	base.Templates = templatePaths

	// Share parsed metadata while retaining private compiled executors for each engine
	base.Parser = s.catalog.newExecutionParser()

	// Repoint config dir to custom templates location
	cfg := nucleiconfig.DefaultConfig
	cfg.SetConfigDir(s.pathTemplates)

	// Template filters
	// Perform necessary transformations
	sev := nucleiseverity.Severities{}
	if errSet := sev.Set(s.includeSeverities); errSet != nil {
		return opts, errSet
	}
	es := nucleiseverity.Severities{}
	if errSet := es.Set(s.excludeSeverities); errSet != nil {
		return opts, errSet
	}
	pt := nucleitemplatetypes.ProtocolTypes{}
	if errSet := pt.Set(s.includeProtocols); errSet != nil {
		return opts, errSet
	}
	ept := nucleitemplatetypes.ProtocolTypes{}
	if errSet := ept.Set(s.excludeProtocols); errSet != nil {
		return opts, errSet
	}

	// Apply custom template filters
	base.Severities = sev
	base.ExcludeSeverities = es
	base.Tags = s.includeTags
	base.ExcludeTags = s.excludeTags
	base.IncludeIds = s.includeIds
	base.ExcludeIds = s.excludeIds
	base.Protocols = pt
	base.ExcludeProtocols = ept

	// Prepare Custom variables
	runtimeVars := nucleigoflags.RuntimeMap{}
	if errSet := runtimeVars.Set(fmt.Sprintf("username=%s", s.username)); errSet != nil {
		return nil, fmt.Errorf("could not set username var: %w", errSet)
	}
	if errSet := runtimeVars.Set(fmt.Sprintf("password=%s", s.password)); errSet != nil {
		return nil, fmt.Errorf("could not set password var: %w", errSet)
	}

	// Set Custom variables
	base.Vars = runtimeVars

	// Override options with the customizations
	opts = append(opts, nucleilib.WithOptions(base))

	// Return options
	return opts, nil
}

// filterIntersection returns the intersection of two CSV lists (deduplicated).
// If `existing` is empty the enforced list is returned unchanged.
// Example: filterIntersection("dns,http,tcp", "dns,whois") -> "dns"
func filterIntersection(existing, enforced string) string {

	// If no existing filter, return the enforced list directly
	if existing == "" {
		return enforced
	}

	// Build a set of entries from the existing CSV (trim spaces, skip empty)
	existingSet := make(map[string]struct{})
	for _, v := range strings.Split(existing, ",") {

		// Trim whitespace around the item
		item := strings.TrimSpace(v)

		// Skip empty items resulting from malformed CSV (e.g., ",,")
		if item == "" {
			continue
		}

		// Add to the set to deduplicate
		existingSet[item] = struct{}{}
	}

	// Build a set of entries from the enforced CSV (trim spaces, skip empty)
	enforcedSet := make(map[string]struct{})
	for _, v := range strings.Split(enforced, ",") {

		// Trim whitespace around the item
		item := strings.TrimSpace(v)

		// Skip empty items
		if item == "" {
			continue
		}

		// Add to the set to deduplicate
		enforcedSet[item] = struct{}{}
	}

	// Compute the intersection between the two sets
	intersection := make([]string, 0)
	for v := range existingSet {

		// Check presence in the enforced set and append if present
		if _, ok := enforcedSet[v]; ok {
			intersection = append(intersection, v)
		}
	}

	// Join the resulting items into a CSV and return
	return strings.Join(intersection, ",")
}

// mergeCsv merges two comma-separated string lists into a deduplicated CSV.
// If `existing` is empty the enforced list is returned unchanged.
func mergeCsv(existing, enforced string) string {

	// If no existing CSV simply return enforced
	if existing == "" {
		return enforced
	}

	// Use a map as a set to collect unique items from both CSV inputs
	set := make(map[string]struct{})

	// Add items from the existing CSV (trim spaces, skip empty)
	for _, v := range strings.Split(existing, ",") {

		// Trim whitespace around the item
		item := strings.TrimSpace(v)

		// Skip empty items
		if item == "" {
			continue
		}

		// Insert into the set
		set[item] = struct{}{}
	}

	// Add items from the enforced CSV (trim spaces, skip empty)
	for _, v := range strings.Split(enforced, ",") {

		// Trim whitespace around the item
		item := strings.TrimSpace(v)

		// Skip empty items.
		if item == "" {
			continue
		}

		// Add to the set to deduplicate
		set[item] = struct{}{}
	}

	// Build a slice from the set to return as CSV
	merged := make([]string, 0, len(set))
	for k := range set {
		merged = append(merged, k)
	}

	// Join and return the CSV string
	return strings.Join(merged, ",")
}

// fetchLatestReleaseTag queries the GitHub releases API at apiURL and returns the latest tag name.
// A non-200 status, malformed JSON, or empty tag_name all result in an error.
func fetchLatestReleaseTag(client *http.Client, apiUrl string) (string, error) {

	// Fetch the latest release metadata from the GitHub API
	resp, errResp := client.Get(apiUrl)
	if errResp != nil {
		return "", fmt.Errorf("could not fetch latest Nuclei templates release: %w", errResp)
	}
	defer func() { _ = resp.Body.Close() }()

	// Reject non-200 responses before attempting to decode
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("could not fetch latest Nuclei templates release, invalid status code: %s", http.StatusText(resp.StatusCode))
	}

	// Decode the JSON payload and extract the tag name
	var payload struct {
		TagName string `json:"tag_name"`
	}
	if errDecode := json.NewDecoder(resp.Body).Decode(&payload); errDecode != nil {
		return "", fmt.Errorf("could not parse latest Nuclei templates release response: %w", errDecode)
	}

	// Reject an empty tag name which would produce an unusable download URL
	if payload.TagName == "" {
		return "", fmt.Errorf("could not parse latest Nuclei templates release response, empty tag name")
	}

	// Return nil as everything went fine
	return payload.TagName, nil
}

// makeHelperFileLoader returns a LoadHelperFileFunction that serves helper-file requests only for
// paths present in allowlist and contained within root. Absolute paths, directory-traversal sequences,
// and symlinks that escape root are all rejected.
func makeHelperFileLoader(root string, allowlist map[string]struct{}) nucleitypes.LoadHelperFileFunction {

	// Pre-compute the prefix that every allowed resolved path must carry
	rootPrefix := root + string(filepath.Separator)

	return func(helperFile, _ string, _ nucleicatalog.Catalog) (io.ReadCloser, error) {

		// (b) Reject absolute paths before joining to prevent platform-specific edge cases
		if filepath.IsAbs(helperFile) {
			return nil, fmt.Errorf("helper file %q must be a relative path", helperFile)
		}

		// Resolve and clean the path relative to the templates root
		resolved := filepath.Clean(filepath.Join(root, helperFile))

		// (b) Reject any path that escapes the templates directory after cleaning
		if !strings.HasPrefix(resolved, rootPrefix) {
			return nil, fmt.Errorf("helper file %q escapes templates directory", helperFile)
		}

		// Compute the normalized relative path for allowlist lookup
		rel := filepath.ToSlash(resolved[len(rootPrefix):])

		// (a) Reject paths not present in the allowlist
		if _, ok := allowlist[rel]; !ok {
			return nil, fmt.Errorf("helper file %q is not in the allowlist", rel)
		}

		// (c) Evaluate symlinks and re-check containment
		realPath, errRealPath := filepath.EvalSymlinks(resolved)
		if errRealPath != nil {
			return nil, fmt.Errorf("could not resolve helper file path: %w", errRealPath)
		}
		if !strings.HasPrefix(filepath.Clean(realPath), rootPrefix) {
			return nil, fmt.Errorf("helper file %q symlink resolves outside templates directory", helperFile)
		}

		// Open and return the file
		f, errF := os.Open(resolved)
		if errF != nil {
			return nil, fmt.Errorf("could not open helper file: %w", errF)
		}

		// Return nil as everything went fine
		return f, nil
	}
}

// targetAddr returns "host:port" if a port is set, otherwise just "host".
func (s *Scanner) targetAddr() string {

	// Check if port is provided
	if s.port != nil {
		return fmt.Sprintf("%s:%d", s.target, *s.port)
	}

	// Return target
	return s.target
}
