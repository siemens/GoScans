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
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/siemens/GoScans/utils"
)

// TestTemplateCatalogConcurrentAcquireAndInvalidation verifies cache sharing and replacement
func TestTemplateCatalogConcurrentAcquireAndInvalidation(t *testing.T) {

	// Create an isolated template root and remove all shared state afterward
	root := createCatalogFixture(t)
	prepareTemplateCatalogTest(t, root)

	// Acquire the same catalog concurrently to exercise initial construction
	const workers = 20
	catalogs := make([]*templateCatalog, workers)
	errors := make([]error, workers)
	wg := sync.WaitGroup{}
	for i := range catalogs {
		wg.Add(1)
		go func(index int) {

			// Signal completion after storing this worker's result
			defer wg.Done()
			catalogs[index], errors[index] = acquireTemplateCatalog(root)
		}(i)
	}
	wg.Wait()

	// Verify every worker received the same catalog and parser
	for i, errCatalog := range errors {
		if errCatalog != nil {
			t.Fatalf("acquireTemplateCatalog[%d]() error = %v", i, errCatalog)
		}
		if catalogs[i] != catalogs[0] || catalogs[i].parser != catalogs[0].parser {
			t.Fatalf("worker %d received a different catalog or parser", i)
		}
	}

	// Verify execution parsers share only the parsed template cache
	executionParserA := catalogs[0].newExecutionParser()
	executionParserB := catalogs[0].newExecutionParser()
	if executionParserA == executionParserB {
		t.Fatal("execution parsers must be private per Scanner")
	}
	if executionParserA.Cache() != executionParserB.Cache() {
		t.Fatal("execution parsers do not share the parsed template cache")
	}
	if executionParserA.CompiledCache() == executionParserB.CompiledCache() {
		t.Fatal("execution parsers unexpectedly share engine-bound compiled executors")
	}

	// Invalidate the catalog and verify future callers receive a replacement
	invalidateTemplateCatalogForTest(t, root)
	replacement, errReplacement := acquireTemplateCatalog(root)
	if errReplacement != nil {
		t.Fatalf("acquireTemplateCatalog() after invalidation error = %v", errReplacement)
	}
	if replacement == catalogs[0] || replacement.parser == catalogs[0].parser {
		t.Fatal("invalidation did not replace the catalog and parser")
	}
}

// TestTemplateCatalogSelectsWithoutCompilingWholeCatalog verifies lightweight template selection
func TestTemplateCatalogSelectsWithoutCompilingWholeCatalog(t *testing.T) {

	// Create an isolated catalog fixture and remove its shared state afterward
	root := createCatalogFixture(t)
	prepareTemplateCatalogTest(t, root)

	// Acquire the catalog used by all selection checks
	catalog, errCatalog := acquireTemplateCatalog(root)
	if errCatalog != nil {
		t.Fatalf("acquireTemplateCatalog() error = %v", errCatalog)
	}
	logger := utils.NewTestLogger()

	// Verify dynamic and fixed templates are selected for their matching port
	port8080, errPort8080 := catalog.portSources(logger, 8080)
	if errPort8080 != nil {
		t.Fatalf("portSources(8080) error = %v", errPort8080)
	}
	assertSourceIds(t, port8080, "dynamic-http", "fixed-http")

	// Verify a fixed port template is excluded for a different port
	port80, errPort80 := catalog.portSources(logger, 80)
	if errPort80 != nil {
		t.Fatalf("portSources(80) error = %v", errPort80)
	}
	assertSourceIds(t, port80, "dynamic-http")

	// Verify host selection is limited to supported host protocols
	hosts, errHosts := catalog.hostSources(logger)
	if errHosts != nil {
		t.Fatalf("hostSources() error = %v", errHosts)
	}
	assertSourceIds(t, hosts, "host-dns")

	// Verify host paths are restricted by the same identifier filters as service paths
	hostIds, hostPaths := filterTemplateSources(hosts, []string{"host-dns"}, nil)
	assertTemplateIds(t, hostIds, []string{"host-dns"})
	if len(hostPaths) != 1 {
		t.Errorf("filtered host paths = %d, want 1", len(hostPaths))
	}

	// Verify selection did not populate either Nuclei parser cache
	if parsed := catalog.parser.ParsedCount(); parsed != 0 {
		t.Errorf("lightweight selection populated parser parsed cache: got %d, want 0", parsed)
	}
	if compiled := catalog.parser.CompiledCount(); compiled != 0 {
		t.Errorf("lightweight selection populated parser compiled cache: got %d, want 0", compiled)
	}
}

// TestGetPortTemplatesAppliesIdentifierFilters verifies the public service selection contract
func TestGetPortTemplatesAppliesIdentifierFilters(t *testing.T) {

	// Create an isolated catalog containing dynamic and fixed port templates
	root := createCatalogFixture(t)
	prepareTemplateCatalogTest(t, root)
	logger := utils.NewTestLogger()

	// Define the include and exclude combinations used by LSD scan settings
	tests := []struct {
		name       string
		includeIds []string
		excludeIds []string
		wantIds    []string
	}{
		{
			name:    "no-identifier-filters",
			wantIds: []string{"dynamic-http", "fixed-http"},
		},
		{
			name:       "limited-include-list",
			includeIds: []string{"fixed-http"},
			wantIds:    []string{"fixed-http"},
		},
		{
			name:       "exclude-list",
			excludeIds: []string{"fixed-http"},
			wantIds:    []string{"dynamic-http"},
		},
		{
			name:       "exclude-wins-over-include",
			includeIds: []string{"dynamic-http", "fixed-http"},
			excludeIds: []string{"fixed-http"},
			wantIds:    []string{"dynamic-http"},
		},
		{
			name:       "unknown-include-identifier",
			includeIds: []string{"missing-template"},
			wantIds:    []string{},
		},
	}

	// Execute every filter combination against the same cached port selection
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {

			// Select identifiers through the public compatibility function
			gotIds, errGotIds := GetPortTemplates(logger, root, 8080, test.includeIds, test.excludeIds)
			if errGotIds != nil {
				t.Fatalf("GetPortTemplates() error = %v", errGotIds)
			}

			// Verify the exact unordered identifier set
			assertTemplateIds(t, gotIds, test.wantIds)
		})
	}
}

// TestPrivateEnginesShareParsedCatalogAndIsolateResults verifies parallel engine isolation
func TestPrivateEnginesShareParsedCatalogAndIsolateResults(t *testing.T) {

	// Run the actual engine test in a child process when requested
	const helperEnv = "GOSCANS_NUCLEI_PARALLEL_HELPER"
	const rootEnv = "GOSCANS_NUCLEI_PARALLEL_ROOT"
	if os.Getenv(helperEnv) == "1" {
		runParallelEngineIsolationTest(t, os.Getenv(rootEnv))
		return
	}

	// Create the fixture in the parent because Nuclei keeps template file handles open on Windows
	root, errRoot := os.MkdirTemp("", "nuclei-parallel-*")
	if errRoot != nil {
		t.Fatalf("os.MkdirTemp() error = %v", errRoot)
	}
	defer func() { _ = os.RemoveAll(root) }()

	// Write the minimal catalog used by all parallel scanners
	writeFixtureFile(t, root, ".nuclei-ignore", "tags: []\nfiles: []\n")
	writeFixtureFile(t, root, "isolation.yaml", `id: cache-isolation
info:
  name: Cache isolation
  author: example-org
  severity: info
http:
  - method: GET
    path:
      - "{{BaseURL}}/match"
    matchers:
      - type: word
        words:
          - "cache-isolation-ok"
`)
	writeFixtureFile(t, root, "unselected.yaml", `id: cache-unselected
info:
  name: Unselected cache template
  author: example-org
  severity: high
http:
  - method: GET
    path:
      - "{{BaseURL}}/match"
    matchers:
      - type: word
        words:
          - "cache-isolation-ok"
`)

	// Execute the parallel engine test in an isolated child process
	command := exec.Command(os.Args[0], "-test.run=^TestPrivateEnginesShareParsedCatalogAndIsolateResults$")
	command.Env = append(os.Environ(), helperEnv+"=1", rootEnv+"="+root)
	output, errOutput := command.CombinedOutput()
	if errOutput != nil {
		t.Fatalf("parallel engine helper failed: %v\n%s", errOutput, output)
	}
}

// runParallelEngineIsolationTest runs concurrent scans against distinct local targets
func runParallelEngineIsolationTest(t *testing.T, root string) {

	// Validate the fixture path supplied by the parent test process
	t.Helper()
	if root == "" {
		t.Fatal("parallel engine helper root is empty")
	}
	prepareTemplateCatalogTest(t, root)

	// Create one distinct HTTP target and Scanner per concurrent scan
	const scans = 20
	servers := make([]*httptest.Server, 0, scans)
	scanners := make([]*Scanner, 0, scans)
	wantPorts := make([]string, 0, scans)
	for i := 0; i < scans; i++ {
		server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {

			// Return the marker expected by the shared test template
			_, _ = writer.Write([]byte("cache-isolation-ok"))
		}))
		servers = append(servers, server)

		// Derive the target and port assigned to this local server
		parsedUrl, errParsedUrl := url.Parse(server.URL)
		if errParsedUrl != nil {
			t.Fatalf("url.Parse() error = %v", errParsedUrl)
		}
		port, errPort := strconv.Atoi(parsedUrl.Port())
		if errPort != nil {
			t.Fatalf("strconv.Atoi() error = %v", errPort)
		}

		// Create a scanner restricted to the HTTP fixture template
		target := fmt.Sprintf("%s://%s", parsedUrl.Scheme, parsedUrl.Hostname())
		scanner, errScanner := NewScanner(
			utils.NewTestLogger(), target, &port, root,
			"", "", nil, nil,
			[]string{"cache-isolation"}, nil,
			"http", "", "", "", "",
		)
		if errScanner != nil {
			t.Fatalf("NewScanner() error = %v", errScanner)
		}
		scanners = append(scanners, scanner)
		wantPorts = append(wantPorts, parsedUrl.Port())
	}

	// Close all test servers after every scan has completed
	defer func() {

		// Close each server owned by this test process
		for _, server := range servers {
			server.Close()
		}
	}()

	// Run every Scanner concurrently and retain results by input position
	results := make([]*Result, scans)
	wg := sync.WaitGroup{}
	for i, scanner := range scanners {
		wg.Add(1)
		go func(index int, scan *Scanner) {

			// Signal completion after storing this scan's isolated result
			defer wg.Done()
			results[index] = scan.Run(30 * time.Second)
		}(i, scanner)
	}
	wg.Wait()

	// Verify each callback received only the finding for its own target
	for i, result := range results {
		if result == nil || result.Exception || result.Data == nil {
			t.Fatalf("scan %d result = %#v", i, result)
		}
		if len(result.Data.Findings) != 1 {
			t.Fatalf("scan %d findings = %d, want 1", i, len(result.Data.Findings))
		}
		finding := result.Data.Findings[0]
		if !strings.Contains(finding.Host, wantPorts[i]) && finding.Port != wantPorts[i] {
			t.Errorf("scan %d finding belongs to host %q port %q, want port %q", i, finding.Host, finding.Port, wantPorts[i])
		}
	}

	// Verify all engines shared only the included template without sharing compiled executors
	catalog := scanners[0].catalog
	if parsed := catalog.parser.ParsedCount(); parsed != 1 {
		t.Errorf("shared parsed template count = %d, want 1", parsed)
	}
	if compiled := catalog.parser.CompiledCount(); compiled != 0 {
		t.Errorf("catalog compiled template count = %d, want 0 private executors", compiled)
	}
}

// createCatalogFixture creates templates covering dynamic ports, fixed ports and host protocols
func createCatalogFixture(t *testing.T) string {

	// Create the root and required Nuclei installation marker
	t.Helper()
	root := t.TempDir()
	writeFixtureFile(t, root, ".nuclei-ignore", "tags: []\nfiles: []\n")

	// Add a dynamic HTTP template accepted for every service port
	writeFixtureFile(t, root, "dynamic.yaml", `id: dynamic-http
info:
  name: Dynamic HTTP
  author: example-org
  severity: info
http:
  - method: GET
    path:
      - "{{BaseURL}}"
`)

	// Add a fixed HTTP template accepted only for port 8080
	writeFixtureFile(t, root, "fixed.yaml", `id: fixed-http
info:
  name: Fixed HTTP
  author: example-org
  severity: info
http:
  - method: GET
    path:
      - "http://{{Host}}:8080"
`)

	// Add a DNS template accepted only for host scans
	writeFixtureFile(t, root, "host.yaml", `id: host-dns
info:
  name: Host DNS
  author: example-org
  severity: info
dns:
  - name: "{{FQDN}}"
    type: A
`)

	// Return the completed fixture root
	return root
}

// prepareTemplateCatalogTest clears shared state before and after a catalog test
func prepareTemplateCatalogTest(t *testing.T, root string) {

	// Clear state left by an earlier test using the same path
	t.Helper()
	invalidateTemplateCatalogForTest(t, root)

	// Clear state created by the current test after all assertions complete
	t.Cleanup(func() {

		// Invalidate through the same checked helper used during setup
		invalidateTemplateCatalogForTest(t, root)
	})
}

// invalidateTemplateCatalogForTest invalidates a catalog and fails the current test on errors
func invalidateTemplateCatalogForTest(t *testing.T, root string) {

	// Invalidate the requested test catalog with explicit error handling
	t.Helper()
	errInvalidate := invalidateTemplateCatalog(root)
	if errInvalidate != nil {
		t.Fatalf("invalidateTemplateCatalog() error = %v", errInvalidate)
	}
}

// writeFixtureFile writes one file below a test catalog root
func writeFixtureFile(t *testing.T, root, name, content string) {

	// Write the fixture with permissions limited to the current user
	t.Helper()
	errWrite := os.WriteFile(filepath.Join(root, name), []byte(content), 0o600)
	if errWrite != nil {
		t.Fatalf("os.WriteFile(%q) error = %v", name, errWrite)
	}
}

// assertSourceIds verifies an unordered selection of template identifiers
func assertSourceIds(t *testing.T, sources []templateSource, want ...string) {

	// Copy source identifiers into the common assertion format
	t.Helper()
	gotIds := make([]string, 0, len(sources))
	for _, source := range sources {
		gotIds = append(gotIds, source.id)
	}

	// Reuse the identifier assertion for the converted selection
	assertTemplateIds(t, gotIds, want)
}

// assertTemplateIds verifies an unordered slice of template identifiers
func assertTemplateIds(t *testing.T, gotIds, wantIds []string) {

	// Build a set from the selected identifiers
	t.Helper()
	got := make(map[string]struct{}, len(gotIds))
	for _, templateId := range gotIds {
		got[templateId] = struct{}{}
	}

	// Reject selections with a different number of identifiers
	if len(got) != len(wantIds) {
		t.Fatalf("template IDs = %v, want %v", gotIds, wantIds)
	}

	// Verify every expected identifier is present
	for _, templateId := range wantIds {
		if _, exists := got[templateId]; !exists {
			t.Errorf("template IDs = %v, missing %q", gotIds, templateId)
		}
	}
}
