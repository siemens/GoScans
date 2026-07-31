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
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/siemens/GoScans/_test"
	"github.com/siemens/GoScans/utils"
)

// TestMain initializes the test environment and runs all tests in the nuclei package.
func TestMain(m *testing.M) {

	// Retrieve test settings
	_test.GetSettings()

	// Prepare test directory
	tmpDir, errTmpDir := os.MkdirTemp(".", "goscans-nuclei-test-*")
	if errTmpDir != nil {
		panic(errTmpDir)
	}
	if errChdir := os.Chdir(tmpDir); errChdir != nil {
		panic(errChdir)
	}

	// Run tests
	code := m.Run()

	// Prepare cleanup
	_ = os.Chdir("..")
	_ = os.RemoveAll(tmpDir)

	// Return nil as everything went fine
	os.Exit(code)
}

// TestNewScanner verifies that NewScanner returns an error for invalid template paths and no error for valid configurations.
func TestNewScanner(t *testing.T) {

	// Retrieve test settings
	testSettings := _test.GetSettings()
	if testSettings.PathNucleiTemplates == "" {
		t.Skip("Integration test skipped: PathNucleiTemplates not configured in _test/settings.go")
		return
	}

	// Prepare test variables
	testLogger := utils.NewTestLogger()

	// Prepare and run test cases
	type args struct {
		target        string
		pathTemplates string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name:    "valid",
			args:    args{target: "127.0.0.1", pathTemplates: testSettings.PathNucleiTemplates},
			wantErr: false,
		},
		{
			name:    "invalid-templates-notexisting",
			args:    args{target: "127.0.0.1", pathTemplates: "notexisting"},
			wantErr: true,
		},
		{
			name:    "invalid-templates-empty",
			args:    args{target: "127.0.0.1", pathTemplates: ""},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, errNewScanner := NewScanner(testLogger, tt.args.target, nil, tt.args.pathTemplates, "", "", nil, nil, nil, nil, "", "", "", "", "")
			if (errNewScanner != nil) != tt.wantErr {
				t.Errorf("NewScanner() error = '%v', wantErr = '%v'", errNewScanner, tt.wantErr)
			}
		})
	}
}

// TestTemplateCatalogExpandsSplitVariants verifies cached expansion of split template identifiers
func TestTemplateCatalogExpandsSplitVariants(t *testing.T) {

	// Prepare a temporary directory containing split variant YAML files
	templatesDir := t.TempDir()
	for _, name := range []string{"ssl-heartbleed_443.yaml", "http-redirect_8080.yaml", "unrelated.yaml"} {
		errWrite := os.WriteFile(filepath.Join(templatesDir, name), []byte(""), 0o644)
		if errWrite != nil {
			t.Fatalf("os.WriteFile() error = '%v'", errWrite)
		}
	}

	// Acquire the catalog containing the cached variant mapping
	prepareTemplateCatalogTest(t, templatesDir)
	catalog, errCatalog := acquireTemplateCatalog(templatesDir)
	if errCatalog != nil {
		t.Fatalf("acquireTemplateCatalog() error = '%v'", errCatalog)
	}

	// Prepare and run test cases
	tests := []struct {
		name         string
		includeIds   []string
		excludeIds   []string
		wantIncludes []string
		wantExcludes []string
	}{
		{
			name:         "both-empty",
			includeIds:   nil,
			excludeIds:   nil,
			wantIncludes: nil,
			wantExcludes: nil,
		},
		{
			name:         "base-id-in-include-adds-variant",
			includeIds:   []string{"ssl-heartbleed"},
			excludeIds:   nil,
			wantIncludes: []string{"ssl-heartbleed", "ssl-heartbleed_443"},
			wantExcludes: nil,
		},
		{
			name:         "base-id-in-exclude-adds-variant",
			includeIds:   nil,
			excludeIds:   []string{"http-redirect"},
			wantIncludes: nil,
			wantExcludes: []string{"http-redirect", "http-redirect_8080"},
		},
		{
			name:         "unmatched-base-id-unchanged",
			includeIds:   []string{"not-in-templates"},
			excludeIds:   nil,
			wantIncludes: []string{"not-in-templates"},
			wantExcludes: nil,
		},
		{
			name:         "single-part-filename-not-treated-as-variant",
			includeIds:   []string{"unrelated"},
			excludeIds:   nil,
			wantIncludes: []string{"unrelated"},
			wantExcludes: nil,
		},
	}

	// Verify every include and exclude combination against the cached mapping
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {

			// Expand both identifier lists without another filesystem walk
			gotIncludes, gotExcludes := catalog.expandTemplateIds(test.includeIds, test.excludeIds)
			if !testStringslicesmatch(gotIncludes, test.wantIncludes) {
				t.Errorf("expandTemplateIds() includes = '%v', want = '%v'", gotIncludes, test.wantIncludes)
			}
			if !testStringslicesmatch(gotExcludes, test.wantExcludes) {
				t.Errorf("expandTemplateIds() excludes = '%v', want = '%v'", gotExcludes, test.wantExcludes)
			}
		})
	}
}

// TestFilterIntersection verifies that filterIntersection returns the correct intersection of two CSV strings.
func TestFilterIntersection(t *testing.T) {

	// Prepare and run test cases
	tests := []struct {
		name     string
		existing string
		enforced string
		want     string
	}{
		{
			name:     "empty-existing-returns-enforced",
			existing: "",
			enforced: "dns,whois",
			want:     "dns,whois",
		},
		{
			name:     "both-empty",
			existing: "",
			enforced: "",
			want:     "",
		},
		{
			name:     "no-overlap",
			existing: "http,tcp",
			enforced: "dns,whois",
			want:     "",
		},
		{
			name:     "single-overlap",
			existing: "dns,http,tcp",
			enforced: "dns,whois",
			want:     "dns",
		},
		{
			name:     "full-overlap",
			existing: "dns,whois",
			enforced: "dns,whois",
			want:     "dns,whois",
		},
		{
			name:     "spaces-in-csv-trimmed",
			existing: "dns, http",
			enforced: "dns",
			want:     "dns",
		},
		{
			name:     "duplicate-in-existing-deduped",
			existing: "dns,dns",
			enforced: "dns",
			want:     "dns",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := filterIntersection(tt.existing, tt.enforced)
			if testSortedcsv(got) != testSortedcsv(tt.want) {
				t.Errorf("filterIntersection() result = '%v', want = '%v'", got, tt.want)
			}
		})
	}
}

// TestMergeCsv verifies that mergeCsv returns a deduplicated union of two CSV strings.
func TestMergeCsv(t *testing.T) {

	// Prepare and run test cases
	tests := []struct {
		name     string
		existing string
		enforced string
		want     string
	}{
		{
			name:     "empty-existing-returns-enforced",
			existing: "",
			enforced: "dns,whois",
			want:     "dns,whois",
		},
		{
			name:     "both-empty",
			existing: "",
			enforced: "",
			want:     "",
		},
		{
			name:     "no-overlap-merges-both",
			existing: "http",
			enforced: "dns",
			want:     "dns,http",
		},
		{
			name:     "partial-overlap-deduped",
			existing: "dns,http",
			enforced: "dns,whois",
			want:     "dns,http,whois",
		},
		{
			name:     "full-overlap-deduped",
			existing: "dns",
			enforced: "dns",
			want:     "dns",
		},
		{
			name:     "spaces-in-csv-trimmed",
			existing: "dns, http",
			enforced: "dns",
			want:     "dns,http",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := mergeCsv(tt.existing, tt.enforced)
			if testSortedcsv(got) != testSortedcsv(tt.want) {
				t.Errorf("mergeCsv() result = '%v', want = '%v'", got, tt.want)
			}
		})
	}
}

// testSortedcsv splits a comma-separated string into items, sorts them, and rejoins them.
// Used for order-independent comparison of CSV outputs produced by map iteration.
func testSortedcsv(s string) string {

	// Return empty for empty input
	if s == "" {
		return ""
	}

	// Split, sort and rejoin
	items := strings.Split(s, ",")
	sort.Strings(items)

	// Return the canonically ordered CSV
	return strings.Join(items, ",")
}

// TestFetchLatestReleaseTag verifies that fetchLatestReleaseTag extracts the tag name on a valid response
// and returns an error for a non-200 status, malformed JSON, and an empty tag_name.
func TestFetchLatestReleaseTag(t *testing.T) {

	// Prepare and run test cases
	tests := []struct {
		name    string
		handler http.HandlerFunc
		wantTag string
		wantErr bool
	}{
		{
			name: "valid-response-returns-tag",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"tag_name":"v9.9.9","name":"nuclei-templates v9.9.9"}`))
			},
			wantTag: "v9.9.9",
			wantErr: false,
		},
		{
			name: "non-200-status-returns-error",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				http.Error(w, "not found", http.StatusNotFound)
			},
			wantTag: "",
			wantErr: true,
		},
		{
			name: "malformed-json-returns-error",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte(`{not-valid-json`))
			},
			wantTag: "",
			wantErr: true,
		},
		{
			name: "empty-tag-name-returns-error",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"tag_name":""}`))
			},
			wantTag: "",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			// Prepare unit test data
			srv := httptest.NewServer(tt.handler)
			t.Cleanup(srv.Close)

			// Execute and check for expected error and tag value
			got, errGot := fetchLatestReleaseTag(&http.Client{Timeout: 5 * time.Second}, srv.URL)
			if (errGot != nil) != tt.wantErr {
				t.Errorf("fetchLatestReleaseTag() error = '%v', wantErr = '%v'", errGot, tt.wantErr)
			}
			if got != tt.wantTag {
				t.Errorf("fetchLatestReleaseTag() tag = '%v', want = '%v'", got, tt.wantTag)
			}
		})
	}
}

// testStringslicesmatch reports whether two string slices contain the same elements regardless of order.
func testStringslicesmatch(a, b []string) bool {

	// Lengths must match
	if len(a) != len(b) {
		return false
	}

	// Both empty or nil — trivially equal
	if len(a) == 0 {
		return true
	}

	// Sort copies and compare element-by-element
	aCopy := make([]string, len(a))
	copy(aCopy, a)
	bCopy := make([]string, len(b))
	copy(bCopy, b)
	sort.Strings(aCopy)
	sort.Strings(bCopy)
	for i := range aCopy {
		if aCopy[i] != bCopy[i] {

			// Return false as an element differs
			return false
		}
	}

	// Return true as slices match
	return true
}

// TestScanner_targetAddr verifies that targetAddr returns "host:port" when a port is set on the scanner
// and just the host string when no port is configured.
func TestScanner_targetAddr(t *testing.T) {

	// Prepare and run test cases
	port443 := 443
	tests := []struct {
		name string
		scan Scanner
		want string
	}{
		{
			name: "with-port",
			scan: Scanner{target: "192.168.1.1", port: &port443},
			want: "192.168.1.1:443",
		},
		{
			name: "without-port",
			scan: Scanner{target: "192.168.1.1", port: nil},
			want: "192.168.1.1",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			// Execute and verify the returned address
			got := tt.scan.targetAddr()
			if got != tt.want {
				t.Errorf("targetAddr() result = '%v', want = '%v'", got, tt.want)
			}
		})
	}
}

// TestScanner_SetContext verifies that SetContext stores the provided context on the first call and ignores
// subsequent calls, preserving the originally set context.
func TestScanner_SetContext(t *testing.T) {

	// Prepare unit test data
	scan := &Scanner{}
	ctx1, cancel1 := context.WithCancel(context.Background())
	defer cancel1()
	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()

	// Verify the first call stores the context
	scan.SetContext(ctx1)
	if scan.contextInner != ctx1 {
		t.Errorf("SetContext() contextInner = '%v', want = '%v'", scan.contextInner, ctx1)
	}

	// Verify a second call does not overwrite the stored context
	scan.SetContext(ctx2)
	if scan.contextInner != ctx1 {
		t.Errorf("SetContext() second call changed contextInner = '%v', want = '%v'", scan.contextInner, ctx1)
	}
}
