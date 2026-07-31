/*
* GoScans, a collection of network scan modules for infrastructure discovery and information gathering.
*
* Copyright (c) Siemens AG, 2016-2026.
*
* This work is licensed under the terms of the MIT license. For a copy, see the LICENSE file in the top-level
* directory or visit <https://opensource.org/licenses/MIT>.
*
 */

package webenum

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/siemens/GoScans/_test"
	"github.com/siemens/GoScans/utils"
)

// TestMain initializes the test environment and runs all tests in the webenum package.
func TestMain(m *testing.M) {

	// Retrieve test settings
	_test.GetSettings()

	// Prepare test directory
	tmpDir, errTmpDir := os.MkdirTemp(".", "goscans-webenum-test-*")
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

// TestNewScanner verifies that NewScanner returns an error for invalid arguments and succeeds for valid ones.
func TestNewScanner(t *testing.T) {

	// Retrieve test settings
	testSettings := _test.GetSettings()

	// Prepare test variables
	testLogger := utils.NewTestLogger()
	sampleProbes := filepath.Join(testSettings.PathDataDir, "webenum", "webenum_sample_probes.txt")
	sampleProbesBroken := filepath.Join(testSettings.PathDataDir, "webenum", "webenum_sample_probes_broken.txt")
	requestTimeout := 5 * time.Second

	// Prepare and run test cases
	type args struct {
		logger       utils.Logger
		target       string
		port         int
		vhosts       []string
		https        bool
		ntlmDomain   string
		ntlmUser     string
		ntlmPassword string
		probesPath   string
		probeRobots  bool
		proxy        string
		timeout      time.Duration
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name:    "valid-basic",
			args:    args{testLogger, "domain.tld", 443, []string{"domain.tld"}, true, "", "", "", sampleProbes, true, "", time.Minute},
			wantErr: false,
		},
		{
			name:    "valid-no-robots",
			args:    args{testLogger, "domain.tld", 443, []string{"domain.tld"}, true, "", "", "", sampleProbes, false, "", time.Minute},
			wantErr: false,
		},
		{
			name:    "valid-no-vhosts",
			args:    args{testLogger, "domain.tld", 443, []string{}, true, "", "", "", sampleProbes, true, "", time.Minute},
			wantErr: false,
		},
		{
			name:    "invalid-broken-probes",
			args:    args{testLogger, "domain.tld", 443, []string{"domain.tld"}, true, "", "", "", sampleProbesBroken, true, "", time.Minute},
			wantErr: true,
		},
		{
			name:    "invalid-probes-path",
			args:    args{testLogger, "domain.tld", 443, []string{"domain.tld"}, true, "", "", "", "probes.txt", true, "", time.Minute},
			wantErr: true,
		},
		{
			name:    "invalid-proxy-1",
			args:    args{testLogger, "domain.tld", 443, []string{"domain.tld"}, true, "", "", "", "probes.txt", true, "localhost:8080", time.Minute},
			wantErr: true,
		},
		{
			name:    "invalid-proxy-2",
			args:    args{testLogger, "domain.tld", 443, []string{"domain.tld"}, true, "", "", "", "probes.txt", true, "no url", time.Minute},
			wantErr: true,
		},
		{
			name:    "invalid-target-1",
			args:    args{testLogger, "not existing", 443, []string{"domain.tld"}, true, "", "", "", "probes.txt", true, "", time.Minute},
			wantErr: true,
		},
		{
			name:    "invalid-target-2",
			args:    args{testLogger, "192.168.0.1/24", 443, []string{"domain.tld"}, true, "", "", "", "probes.txt", true, "", time.Minute},
			wantErr: true,
		},
		{
			name:    "incomplete-ntlm-creds-1",
			args:    args{testLogger, "domain.tld", 443, []string{"domain.tld"}, true, "wrong", "", "", sampleProbes, true, "", time.Minute},
			wantErr: true,
		},
		{
			name:    "incomplete-ntlm-creds-2",
			args:    args{testLogger, "domain.tld", 443, []string{"domain.tld"}, true, "", "wrong", "", sampleProbes, true, "", time.Minute},
			wantErr: true,
		},
		{
			name:    "incomplete-ntlm-creds-3",
			args:    args{testLogger, "domain.tld", 443, []string{"domain.tld"}, true, "", "", "wrong", sampleProbes, true, "", time.Minute},
			wantErr: true,
		},
		{
			name:    "invalid-path",
			args:    args{testLogger, "domain.tld", 443, []string{"domain.tld"}, true, "", "", "", "?", true, "", time.Minute},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, errNewScanner := NewScanner(tt.args.logger, tt.args.target, tt.args.port, tt.args.vhosts, tt.args.https,
				tt.args.ntlmDomain, tt.args.ntlmUser, tt.args.ntlmPassword, tt.args.probesPath, tt.args.probeRobots,
				testSettings.HttpUserAgent, tt.args.proxy, requestTimeout,
			)
			if (errNewScanner != nil) != tt.wantErr {
				t.Errorf("NewScanner() error = '%v', wantErr = '%v'", errNewScanner, tt.wantErr)
				return
			}
		})
	}
}

// TestLoadProbes verifies that loadProbes parses a valid probes file and returns an error for broken files.
func TestLoadProbes(t *testing.T) {

	// Retrieve test settings
	testSettings := _test.GetSettings()

	// Prepare test variables
	sampleProbes := filepath.Join(testSettings.PathDataDir, "webenum", "webenum_sample_probes.txt")
	sampleProbesBroken := filepath.Join(testSettings.PathDataDir, "webenum", "webenum_sample_probes_broken.txt")

	// Prepare an empty probes file in the isolated test directory
	emptyFile, errEmptyFile := os.CreateTemp(".", "empty-probes-*.txt")
	if errEmptyFile != nil {
		t.Fatalf("TestLoadProbes could not create empty probes file: '%v'", errEmptyFile)
	}
	_ = emptyFile.Close()
	emptyPath := emptyFile.Name()
	defer func() { _ = os.Remove(emptyPath) }()

	// Prepare and run test cases
	tests := []struct {
		name    string
		path    string
		want    []Probe
		wantErr bool
	}{
		{
			name:    "valid",
			path:    sampleProbes,
			want:    []Probe{{"Apache default content", "/icons/", []string(nil)}, {"Git", "/git/", []string(nil)}, {"Git", "/users/sign_in", []string{"href=\"https://about.gitlab.com/\"", "GitLab"}}, {"PhpMyAdmin", "/php-myadmin/", []string(nil)}, {"PhpMyAdmin", "/phpmyadmin/index.php", []string{"<input type=\"text\" name=\"pma_username\" id=\"input_username\"", "<label for=\"select_server\">", "function PMA_focusInput()"}}, {"Entitlement POST Form", "/wahtever/", []string{"<input type=\"hidden\" name=\"SAMLRequest\""}}},
			wantErr: false,
		},
		{
			name:    "broken",
			path:    sampleProbesBroken,
			want:    []Probe(nil),
			wantErr: true,
		},
		{
			name:    "nonexistent-file",
			path:    "nonexistent-probes-file.txt",
			want:    []Probe(nil),
			wantErr: true,
		},
		{
			name:    "empty-file",
			path:    emptyPath,
			want:    []Probe(nil),
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, errGot := loadProbes(tt.path)
			if (errGot != nil) != tt.wantErr {
				t.Errorf("loadProbes() error = '%v', wantErr = '%v'", errGot, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("loadProbes() = '%v', want = '%v'", got, tt.want)
			}
		})
	}
}

// robotsTxt is the static robots.txt served by the test server for the "valid" case.
const robotsTxt = `User-agent: *
Disallow: *cr-dokumentation.pdf$
Disallow: /gutscheine/suche?
Disallow: /gutscheine/*?code=*
Disallow: /gutscheine/*&code=*
Sitemap: https://www.spiegel.de/sitemaps/news-de.xml
Sitemap: https://www.spiegel.de/sitemaps/videos/sitemap.xml
Sitemap: https://www.spiegel.de/plus/sitemap.xml
Sitemap: https://www.spiegel.de/sitemap.xml
Sitemap: https://www.spiegel.de/gutscheine/sitemap.xml
`

// TestLoadProbesRobots verifies that loadProbesRobots fetches and parses a robots.txt file into probes.
func TestLoadProbesRobots(t *testing.T) {

	// Retrieve test settings
	testSettings := _test.GetSettings()

	// Set up test HTTP servers to avoid live internet dependency.
	robotsServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte(robotsTxt))
	}))
	t.Cleanup(robotsServer.Close)

	noRobotsServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	t.Cleanup(noRobotsServer.Close)

	errorServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "internal server error", http.StatusInternalServerError)
	}))
	t.Cleanup(errorServer.Close)

	// Prepare test variables. No proxy is used so httptest loopback servers are reached directly.
	testRequester := utils.NewRequester(utils.ReuseNone, "", "", "", testSettings.HttpUserAgent, nil, time.Second*8, utils.InsecureTransportFactory, utils.ClientFactory)

	// Prepare and run test cases
	type args struct {
		url   string
		vName string
	}
	tests := []struct {
		name    string
		args    args
		want    []Probe
		wantErr bool
	}{
		{
			// Port 1 is always refused. Connection-refused is a reliable non-DNS error.
			name:    "invalid-url",
			args:    args{"http://127.0.0.1:1/robots.txt", "127.0.0.1"},
			want:    []Probe(nil),
			wantErr: true,
		},
		{
			name:    "no-robots",
			args:    args{noRobotsServer.URL + "/robots.txt", "no-robots-host"},
			want:    []Probe(nil),
			wantErr: false,
		},
		{
			name:    "server-error",
			args:    args{errorServer.URL + "/robots.txt", "error-host"},
			want:    []Probe(nil),
			wantErr: false,
		},
		{
			// Served by a local httptest.Server to avoid live-data drift.
			name: "valid",
			args: args{robotsServer.URL + "/robots.txt", "www.spiegel.de"},
			want: []Probe{
				{"Disallowed by robots.txt", "*cr-dokumentation.pdf$", []string(nil)},
				{"Disallowed by robots.txt", "gutscheine/suche?", []string(nil)},
				{"Disallowed by robots.txt", "gutscheine/*?code=*", []string(nil)},
				{"Disallowed by robots.txt", "gutscheine/*&code=*", []string(nil)},
				{"Sitemap by robots.txt", "sitemaps/news-de.xml", []string(nil)},
				{"Sitemap by robots.txt", "sitemaps/videos/sitemap.xml", []string(nil)},
				{"Sitemap by robots.txt", "plus/sitemap.xml", []string(nil)},
				{"Sitemap by robots.txt", "sitemap.xml", []string(nil)},
				{"Sitemap by robots.txt", "gutscheine/sitemap.xml", []string(nil)},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, errGot := loadProbesRobots(testRequester, tt.args.url, tt.args.vName)
			if (errGot != nil) != tt.wantErr {
				t.Errorf("loadProbesRobots() error = '%v', wantErr = '%v'", errGot, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("loadProbesRobots() = '%v', want = '%v'", got, tt.want)
			}
		})
	}
}

// TestPathsFromRobotsLine verifies that pathsFromRobotsLine splits comma-separated values from a robots.txt line.
func TestPathsFromRobotsLine(t *testing.T) {

	// Prepare and run test cases
	tests := []struct {
		name string
		line string
		want []string
	}{
		{name: "sample-1", line: "key: val1, val2, val3", want: []string{"val1", "val2", "val3"}},
		{name: "sample-2", line: "key: val1,val2", want: []string{"val1", "val2"}},
		{name: "sample-3", line: "key : val1, val2, val3", want: []string{"val1", "val2", "val3"}},
		{name: "sample-4", line: "key: val1, val2, val3, ", want: []string{"val1", "val2", "val3"}},
		{name: "empty-value", line: "key: ", want: []string{}},
		{name: "no-colon", line: "no-colon-line", want: []string{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := pathsFromRobotsLine(tt.line); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("pathsFromRobotsLine() = '%v', want = '%v'", got, tt.want)
			}
		})
	}
}
