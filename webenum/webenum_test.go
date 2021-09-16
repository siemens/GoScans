/*
* GoScans, a collection of network scan modules for infrastructure discovery and information gathering.
*
* Copyright (c) Siemens AG, 2016-2021.
*
* This work is licensed under the terms of the MIT license. For a copy, see the LICENSE file in the top-level
* directory or visit <https://opensource.org/licenses/MIT>.
*
 */

package webenum

import (
	"go-scans/_test"
	"go-scans/utils"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func TestNewScanner(t *testing.T) {

	// Retrieve test settings
	testSettings, errSettings := _test.GetSettings()
	if errSettings != nil {
		t.Errorf("Invalid test settings: %s", errSettings)
		return
	}

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
		{"valid-basic", args{testLogger, "domain.tld", 443, []string{"domain.tld"}, true, "", "", "", sampleProbes, true, "", time.Minute}, false},
		{"valid-no-robots", args{testLogger, "domain.tld", 443, []string{"domain.tld"}, true, "", "", "", sampleProbes, false, "", time.Minute}, false},
		{"valid-no-vhosts", args{testLogger, "domain.tld", 443, []string{}, true, "", "", "", sampleProbes, true, "", time.Minute}, false},
		{"invalid-broken-probes", args{testLogger, "domain.tld", 443, []string{"domain.tld"}, true, "", "", "", sampleProbesBroken, true, "", time.Minute}, true},
		{"invalid-probes-path", args{testLogger, "domain.tld", 443, []string{"domain.tld"}, true, "", "", "", "probes.txt", true, "", time.Minute}, true},
		{"invalid-proxy-1", args{testLogger, "domain.tld", 443, []string{"domain.tld"}, true, "", "", "", "probes.txt", true, "localhost:8080", time.Minute}, true},
		{"invalid-proxy-2", args{testLogger, "domain.tld", 443, []string{"domain.tld"}, true, "", "", "", "probes.txt", true, "no url", time.Minute}, true},
		{"invalid-target-1", args{testLogger, "not existing", 443, []string{"domain.tld"}, true, "", "", "", "probes.txt", true, "", time.Minute}, true},
		{"invalid-target-2", args{testLogger, "192.168.0.1/24", 443, []string{"domain.tld"}, true, "", "", "", "probes.txt", true, "", time.Minute}, true},
		{"incomplete-ntlm-creds-1", args{testLogger, "domain.tld", 443, []string{"domain.tld"}, true, "wrong", "", "", sampleProbes, true, "", time.Minute}, true},
		{"incomplete-ntlm-creds-2", args{testLogger, "domain.tld", 443, []string{"domain.tld"}, true, "", "wrong", "", sampleProbes, true, "", time.Minute}, true},
		{"incomplete-ntlm-creds-3", args{testLogger, "domain.tld", 443, []string{"domain.tld"}, true, "", "", "wrong", sampleProbes, true, "", time.Minute}, true},
		{"invalid-path", args{testLogger, "domain.tld", 443, []string{"domain.tld"}, true, "", "", "", "?", true, "", time.Minute}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewScanner(tt.args.logger, tt.args.target, tt.args.port, tt.args.vhosts, tt.args.https,
				tt.args.ntlmDomain, tt.args.ntlmUser, tt.args.ntlmPassword, tt.args.probesPath, tt.args.probeRobots,
				testSettings.HttpUserAgent, tt.args.proxy, requestTimeout,
			)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewScanner() error = '%v', wantErr = '%v'", err, tt.wantErr)
				return
			}
		})
	}
}

func TestLoadProbes(t *testing.T) {

	// Retrieve test settings
	testSettings, errSettings := _test.GetSettings()
	if errSettings != nil {
		t.Errorf("Invalid test settings: %s", errSettings)
		return
	}

	// Prepare test variables
	sampleProbes := filepath.Join(testSettings.PathDataDir, "webenum", "webenum_sample_probes.txt")
	sampleProbesBroken := filepath.Join(testSettings.PathDataDir, "webenum", "webenum_sample_probes_broken.txt")

	// Prepare and run test cases
	tests := []struct {
		name    string
		path    string
		want    []Probe
		wantErr bool
	}{
		{"valid", sampleProbes, []Probe{{"Apache default content", "/icons/", []string(nil)}, {"Git", "/git/", []string(nil)}, {"Git", "/users/sign_in", []string{"href=\"https://about.gitlab.com/\"", "GitLab"}}, {"PhpMyAdmin", "/php-myadmin/", []string(nil)}, {"PhpMyAdmin", "/phpmyadmin/index.php", []string{"<input type=\"text\" name=\"pma_username\" id=\"input_username\"", "<label for=\"select_server\">", "function PMA_focusInput()"}}, {"Entitlement POST Form", "/wahtever/", []string{"<input type=\"hidden\" name=\"SAMLRequest\""}}}, false},
		{"broken", sampleProbesBroken, []Probe(nil), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := loadProbes(tt.path)
			if (err != nil) != tt.wantErr {
				t.Errorf("loadProbes() error = '%v', wantErr = '%v'", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("loadProbes() = '%v', want = '%v'", got, tt.want)
			}
		})
	}
}

func TestLoadProbesRobots(t *testing.T) {

	// Retrieve test settings
	testSettings, errSettings := _test.GetSettings()
	if errSettings != nil {
		t.Errorf("Invalid test settings: %s", errSettings)
		return
	}

	// Prepare test variables
	testRequester := utils.NewRequester(utils.ReuseNone, "", "", "", testSettings.HttpUserAgent, testSettings.HttpProxy, time.Second*8, utils.InsecureTransportFactory, utils.ClientFactory)

	// Prepare and run test cases
	type args struct {
		url       string
		vName     string
		userAgent string
	}
	tests := []struct {
		name    string
		args    args
		want    []Probe
		wantErr bool
	}{
		{"invalid-url", args{"https://notexisting.com:443/robots.txt", "notexisting.com", ""}, []Probe(nil), true},
		{"no-robots", args{"https://www.bahn.de:443/robots.txt", "www.bahn.de", ""}, []Probe(nil), false},
		{"valid", args{"https://www.spiegel.de/robots.txt", "www.spiegel.de", ""}, []Probe{
			{"Disallowed by robots.txt", "*cr-dokumentation.pdf$", []string(nil)},
			{"Disallowed by robots.txt", "gutscheine/suche?", []string(nil)},
			{"Disallowed by robots.txt", "gutscheine/*?code=*", []string(nil)},
			{"Disallowed by robots.txt", "gutscheine/*&code=*", []string(nil)},
			{"Sitemap by robots.txt", "sitemaps/news-de.xml", []string(nil)},
			{"Sitemap by robots.txt", "sitemaps/videos/sitemap.xml", []string(nil)},
			{"Sitemap by robots.txt", "plus/sitemap.xml", []string(nil)},
			{"Sitemap by robots.txt", "sitemap.xml", []string(nil)},
			{"Sitemap by robots.txt", "gutscheine/sitemap.xml", []string(nil)},
		}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := loadProbesRobots(testRequester, tt.args.url, tt.args.vName)
			if (err != nil) != tt.wantErr {
				t.Errorf("loadProbesRobots() error = '%v', wantErr = '%v'", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("loadProbesRobots() = '%v', want = '%v'", got, tt.want)
			}
		})
	}
}

func TestPathsFromRobotsLine(t *testing.T) {

	// Prepare and run test cases
	tests := []struct {
		name string
		line string
		want []string
	}{
		{"sample-1", "key: val1, val2, val3", []string{"val1", "val2", "val3"}},
		{"sample-2", "key: val1,val2", []string{"val1", "val2"}},
		{"sample-3", "key : val1, val2, val3", []string{"val1", "val2", "val3"}},
		{"sample-4", "key: val1, val2, val3, ", []string{"val1", "val2", "val3"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := pathsFromRobotsLine(tt.line); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("pathsFromRobotsLine() = '%v', want = '%v'", got, tt.want)
			}
		})
	}
}
