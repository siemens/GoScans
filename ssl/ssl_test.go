/*
* GoScans, a collection of network scan modules for infrastructure discovery and information gathering.
*
* Copyright (c) Siemens AG, 2016-2026.
*
* This work is licensed under the terms of the MIT license. For a copy, see the LICENSE file in the top-level
* directory or visit <https://opensource.org/licenses/MIT>.
*
 */

package ssl

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/siemens/GoScans/_test"
	"github.com/siemens/GoScans/utils"
)

// TestMain initializes the test environment and runs all tests in the ssl package.
func TestMain(m *testing.M) {

	// Retrieve test settings
	_test.GetSettings()

	// Prepare test directory
	tmpDir, errTmpDir := os.MkdirTemp(".", "goscans-ssl-test-*")
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

// TestScanner_SetContext_SetsOnFirstCallOnly verifies that SetContext only accepts the first context and ignores subsequent ones.
func TestScanner_SetContext_SetsOnFirstCallOnly(t *testing.T) {

	// Prepare scanner with minimum required fields
	s := &Scanner{
		logger: utils.NewTestLogger(),
	}

	// Set initial context
	ctx1, cancel1 := context.WithCancel(context.Background())
	defer cancel1()
	s.SetContext(ctx1)

	// Verify context was set
	if s.contextInner != ctx1 {
		t.Errorf("SetContext() contextInner = '%v', want = '%v'", s.contextInner, ctx1)
	}

	// Set second context, which should be ignored
	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()
	s.SetContext(ctx2)

	// Verify context was not replaced
	if s.contextInner != ctx1 {
		t.Errorf("SetContext() contextInner = '%v', want = '%v' (should not have changed)", s.contextInner, ctx1)
	}
}

// TestScanner_LoadCiphers verifies that LoadCiphers populates the cipher mapping without errors.
func TestScanner_LoadCiphers(t *testing.T) {

	// Prepare test variables
	testLogger := utils.NewTestLogger()

	// Test load
	LoadCiphers(testLogger)
}

// TestScanner_DuplicateCiphers verifies that only known allowed duplicate OpenSSL cipher names exist in the cipher mapping.
func TestScanner_DuplicateCiphers(t *testing.T) {

	// Prepare test variables
	testLogger := utils.NewTestLogger()

	LoadCiphers(testLogger)

	for name, ciphers := range cipherMapping {
		if len(ciphers) != 1 {
			if len(ciphers) != 2 {
				t.Errorf("Normally there's a maximum of 2 ciphers with the same OpenSSL name. We have '%d'.", len(ciphers))
				continue
			}

			if (ciphers[0].Id == "0x010080" && ciphers[1].Id == "0x04") || //  RC4-MD5
				(ciphers[0].Id == "0x04" && ciphers[1].Id == "0x010080") || // RC4-MD5
				(ciphers[0].Id == "0x040080" && ciphers[1].Id == "0x06") || // EXP-RC2-CBC-MD5
				(ciphers[0].Id == "0x06" && ciphers[1].Id == "0x040080") || // EXP-RC2-CBC-MD5
				(ciphers[0].Id == "0x020080" && ciphers[1].Id == "0x03") || // EXP-RC4-MD5
				(ciphers[0].Id == "0x03" && ciphers[1].Id == "0x020080") { //  EXP-RC4-MD5
				continue
			}

			// Unknown duplicates.
			t.Errorf("Unknown duplicates: %s", name)
		}
	}
}

// TestParseSslyzeVersion verifies that parseSslyzeVersion correctly extracts the version from SSLyze help output.
func TestParseSslyzeVersion(t *testing.T) {

	// Prepare and run test cases
	tests := []struct {
		name      string
		input     string
		wantErr   bool
		wantMajor int
		wantMinor int
		wantPatch int
	}{
		{
			name:      "valid-5-0-0",
			input:     "SSLyze version 5.0.0\npositional arguments",
			wantErr:   false,
			wantMajor: 5,
			wantMinor: 0,
			wantPatch: 0,
		},
		{
			name:      "valid-5-1-2",
			input:     "SSLyze version 5.1.2\npositional arguments\nsome more text",
			wantErr:   false,
			wantMajor: 5,
			wantMinor: 1,
			wantPatch: 2,
		},
		{
			name:    "missing-version-prefix",
			input:   "No version information here\npositional arguments",
			wantErr: true,
		},
		{
			name:    "missing-arguments-suffix",
			input:   "SSLyze version 5.0.0\nno arguments suffix here",
			wantErr: true,
		},
		{
			name:    "empty-input",
			input:   "",
			wantErr: true,
		},
		{
			name:    "invalid-version-format",
			input:   "SSLyze version invalid\npositional arguments",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			version, errVersion := parseSslyzeVersion(tt.input)
			if (errVersion != nil) != tt.wantErr {
				t.Errorf("parseSslyzeVersion() error = '%v', wantErr = '%v'", errVersion, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if version.Major != tt.wantMajor {
					t.Errorf("parseSslyzeVersion() Major = '%v', want = '%v'", version.Major, tt.wantMajor)
				}
				if version.Minor != tt.wantMinor {
					t.Errorf("parseSslyzeVersion() Minor = '%v', want = '%v'", version.Minor, tt.wantMinor)
				}
				if version.Patch != tt.wantPatch {
					t.Errorf("parseSslyzeVersion() Patch = '%v', want = '%v'", version.Patch, tt.wantPatch)
				}
			}
		})
	}
}

// TestScanner_Results verifies that a live SSL scan returns expected compliance, vulnerability, and curve results.
func TestScanner_Results(t *testing.T) {

	// Retrieve test settings
	testSettings := _test.GetSettings()
	if testSettings.PathSslyze == "" {
		t.Skip("Integration test skipped: PathSslyze not configured in _test/settings.go")
		return
	}

	// Prepare test variables
	testLogger := utils.NewTestLogger()

	// Prepare test scans
	type args struct {
		target           string
		port             int
		vhosts           []string
		sslyzePath       string
		customTruststore string
	}
	type scanResults struct { // The attributes of the results to be tested
		Status         string
		IsCompliant    bool // Check against Mozilla's recommended SSL config
		VulnHeartBleed bool
		NumSupportedEC int // Number of supported elliptic curves
	}
	tests := []struct {
		name            string
		args            args
		expectedResults scanResults
	}{
		{
			name: "www.mozilla.org",
			args: args{
				target:           "www.mozilla.org",
				port:             443,
				vhosts:           nil,
				sslyzePath:       testSettings.PathSslyze,
				customTruststore: "",
			},
			expectedResults: scanResults{
				Status:         "Completed",
				IsCompliant:    false,
				VulnHeartBleed: false,
				NumSupportedEC: 3,
			},
		},
	}

	// Run test scans
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scanner, errScanner := NewScanner(testLogger, tt.args.sslyzePath, tt.args.customTruststore, tt.args.target,
				tt.args.port, tt.args.vhosts)
			if errScanner != nil {
				t.Errorf("NewScanner() error = '%v', want = 'nil'", errScanner)
				return
			}

			// Add timeout
			timeout := 60 * time.Second

			// Run scan
			result := scanner.Run(timeout)

			// Verify scan results
			if result.Status != tt.expectedResults.Status {
				t.Errorf("Result.Status = '%v', want = '%v'", result.Status, tt.expectedResults.Status)
			}
			if result.Data[0].Settings.IsCompliantToMozillaConfig != tt.expectedResults.IsCompliant {
				t.Errorf("Result.Data[0].Settings.IsCompliantToMozillaConfig = '%v', want = '%v'",
					result.Data[0].Settings.IsCompliantToMozillaConfig, tt.expectedResults.IsCompliant)
			}
			if result.Data[0].Issues.Heartbleed != tt.expectedResults.VulnHeartBleed {
				t.Errorf("Result.Data[0].Issues.Heartbleed = '%v', want = '%v'",
					result.Data[0].Issues.Heartbleed, tt.expectedResults.VulnHeartBleed)
			}
			if len(result.Data[0].Curves.SupportedCurves) != tt.expectedResults.NumSupportedEC {
				t.Errorf("len(Result.Data[0].Curves.SupportedCurves) = '%v', want = '%v'",
					len(result.Data[0].Curves.SupportedCurves), tt.expectedResults.NumSupportedEC)
			}
		})
	}
}
