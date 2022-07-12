/*
* GoScans, a collection of network scan modules for infrastructure discovery and information gathering.
*
* Copyright (c) Siemens AG, 2016-2021.
*
* This work is licensed under the terms of the MIT license. For a copy, see the LICENSE file in the top-level
* directory or visit <https://opensource.org/licenses/MIT>.
*
 */

package ssl

import (
	"fmt"
	"github.com/siemens/GoScans/_test"
	"github.com/siemens/GoScans/utils"
	"testing"
	"time"
)

func TestScanner_LoadCiphers(t *testing.T) {

	// Prepare test variables
	testLogger := utils.NewTestLogger()

	// Test load
	LoadCiphers(testLogger)
}

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

// An assertion function to be used in testing
func assertEqual(t *testing.T, a interface{}, b interface{}, message string) {
	if a == b {
		return
	}
	if len(message) == 0 {
		message = fmt.Sprintf("%v != %v", a, b)
	}
	t.Fatal(message)
}

// TestScanner_Results tests the results of a scan against some expected results
func TestScanner_Results(t *testing.T) {

	// Retrieve test settings
	testSettings, errSettings := _test.GetSettings()
	if errSettings != nil {
		t.Errorf("Invalid test settings: %s", errSettings)
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
		{"www.mozilla.org", args{"www.mozilla.org", 443, nil, testSettings.PathSslyze, ""},
			scanResults{"Completed", false, false, 3}},
	}

	// Run test scans
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scanner, err := NewScanner(testLogger, tt.args.sslyzePath, tt.args.customTruststore, tt.args.target,
				tt.args.port, tt.args.vhosts)
			if err != nil {
				t.Errorf("Cannot initilize Scanner for %s: %s", tt.name, err)
				return
			}

			// Add timeout
			timeout := 60 * time.Second

			// Run scan
			result := scanner.Run(timeout)

			// Test asserts
			assertEqual(t, result.Status, tt.expectedResults.Status, fmt.Sprintf("Scan not completed for %s", tt.name))
			assertEqual(t, result.Data[0].Issues.IsCompliantToMozillaConfig,
				tt.expectedResults.IsCompliant, fmt.Sprintf("Wrong results for Mozilla's compliance check for %s", tt.name))
			assertEqual(t, result.Data[0].Issues.Heartbleed,
				tt.expectedResults.VulnHeartBleed, fmt.Sprintf("Wrong results for Heartbleed check for %s", tt.name))
			assertEqual(t, len(result.Data[0].EllipticCurves.SupportedCurves),
				tt.expectedResults.NumSupportedEC, fmt.Sprintf("Wrong results for the number of supported elliptic curves for %s", tt.name))
		})
	}
}
