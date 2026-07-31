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
	"os/exec"
	"testing"

	"github.com/siemens/GoScans/_test"
	"github.com/siemens/GoScans/utils"
)

// Test_NewScanner verifies that NewScanner returns an error for an invalid Python path and succeeds with a valid one.
func Test_NewScanner(t *testing.T) {

	// Prepare test variables
	testLogger := utils.NewTestLogger()

	// Retrieve test settings
	testSettings := _test.GetSettings()

	// Detect SSLyze dynamically so the test assertion adapts to
	// any environment: CI with full toolchain (wantErr=false for "valid") and
	// local dev without SSLyze (wantErr=true for "valid").
	sslyzeAvailable := false
	if testSettings.PathPython != "" {
		if _, errCombinedOutput := exec.Command(testSettings.PathPython, "-m", "sslyze", "--help").CombinedOutput(); errCombinedOutput == nil {
			sslyzeAvailable = true
		}
	}

	// Prepare and run test cases
	type args struct {
		pythonPath       string
		customTruststore string
		target           string
		port             int
		vhosts           []string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "invalid-path-python",
			args: args{
				pythonPath:       "xxx",
				customTruststore: "",
				target:           "sub.domain.tld",
				port:             443,
				vhosts:           nil,
			},
			wantErr: true,
		},
		{
			// wantErr mirrors sslyze availability: false when Python+SSLyze are
			// present (CI with full toolchain), true when SSLyze is missing.
			name: "valid",
			args: args{
				pythonPath:       testSettings.PathPython,
				customTruststore: "",
				target:           "sub.domain.tld",
				port:             443,
				vhosts:           nil,
			},
			wantErr: !sslyzeAvailable,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, errNewScanner := NewScanner(testLogger, tt.args.pythonPath, tt.args.customTruststore, tt.args.target,
				tt.args.port, tt.args.vhosts)
			if (errNewScanner != nil) != tt.wantErr {
				t.Errorf("NewScanner() error = '%v', wantErr = '%v'", errNewScanner, tt.wantErr)
				return
			}
		})
	}
}
