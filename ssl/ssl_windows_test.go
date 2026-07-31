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
	"testing"

	"github.com/siemens/GoScans/_test"
	"github.com/siemens/GoScans/utils"
)

// Test_NewScanner verifies that NewScanner returns no error for a valid SSLyze path and an error for an invalid one.
func Test_NewScanner(t *testing.T) {

	// Retrieve test settings
	testSettings := _test.GetSettings()
	if testSettings.PathSslyze == "" {
		t.Skip("Integration test skipped: PathSslyze not configured in _test/settings.go")
		return
	}

	// Prepare test variables
	testLogger := utils.NewTestLogger()

	// Prepare and run test cases
	type args struct {
		target           string
		port             int
		vhosts           []string
		sslyzePath       string
		customTruststore string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "valid",
			args: args{
				target:           "sub.domain.tld",
				port:             443,
				vhosts:           nil,
				sslyzePath:       testSettings.PathSslyze,
				customTruststore: "",
			},
			wantErr: false,
		},
		{
			name: "invalid-path-sslyze",
			args: args{
				target:           "sub.domain.tld",
				port:             443,
				vhosts:           nil,
				sslyzePath:       "xxx",
				customTruststore: "",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, errNewScanner := NewScanner(testLogger, tt.args.sslyzePath, tt.args.customTruststore, tt.args.target,
				tt.args.port, tt.args.vhosts)
			if (errNewScanner != nil) != tt.wantErr {
				t.Errorf("NewScanner() error = '%v', wantErr = '%v'", errNewScanner, tt.wantErr)
				return
			}
		})
	}
}
