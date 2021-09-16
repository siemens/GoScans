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
	"go-scans/_test"
	"go-scans/utils"
	"testing"
)

func Test_NewScanner(t *testing.T) {

	// Retrieve test settings
	testSettings, errSettings := _test.GetSettings()
	if errSettings != nil {
		t.Errorf("Invalid test settings: %s", errSettings)
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
		{"valid", args{"sub.domain.tld", 443, nil, testSettings.PathSslyze, ""}, false},
		{"invalid-pathSslyze", args{"sub.domain.tld", 443, nil, "xxx", ""}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewScanner(testLogger, tt.args.sslyzePath, tt.args.customTruststore, tt.args.target,
				tt.args.port, tt.args.vhosts)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewScanner() error = '%v', wantErr = '%v'", err, tt.wantErr)
				return
			}
		})
	}
}
