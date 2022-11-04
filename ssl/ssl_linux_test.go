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
	"github.com/siemens/GoScans/utils"
	"testing"
)

func Test_NewScanner(t *testing.T) {

	// Prepare test variables
	testLogger := utils.NewTestLogger()

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
		// The installation path might differ. If this test does not pass, check it with 'which python3'
		{"valid", args{"/usr/bin/python3.7", "", "sub.domain.tld", 443, nil}, false},
		{"invalid-pathPython", args{"xxx", "", "sub.domain.tld", 443, nil}, true},
		// There should also be a test for a missing SSLyze installation, but this needs to be change in the OS.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewScanner(testLogger, tt.args.pythonPath, tt.args.customTruststore, tt.args.target,
				tt.args.port, tt.args.vhosts)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewScanner() error = '%v', wantErr = '%v'", err, tt.wantErr)
				return
			}
		})
	}
}

func Test_compareVersion(t *testing.T) {
	type args struct {
		got    string
		wanted []int
	}
	tests := []struct {
		name    string
		args    args
		want    bool
		wantErr bool
	}{
		{"valid", args{"1.2.3", []int{1, 2, 3}}, true, false},
		{"invalid-1", args{"1.2.3", []int{2, 2, 3}}, false, false},
		{"invalid-2", args{"1.2.3", []int{1, 3, 3}}, false, false},
		{"invalid-3", args{"1.2.3", []int{1, 2, 4}}, false, false},
		{"error-length-1", args{"1.2", []int{1, 2, 3}}, false, true},
		{"error-length-2", args{"1.2.3.", []int{1, 2, 3}}, false, true},
		{"error-length-3", args{"1.2.3.4", []int{1, 2, 3}}, false, true},
		{"error-length-4", args{"1.2.3", []int{1, 2}}, false, true},
		{"error-length-5", args{"1.2.3", []int{1, 2, 3, 4}}, false, true},
		{"error-prefix", args{"Python 1.2.3", []int{1, 2, 3}}, false, true},
		{"error-atoi", args{"1.asdf.3", []int{1, 2, 3}}, false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := compareVersion(tt.args.got, tt.args.wanted)
			if (err != nil) != tt.wantErr {
				t.Errorf("compareVersion() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("compareVersion() got = %v, want %v", got, tt.want)
			}
		})
	}
}
