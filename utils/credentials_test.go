/*
* GoScans, a collection of network scan modules for infrastructure discovery and information gathering.
*
* Copyright (c) Siemens AG, 2016-2021.
*
* This work is licensed under the terms of the MIT license. For a copy, see the LICENSE file in the top-level
* directory or visit <https://opensource.org/licenses/MIT>.
*
 */

package utils

import "testing"

func TestValidCredentialsSet(t *testing.T) {

	// Prepare and run test cases
	type args struct {
		domain   string
		user     string
		password string
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{"valid-no-creds", args{"", "", ""}, true},
		{"valid-no-domain", args{"", "user", "pass"}, true},
		{"valid-all", args{"domain", "user", "pass"}, true},
		{"invalid-no-pass", args{"domain", "user", ""}, false},
		{"invalid-no-user", args{"domain", "", "pass"}, false},
		{"invalid-no-creds", args{"domain", "", ""}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ValidOrEmptyCredentials(tt.args.domain, tt.args.user, tt.args.password); got != tt.want {
				t.Errorf("ValidOrEmptyCredentials() = '%v', want = '%v'", got, tt.want)
			}
		})
	}
}
