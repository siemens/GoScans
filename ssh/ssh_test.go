/*
* GoScans, a collection of network scan modules for infrastructure discovery and information gathering.
*
* Copyright (c) Siemens AG, 2016-2021.
*
* This work is licensed under the terms of the MIT license. For a copy, see the LICENSE file in the top-level
* directory or visit <https://opensource.org/licenses/MIT>.
*
 */

package ssh

import (
	"fmt"
	"go-scans/utils"
	"testing"
)

func TestInfoFromErr(t *testing.T) {

	// Prepare and run test cases
	type args struct {
		errMsg error
	}
	tests := []struct {
		name        string
		args        args
		expecResult []string
		expecErrMsg string
		wantErr     bool
	}{
		{"success", args{fmt.Errorf("ssh: handshake failed: ssh: no common algorithm for key exchange; client offered: [], server offered: [diffie-hellman-group-exchange-sha256 diffie-hellman-group14-sha1 diffie-hellman-group-exchange-sha1]")}, []string{"diffie-hellman-group-exchange-sha256", "diffie-hellman-group14-sha1", "diffie-hellman-group-exchange-sha1"}, "", false},
		{"nil-err-msg", args{nil}, []string{}, "error message was nil", true},
		{"no-such-host", args{fmt.Errorf("dial tcp: lookup nosuchhost.domain.tld: no such host")}, []string{}, "no such host", true},
		{"new-err-msg", args{fmt.Errorf("the error message changed internally in the crypto package")}, []string{}, "could not excerpt parameter from error message: the error message changed internally in the crypto package", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := infoFromErr(tt.args.errMsg)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewScanner() error = '%v', wantErr = '%v'", err, tt.wantErr)
				return
			}

			// Check if the right security parameters were returned
			if err == nil && !utils.Equals(got, tt.expecResult) {
				t.Errorf("infoFromErr = '%v', want = '%v'", got, tt.expecResult)
			}

			// Check if the right errormessage was returned
			if err != nil && err.Error() != tt.expecErrMsg {
				t.Errorf("infoFromErr = '%v', want = '%v'", err, tt.expecErrMsg)
			}
		})
	}
}
