/*
* GoScans, a collection of network scan modules for infrastructure discovery and information gathering.
*
* Copyright (c) Siemens AG, 2016-2026.
*
* This work is licensed under the terms of the MIT license. For a copy, see the LICENSE file in the top-level
* directory or visit <https://opensource.org/licenses/MIT>.
*
 */

package ad

import (
	"os"
	"testing"
	"time"

	"github.com/siemens/GoScans/_test"
)

// TestMain initializes the test environment and runs all tests in the ad package.
func TestMain(m *testing.M) {

	// Retrieve test settings
	_test.GetSettings()

	// Prepare test directory
	tmpDir, errTmpDir := os.MkdirTemp(".", "goscans-ad-test-*")
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

	// Exit with the test result code
	os.Exit(code)
}

// TestFqdnToDn verifies that fqdnToDn converts a dot-separated FQDN to an LDAP distinguished name.
func TestFqdnToDn(t *testing.T) {

	// Prepare and run test cases
	tests := []struct {
		name string
		fqdn string
		want string
	}{
		{
			name: "single-label",
			fqdn: "tld",
			want: "dc=tld",
		},
		{
			name: "two-level",
			fqdn: "domain.tld",
			want: "dc=domain,dc=tld",
		},
		{
			name: "three-level",
			fqdn: "sub.domain.tld",
			want: "dc=sub,dc=domain,dc=tld",
		},
		{
			name: "empty",
			fqdn: "",
			want: "dc=",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := fqdnToDn(tt.fqdn); got != tt.want {
				t.Errorf("fqdnToDn() = '%v', want = '%v'", got, tt.want)
			}
		})
	}
}

// TestParseDn verifies that parseDn correctly extracts the LDAP address, search CN, and base DN from a distinguished
// name.
func TestParseDn(t *testing.T) {

	// Prepare and run test cases
	tests := []struct {
		name       string
		dn         string
		wantAddr   string
		wantCn     string
		wantBaseDn string
	}{
		{
			name:       "three-dc-components",
			dn:         "cn=host123,dc=sub,dc=domain,dc=tld",
			wantAddr:   "sub.domain.tld",
			wantCn:     "host123",
			wantBaseDn: "dc=sub,dc=domain,dc=tld",
		},
		{
			name:       "two-dc-components",
			dn:         "cn=user,dc=domain,dc=tld",
			wantAddr:   "domain.tld",
			wantCn:     "user",
			wantBaseDn: "dc=domain,dc=tld",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotAddr, gotCn, gotBaseDn := parseDn(tt.dn)
			if gotAddr != tt.wantAddr {
				t.Errorf("parseDn() ldapAddress = '%v', want = '%v'", gotAddr, tt.wantAddr)
			}
			if gotCn != tt.wantCn {
				t.Errorf("parseDn() searchCn = '%v', want = '%v'", gotCn, tt.wantCn)
			}
			if gotBaseDn != tt.wantBaseDn {
				t.Errorf("parseDn() baseDn = '%v', want = '%v'", gotBaseDn, tt.wantBaseDn)
			}
		})
	}
}

// TestDnSplit verifies that dnSplit splits a distinguished name on unescaped commas, returning the correct segments.
func TestDnSplit(t *testing.T) {

	// Prepare and run test cases
	tests := []struct {
		name string
		dn   string
		want []string
	}{
		{
			name: "standard-dn",
			dn:   "cn=host,dc=sub,dc=domain,dc=tld",
			want: []string{"cn=host", "dc=sub", "dc=domain", "dc=tld"},
		},
		{
			name: "escaped-comma",
			dn:   `cn=host\,with\,comma,dc=tld`,
			want: []string{"cn=host,with,comma", "dc=tld"},
		},
		{
			name: "single-element",
			dn:   "cn=only",
			want: []string{"cn=only"},
		},
		{
			name: "empty",
			dn:   "",
			want: []string{""},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := dnSplit(tt.dn)
			if len(got) != len(tt.want) {
				t.Errorf("dnSplit() len = '%v', want = '%v'", len(got), len(tt.want))
				return
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("dnSplit()[%d] = '%v', want = '%v'", i, got[i], tt.want[i])
				}
			}
		})
	}
}

// TestInteger8ToTime verifies that Integer8ToTime converts a Windows FILETIME integer to the correct UTC time.
func TestInteger8ToTime(t *testing.T) {

	// Prepare and run test cases
	tests := []struct {
		name string
		val  int64
		want time.Time
	}{
		{
			name: "zero-value",
			val:  0,
			want: time.Date(1601, 1, 1, 0, 0, 0, 0, time.UTC),
		},
		{
			name: "unix-epoch",
			val:  116444736000000000,
			want: time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Integer8ToTime(tt.val); !got.Equal(tt.want) {
				t.Errorf("Integer8ToTime() = '%v', want = '%v'", got, tt.want)
			}
		})
	}
}

// TestGeneralizedTimeToTime verifies that GeneralizedTimeToTime parses valid generalized-time strings and returns an
// error for invalid ones.
func TestGeneralizedTimeToTime(t *testing.T) {

	// Prepare and run test cases
	tests := []struct {
		name     string
		val      string
		wantErr  bool
		wantYear int
	}{
		{
			name:     "valid-utc-offset",
			val:      "20190221143249+0000",
			wantErr:  false,
			wantYear: 2019,
		},
		{
			name:    "invalid-format",
			val:     "notadate",
			wantErr: true,
		},
		{
			name:    "empty",
			val:     "",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, errGot := GeneralizedTimeToTime(tt.val)
			if (errGot != nil) != tt.wantErr {
				t.Errorf("GeneralizedTimeToTime() error = '%v', wantErr = '%v'", errGot, tt.wantErr)
				return
			}
			if !tt.wantErr && got.Year() != tt.wantYear {
				t.Errorf("GeneralizedTimeToTime() year = '%v', want = '%v'", got.Year(), tt.wantYear)
			}
		})
	}
}
