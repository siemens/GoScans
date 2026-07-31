/*
* GoScans, a collection of network scan modules for infrastructure discovery and information gathering.
*
* Copyright (c) Siemens AG, 2016-2026.
*
* This work is licensed under the terms of the MIT license. For a copy, see the LICENSE file in the top-level
* directory or visit <https://opensource.org/licenses/MIT>.
*
 */

package smb

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/siemens/GoScans/_test"
	"github.com/siemens/GoScans/utils"
)

// TestMain initializes the test environment and runs all tests in the smb package.
func TestMain(m *testing.M) {

	// Retrieve test settings
	_test.GetSettings()

	// Prepare test directory
	tmpDir, errTmpDir := os.MkdirTemp(".", "goscans-smb-test-*")
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

// TestNewScanner verifies that NewScanner returns a valid scanner for valid inputs and errors for invalid ones.
func TestNewScanner(t *testing.T) {

	// Prepare test variables
	testLogger := utils.NewTestLogger()

	// Prepare and run test cases
	tests := []struct {
		name        string
		target      string
		smbDomain   string
		smbUser     string
		smbPassword string
		wantErr     bool
	}{
		{
			name:    "valid-ip",
			target:  "192.0.2.1",
			wantErr: false,
		},
		{
			name:    "valid-hostname",
			target:  "hostname.domain.tld",
			wantErr: false,
		},
		{
			name:    "invalid-empty",
			target:  "",
			wantErr: true,
		},
		{
			name:    "invalid-cidr",
			target:  "192.0.2.0/24",
			wantErr: true,
		},
		{
			name:    "invalid-with-port",
			target:  "192.0.2.1:445",
			wantErr: true,
		},
		{
			name:        "invalid-credentials-domain-only",
			target:      "192.0.2.1",
			smbDomain:   "DOMAIN",
			smbUser:     "",
			smbPassword: "",
			wantErr:     true,
		},
		{
			name:        "invalid-credentials-user-only",
			target:      "192.0.2.1",
			smbDomain:   "",
			smbUser:     "user",
			smbPassword: "",
			wantErr:     true,
		},
		{
			name:        "invalid-credentials-password-only",
			target:      "192.0.2.1",
			smbDomain:   "",
			smbUser:     "",
			smbPassword: "pass",
			wantErr:     true,
		},
		{
			name:        "valid-with-credentials",
			target:      "192.0.2.1",
			smbDomain:   "DOMAIN",
			smbUser:     "user",
			smbPassword: "pass",
			wantErr:     false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scanner, errScanner := NewScanner(
				testLogger,
				tt.target,
				-1,
				1,
				nil,
				nil,
				nil,
				nil,
				time.Time{},
				0,
				false,
				tt.smbDomain,
				tt.smbUser,
				tt.smbPassword,
			)
			if (errScanner != nil) != tt.wantErr {
				t.Errorf("NewScanner() error = '%v', wantErr = '%v'", errScanner, tt.wantErr)
				return
			}
			if !tt.wantErr && scanner == nil {
				t.Errorf("NewScanner() = '%v', want = 'non-nil scanner'", scanner)
			}
		})
	}
}

// TestScanner_Label_MatchesPackageConstant verifies that the scanner label matches the package-level Label constant.
func TestScanner_Label_MatchesPackageConstant(t *testing.T) {

	// Prepare test variables
	testLogger := utils.NewTestLogger()

	// Create scanner
	scanner, errScanner := NewScanner(testLogger, "192.0.2.1", -1, 1, nil, nil, nil, nil, time.Time{}, 0, false, "", "", "")
	if errScanner != nil {
		t.Errorf("NewScanner() error = '%v', want = 'nil'", errScanner)
		return
	}

	// Verify label matches constant
	if scanner.Label != Label {
		t.Errorf("Scanner.Label = '%v', want = '%v'", scanner.Label, Label)
	}
}

// TestScanner_SetContext_SetsOnFirstCallOnly verifies that SetContext only accepts the first context and ignores subsequent ones.
func TestScanner_SetContext_SetsOnFirstCallOnly(t *testing.T) {

	// Prepare test variables
	testLogger := utils.NewTestLogger()

	// Create scanner
	scanner, errScanner := NewScanner(testLogger, "192.0.2.1", -1, 1, nil, nil, nil, nil, time.Time{}, 0, false, "", "", "")
	if errScanner != nil {
		t.Errorf("NewScanner() error = '%v', want = 'nil'", errScanner)
		return
	}

	// Set initial context
	ctx1, cancel1 := context.WithCancel(context.Background())
	defer cancel1()
	scanner.SetContext(ctx1)

	// Verify context was set
	if scanner.contextInner != ctx1 {
		t.Errorf("SetContext() contextInner = '%v', want = '%v'", scanner.contextInner, ctx1)
	}

	// Set second context, which should be ignored
	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()
	scanner.SetContext(ctx2)

	// Verify context was not replaced
	if scanner.contextInner != ctx1 {
		t.Errorf("SetContext() contextInner = '%v', want = '%v' (should not have changed)", scanner.contextInner, ctx1)
	}
}
