/*
* GoScans, a collection of network scan modules for infrastructure discovery and information gathering.
*
* Copyright (c) Siemens AG, 2016-2026.
*
* This work is licensed under the terms of the MIT license. For a copy, see the LICENSE file in the top-level
* directory or visit <https://opensource.org/licenses/MIT>.
*
 */

package utils

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/siemens/GoScans/_test"
)

// TestExecute verifies that Execute runs valid system commands and returns an error for invalid or unprivileged ones.
func TestExecute(t *testing.T) {

	// Retrieve test settings
	testSettings := _test.GetSettings()
	if testSettings.PathNmap == "" {
		t.Skip("Integration test skipped: PathNmap not configured in _test/settings.go")
		return
	}

	// Calculate Nmap dir
	errNmapDir := IsValidFolder(testSettings.PathNmapDir)
	if errNmapDir != nil {
		t.Errorf("Execute() Nmap directory invalid: '%v'", errNmapDir)
		return
	}

	// Prepare test variables
	patchFile := filepath.Join(testSettings.PathNmapDir, "nmap_performance.reg")

	// Prepare and run test cases
	type args struct {
		cmd  string
		args []string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name:    "valid",
			args:    args{"whoami", []string{}},
			wantErr: false,
		},
		{
			name:    "valid-args",
			args:    args{"ipconfig", []string{"/all"}},
			wantErr: false,
		},
		{
			name:    "invalid-command",
			args:    args{"notexisting", []string{}},
			wantErr: true,
		},
		{
			name:    "invalid-command-args",
			args:    args{"notexisting", []string{"a", "b", "c"}},
			wantErr: true,
		},
		{
			name:    "invalid-privileges",
			args:    args{"reg", []string{"import", patchFile}},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if errExecute := Execute(tt.args.cmd, tt.args.args); (errExecute != nil) != tt.wantErr {
				t.Errorf("Execute() error = '%v', wantErr = '%v'", errExecute, tt.wantErr)
			}
		})
	}
}

// TestIsElevated verifies that IsElevated returns false when not running with elevated privileges.
func TestIsElevated(t *testing.T) {

	// Prepare and run test cases
	tests := []struct {
		name string
		want bool
	}{
		{name: "invalid", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsElevated(); got != tt.want {
				t.Errorf("IsElevated() = '%v', want = '%v'", got, tt.want)
			}
		})
	}
}

// TestSanitizeFilename verifies that SanitizeFilename replaces illegal characters with the given placeholder.
func TestSanitizeFilename(t *testing.T) {

	// Prepare test variables
	testContent := []byte("test")

	// Prepare and run test cases
	type args struct {
		raw         string
		placeholder string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "sanitize-special-chars",
			args: args{
				raw:         "!\"§$%&/(()=?`*'_:;><,.-#+´ß0987654321^°|~\\}][{³²µ'`)",
				placeholder: "_",
			},
			want: "!_§$%&_(()=_`_'__;__,.-#+´ß0987654321^°_~_}][{³²µ'`)",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SanitizeFilename(tt.args.raw, tt.args.placeholder)
			if got != tt.want {
				t.Errorf("SanitizeFilename() = '%v', want = '%v'", got, tt.want)
			}

			// Verify the sanitized name can be used to write and read a file
			dir := t.TempDir()
			p := filepath.Join(dir, got+".txt")
			errWrite := os.WriteFile(p, testContent, 0666)
			if errWrite != nil {
				t.Errorf("SanitizeFilename() WriteFile error = '%v'", errWrite)
				return
			}
			content, errContent := os.ReadFile(p)
			if errContent != nil {
				t.Errorf("SanitizeFilename() ReadFile error = '%v'", errContent)
				return
			}
			if string(content) != string(testContent) {
				t.Errorf("SanitizeFilename() file content = '%v', want = '%v'", string(content), string(testContent))
			}
		})
	}
}
