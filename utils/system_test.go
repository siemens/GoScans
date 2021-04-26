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

import (
	"go-scans/_test"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
)

func TestExecute(t *testing.T) {

	// Retrieve test settings
	testSettings, errSettings := _test.GetSettings()
	if errSettings != nil {
		t.Errorf("Invalid test settings: %s", errSettings)
		return
	}

	// Calculate Nmap dir
	errNmapDir := IsValidFolder(testSettings.PathNmapDir)
	if errNmapDir != nil {
		t.Errorf("Execute() - Could calculate Nmap directory")
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
		{"valid", args{"whoami", []string{}}, false},
		{"valid-args", args{"ipconfig", []string{"/all"}}, false},
		{"invalid-command", args{"notexisting", []string{}}, true},
		{"invalid-command-args", args{"notexisting", []string{"a", "b", "c"}}, true},
		{"invalid-privileges", args{"reg", []string{"import", patchFile}}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := Execute(tt.args.cmd, tt.args.args); (err != nil) != tt.wantErr {
				t.Errorf("Execute() error = '%v', wantErr = '%v'", err, tt.wantErr)
			}
		})
	}
}

func TestIsElevated(t *testing.T) {

	// Prepare and run test cases
	tests := []struct {
		name string
		want bool
	}{
		{"invalid", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsElevated(); got != tt.want {
				t.Errorf("IsElevated() = '%v', want = '%v'", got, tt.want)
			}
		})
	}
}

func TestIsValidFolder(t *testing.T) {

	// Prepare and run test cases
	tests := []struct {
		name    string
		path    string
		wantErr bool
	}{
		{"invalid-path", `C:\notexistingfolder`, true},
		{"invalid-folder", `C:\Windows\System32\cmd.exe`, true},
		{"valid-1", `C:\Windows\System32`, false},
		{"valid-2", `C:\Windows\System32\`, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := IsValidFolder(tt.path); (err != nil) != tt.wantErr {
				t.Errorf("IsValidFolder() error = '%v', wantErr = '%v'", err, tt.wantErr)
			}
		})
	}
}

func TestIsValidFile(t *testing.T) {

	// Prepare and run test cases
	tests := []struct {
		name    string
		path    string
		wantErr bool
	}{
		{"invalid-folder", `C:\notexistingfolder`, true},
		{"valid-file", `C:\Windows\System32\cmd.exe`, false},
		{"invalid-folder-1", `C:\Windows\System32`, true},
		{"invalid-folder-2", `C:\Windows\System32\`, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := IsValidFile(tt.path); (err != nil) != tt.wantErr {
				t.Errorf("IsValidFile() error = '%v', wantErr = '%v'", err, tt.wantErr)
			}
		})
	}
}

func TestIsValidExecutable(t *testing.T) {

	// Prepare and run test cases
	tests := []struct {
		name    string
		path    string
		args    []string
		wantErr bool
	}{
		{"executable-invalid-inexisting-folder", `C:\notexistingfolder`, []string{"-h"}, true},
		{"executable-invalid-existing-folder", `..`, []string{"-h"}, true},
		{"executable-valid", `C:\Windows\System32\cmd.exe`, []string{"-h"}, false},
		{"executable-invalid", `C:\Windows\System32`, []string{"-h"}, true},
		{"executable-from-env-path", `cmd`, []string{}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := IsValidExecutable(tt.path, tt.args...); (err != nil) != tt.wantErr {
				t.Errorf("IsValidExecutable() error = '%v', wantErr = '%v'", err, tt.wantErr)
			}
		})
	}
}

func TestSanitizeFilename(t *testing.T) {

	// Retrieve test settings
	testSettings, errSettings := _test.GetSettings()
	if errSettings != nil {
		t.Errorf("Invalid test settings: %s", errSettings)
		return
	}

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
		{"", args{"!\"§$%&/(()=?`*'_:;><,.-#+´ß0987654321^°|~\\}][{³²µ'`)", "_"}, "!_§$%&_(()=_`_'__;__,.-#+´ß0987654321^°_~_}][{³²µ'`)"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := SanitizeFilename(tt.args.raw, tt.args.placeholder); got != tt.want {
				t.Errorf("SanitizeFilename() = '%v', want = '%v'", got, tt.want)
			}
			p := filepath.Join(testSettings.PathTmpDir, tt.want+".txt")
			errWrite := ioutil.WriteFile(p, testContent, 666)
			if errWrite != nil {
				t.Errorf("SanitizeFilename() Writing test file failed!")
			}
			content, errRead := ioutil.ReadFile(p)
			if errRead != nil {
				t.Errorf("SanitizeFilename() Reading test file failed!")
			}
			if string(content) != string(testContent) {
				t.Errorf("SanitizeFilename() Output does not match input!")
			}
			_ = os.Remove(p)
		})
	}
}
