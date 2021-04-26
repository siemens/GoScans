/*
* GoScans, a collection of network scan modules for infrastructure discovery and information gathering.
*
* Copyright (c) Siemens AG, 2016-2021.
*
* This work is licensed under the terms of the MIT license. For a copy, see the LICENSE file in the top-level
* directory or visit <https://opensource.org/licenses/MIT>.
*
 */

package discovery

import (
	"go-scans/_test"
	"golang.org/x/sys/windows/registry"
	"path/filepath"
	"testing"
)

func TestCheckWinpcap(t *testing.T) {

	// Prepare and run test cases
	tests := []struct {
		name    string
		wantErr bool
	}{
		{"valid", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := CheckWinpcap(); (err != nil) != tt.wantErr {
				t.Errorf("CheckWinpcap() error = '%v', wantErr = '%v'", err, tt.wantErr) // throws error if winpcap is not installed.
			}
		})
	}
}

func TestCheckNpcap(t *testing.T) {

	// Prepare and run test cases
	tests := []struct {
		name    string
		wantErr bool
	}{
		{"valid", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := CheckNpcap(); (err != nil) != tt.wantErr {
				t.Errorf("CheckNpcap() error = '%v', wantErr = '%v'", err, tt.wantErr)
			}
		})
	}
}

func TestImportRegistryFile(t *testing.T) {

	// Retrieve test settings
	testSettings, errSettings := _test.GetSettings()
	if errSettings != nil {
		t.Errorf("Invalid test settings: %s", errSettings)
		return
	}

	// Prepare test variables
	patchPath := filepath.Join(testSettings.PathNmapDir, "nmap_performance.reg")

	// Prepare and run test cases
	tests := []struct {
		name     string
		filePath string
		wantErr  bool
	}{
		{"invalid-privileges", patchPath, true}, // throws error without admin process privileges
		{"invalid-path", "notexisting", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := ImportRegistryFile(tt.filePath); (err != nil) != tt.wantErr {
				t.Errorf("ImportRegistryFile() error = '%v', wantErr = '%v'", err, tt.wantErr)
			}
		})
	}
}

func TestCheckNmapPerformancePatch(t *testing.T) {

	// Prepare and run test cases
	tests := []struct {
		name    string
		wantErr bool
	}{
		{"patch-SHOULD-be-applied", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := CheckNmapPerformancePatch(); (err != nil) != tt.wantErr {
				t.Errorf("CheckNmapPerformancePatch() error = '%v', wantErr = '%v'", err, tt.wantErr)
			}
		})
	}
}

// TestCheckRegistryIntValue also covers GetRegistryIntValue
func TestCheckRegistryIntValue(t *testing.T) {

	// Prepare and run test cases
	type args struct {
		root  registry.Key
		path  string
		key   string
		value int
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{"valid-value", args{registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control`, "LastBootSucceeded", 1}, false},
		{"invalid-path", args{registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\notexisting`, "key", 815}, true},
		{"invalid-key", args{registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control`, "notexisting", 815}, true},
		{"invalid-value", args{registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control`, "LastBootSucceeded", 815}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := CheckRegistryIntValue(tt.args.root, tt.args.path, tt.args.key, tt.args.value); (err != nil) != tt.wantErr {
				t.Errorf("CheckRegistryIntValue() error = '%v', wantErr = '%v'", err, tt.wantErr)
			}
		})
	}
}

func TestGetRegistryStringValue(t *testing.T) {

	// Prepare and run test cases
	type args struct {
		root registry.Key
		path string
		key  string
	}
	tests := []struct {
		name    string
		args    args
		wantVal string
		wantErr bool
	}{
		{"valid-value", args{registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\Print`, "ConfigModule"}, "PrintConfig.dll", false},
		{"invalid-path", args{registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\notexisting`, "key"}, "", true},
		{"invalid-key", args{registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control`, "notexisting"}, "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			str, err := GetRegistryStringValue(tt.args.root, tt.args.path, tt.args.key)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetRegistryStringValue() error = '%v', wantErr = '%v'", err, tt.wantErr)
			} else if str != tt.wantVal {
				t.Errorf("GetRegistryStringValue() = '%v', want = '%v'", str, tt.wantVal)
			}
		})
	}
}

func TestCheckNmapFirewall(t *testing.T) {

	// Prepare and run test cases
	type args struct {
		appPath string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{"allowed-app", args{`C:\WINDOWS\system32\lsass.exe`}, false},
		{"declined-app", args{`C:\notexisting.exe`}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := CheckNmapFirewall(tt.args.appPath); (err != nil) != tt.wantErr {
				t.Errorf("CheckNmapFirewall() error = '%v', wantErr = '%v'", err, tt.wantErr)
			}
		})
	}
}

func TestSetNmapFirewall(t *testing.T) {

	// Retrieve test settings
	testSettings, errSettings := _test.GetSettings()
	if errSettings != nil {
		t.Errorf("Invalid test settings: %s", errSettings)
		return
	}

	// Prepare and run test cases
	tests := []struct {
		name     string
		nmapPath string
		wantErr  bool
	}{
		{"invalid-privileges", testSettings.PathNmap, true}, // throws error without admin process privileges
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := SetNmapFirewall(tt.nmapPath); (err != nil) != tt.wantErr {
				t.Errorf("SetNmapFirewall() error = '%v', wantErr = '%v'", err, tt.wantErr)
			}
		})
	}
}
