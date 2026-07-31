/*
* GoScans, a collection of network scan modules for infrastructure discovery and information gathering.
*
* Copyright (c) Siemens AG, 2016-2026.
*
* This work is licensed under the terms of the MIT license. For a copy, see the LICENSE file in the top-level
* directory or visit <https://opensource.org/licenses/MIT>.
*
 */

package discovery

import (
	"path/filepath"
	"runtime"
	"testing"

	"github.com/noneymous/go-redistributable-checker"
	"github.com/siemens/GoScans/_test"
	"golang.org/x/sys/windows/registry"
)

// TestGetNmapRedistributableVersion_V14Binary_ReturnsVersion verifies the bundled Nmap runtime.
func TestGetNmapRedistributableVersion_V14Binary_ReturnsVersion(t *testing.T) {

	// Locate and inspect the stable Nmap fixture
	nmapPath := test_redistributablePath(t, "..", "_test", "tools", "nmap-7.92", "nmap.exe")
	version, errVersion := getNmapRedistributableVersion(nmapPath)
	if errVersion != nil {
		t.Fatalf("getNmapRedistributableVersion() error = '%v', want = '<nil>'", errVersion)
	}

	// Verify its runtime family
	if version != redistributable.VersionV14 {
		t.Errorf(
			"getNmapRedistributableVersion() version = '%v', want = '%v'",
			version,
			redistributable.VersionV14,
		)
	}
}

// TestGetNmapRedistributableVersion_InvalidExecutable_ReturnsError verifies invalid PE diagnostics.
func TestGetNmapRedistributableVersion_InvalidExecutable_ReturnsError(t *testing.T) {

	// Prepare and run stable invalid paths
	tests := []struct {
		name     string
		nmapPath string
	}{
		{
			name:     "missing-executable",
			nmapPath: test_redistributablePath(t, "notexisting.exe"),
		},
		{
			name:     "invalid-pe",
			nmapPath: test_redistributablePath(t, "TEST-PLAN.md"),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, errVersion := getNmapRedistributableVersion(test.nmapPath)
			if errVersion == nil {
				t.Errorf("getNmapRedistributableVersion() error = '%v', want non-nil", errVersion)
			}
		})
	}
}

// TestFindNmapRedistributableVersion_Imports_ReturnsExactVersion verifies runtime import mapping.
func TestFindNmapRedistributableVersion_Imports_ReturnsExactVersion(t *testing.T) {

	// Prepare and run supported imports
	tests := []struct {
		name        string
		imports     []string
		wantVersion redistributable.Version
	}{
		{
			name:        "visual-cpp-2013",
			imports:     []string{"malloc:MSVCR120.dll"},
			wantVersion: redistributable.Version2013,
		},
		{
			name:        "visual-cpp-v14",
			imports:     []string{"memcpy:VCRUNTIME140.dll"},
			wantVersion: redistributable.VersionV14,
		},
		{
			name:    "static-runtime",
			imports: []string{"CloseHandle:KERNEL32.dll"},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			version := findNmapRedistributableVersion(test.imports)
			if version != test.wantVersion {
				t.Errorf(
					"findNmapRedistributableVersion() version = '%v', want = '%v'",
					version,
					test.wantVersion,
				)
			}
		})
	}
}

// test_redistributablePath returns a stable path relative to the discovery package
func test_redistributablePath(t *testing.T, elements ...string) string {
	t.Helper()

	// Resolve the test file location independently from the process working directory
	_, testFile, _, okCaller := runtime.Caller(0)
	if !okCaller {
		t.Fatal("runtime.Caller() ok = 'false', want = 'true'")
	}

	// Return the requested path
	return filepath.Join(append([]string{filepath.Dir(testFile)}, elements...)...)
}

// TestCheckWinpcap verifies that CheckWinpcap returns an error when WinPcap is not installed.
func TestCheckWinpcap(t *testing.T) {

	// Prepare and run test cases
	tests := []struct {
		name    string
		wantErr bool
	}{
		{name: "valid", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if errCheckWinpcap := CheckWinpcap(); (errCheckWinpcap != nil) != tt.wantErr {
				t.Errorf("CheckWinpcap() error = '%v', wantErr = '%v'", errCheckWinpcap, tt.wantErr) // throws error if winpcap is not installed.
			}
		})
	}
}

// TestCheckNpcap verifies that CheckNpcap returns no error when Npcap is installed.
func TestCheckNpcap(t *testing.T) {

	// Prepare and run test cases
	tests := []struct {
		name    string
		wantErr bool
	}{
		{name: "valid", wantErr: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if errCheckNpcap := CheckNpcap(); (errCheckNpcap != nil) != tt.wantErr {
				t.Errorf("CheckNpcap() error = '%v', wantErr = '%v'", errCheckNpcap, tt.wantErr)
			}
		})
	}
}

// TestImportRegistryFile verifies that ImportRegistryFile returns an error without admin privileges or for invalid paths.
func TestImportRegistryFile(t *testing.T) {

	// Retrieve test settings
	testSettings := _test.GetSettings()
	if testSettings.PathNmap == "" {
		t.Skip("Integration test skipped: PathNmap not configured in _test/settings.go")
		return
	}

	// Prepare unit test data
	patchPath := filepath.Join(testSettings.PathNmapDir, "nmap_performance.reg")

	// Prepare and run test cases
	tests := []struct {
		name     string
		filePath string
		wantErr  bool
	}{
		{
			name:     "invalid-privileges",
			filePath: patchPath,
			wantErr:  true,
		}, // throws error without admin process privileges
		{
			name:     "invalid-path",
			filePath: "notexisting",
			wantErr:  true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if errImportRegistryFile := ImportRegistryFile(tt.filePath); (errImportRegistryFile != nil) != tt.wantErr {
				t.Errorf("ImportRegistryFile() error = '%v', wantErr = '%v'", errImportRegistryFile, tt.wantErr)
			}
		})
	}
}

// TestCheckNmapPerformancePatch verifies that CheckNmapPerformancePatch detects whether the performance patch is applied.
func TestCheckNmapPerformancePatch(t *testing.T) {

	// Prepare and run test cases
	tests := []struct {
		name    string
		wantErr bool
	}{
		{name: "patch-should-be-applied", wantErr: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if errCheckNmapPerformancePatch := CheckNmapPerformancePatch(); (errCheckNmapPerformancePatch != nil) != tt.wantErr {
				t.Errorf("CheckNmapPerformancePatch() error = '%v', wantErr = '%v'", errCheckNmapPerformancePatch, tt.wantErr)
			}
		})
	}
}

// TestCheckRegistryIntValue verifies that CheckRegistryIntValue validates registry integer values and covers GetRegistryIntValue.
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
		{
			name:    "valid-value",
			args:    args{registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control`, "LastBootSucceeded", 1},
			wantErr: false,
		},
		{
			name:    "invalid-path",
			args:    args{registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\notexisting`, "key", 815},
			wantErr: true,
		},
		{
			name:    "invalid-key",
			args:    args{registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control`, "notexisting", 815},
			wantErr: true,
		},
		{
			name:    "invalid-value",
			args:    args{registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control`, "LastBootSucceeded", 815},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if errCheckRegistryIntValue := CheckRegistryIntValue(tt.args.root, tt.args.path, tt.args.key, tt.args.value); (errCheckRegistryIntValue != nil) != tt.wantErr {
				t.Errorf("CheckRegistryIntValue() error = '%v', wantErr = '%v'", errCheckRegistryIntValue, tt.wantErr)
			}
		})
	}
}

// TestGetRegistryStringValue verifies that GetRegistryStringValue retrieves the correct string value from the registry.
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
		{
			name:    "valid-value",
			args:    args{registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\Print`, "ConfigModule"},
			wantVal: "PrintConfig.dll",
			wantErr: false,
		},
		{
			name:    "invalid-path",
			args:    args{registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\notexisting`, "key"},
			wantVal: "",
			wantErr: true,
		},
		{
			name:    "invalid-key",
			args:    args{registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control`, "notexisting"},
			wantVal: "",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			str, errStr := GetRegistryStringValue(tt.args.root, tt.args.path, tt.args.key)
			if (errStr != nil) != tt.wantErr {
				t.Errorf("GetRegistryStringValue() error = '%v', wantErr = '%v'", errStr, tt.wantErr)
			} else if str != tt.wantVal {
				t.Errorf("GetRegistryStringValue() = '%v', want = '%v'", str, tt.wantVal)
			}
		})
	}
}

// TestCheckNmapFirewall verifies that CheckNmapFirewall returns an error for an executable not in the Windows firewall list.
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
		{
			name:    "declined-app",
			args:    args{`C:\notexisting.exe`},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if errCheckNmapFirewall := CheckNmapFirewall(tt.args.appPath); (errCheckNmapFirewall != nil) != tt.wantErr {
				t.Errorf("CheckNmapFirewall() error = '%v', wantErr = '%v'", errCheckNmapFirewall, tt.wantErr)
			}
		})
	}
}

// TestSetNmapFirewall verifies that SetNmapFirewall returns an error without admin process privileges.
func TestSetNmapFirewall(t *testing.T) {

	// Retrieve test settings
	testSettings := _test.GetSettings()
	if testSettings.PathNmap == "" {
		t.Skip("Integration test skipped: PathNmap not configured in _test/settings.go")
		return
	}

	// Prepare and run test cases
	tests := []struct {
		name     string
		nmapPath string
		wantErr  bool
	}{
		{
			name:     "invalid-privileges",
			nmapPath: testSettings.PathNmap,
			wantErr:  true,
		}, // throws error without admin process privileges
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if errSetNmapFirewall := SetNmapFirewall(tt.nmapPath); (errSetNmapFirewall != nil) != tt.wantErr {
				t.Errorf("SetNmapFirewall() error = '%v', wantErr = '%v'", errSetNmapFirewall, tt.wantErr)
			}
		})
	}
}
