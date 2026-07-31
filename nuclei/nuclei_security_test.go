/*
* GoScans, a collection of network scan modules for infrastructure discovery and information gathering.
*
* Copyright (c) Siemens AG, 2016-2026.
*
* This work is licensed under the terms of the MIT license. For a copy, see the LICENSE file in the top-level
* directory or visit <https://opensource.org/licenses/MIT>.
*
 */

package nuclei

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// TestMakeHelperFileLoader_AllowedPath verifies that an allowlisted path is served correctly.
func TestMakeHelperFileLoader_AllowedPath(t *testing.T) {

	// Prepare unit test data
	root, helperRelPath, _ := test_helperLoaderFixture(t)

	// Prepare and run test cases
	loader := makeHelperFileLoader(root, map[string]struct{}{helperRelPath: {}})
	rc, errRc := loader(helperRelPath, "", nil)
	if errRc != nil {
		t.Fatalf("makeHelperFileLoader() error = '%v', wantErr = 'false'", errRc)
	}
	_ = rc.Close()
}

// TestMakeHelperFileLoader_DeniedPaths verifies that paths not present in the allowlist are rejected.
func TestMakeHelperFileLoader_DeniedPaths(t *testing.T) {

	// Prepare unit test data
	root, helperRelPath, _ := test_helperLoaderFixture(t)
	allowlist := map[string]struct{}{helperRelPath: {}}

	// Prepare and run test cases
	tests := []struct {
		name       string
		helperFile string
	}{
		{
			name:       "not-in-allowlist",
			helperFile: "helpers/wordlists/not-present.txt",
		},
		{
			name:       "empty-path",
			helperFile: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rc, errRc := makeHelperFileLoader(root, allowlist)(tt.helperFile, "", nil)
			if errRc == nil {
				_ = rc.Close()
				t.Errorf("makeHelperFileLoader() error = 'nil', wantErr = 'true'")
			}
		})
	}
}

// TestMakeHelperFileLoader_RelativeEscape verifies that directory-traversal sequences are rejected.
func TestMakeHelperFileLoader_RelativeEscape(t *testing.T) {

	// Prepare unit test data
	root := t.TempDir()

	// Prepare and run test cases
	tests := []struct {
		name       string
		helperFile string
	}{
		{
			name:       "dotdot-escape",
			helperFile: "../other-file.txt",
		},
		{
			name:       "dotdot-deep-escape",
			helperFile: "helpers/../../etc/passwd",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// The path would need to be in the allowlist to reach the containment check;
			// absolute and traversal rejections happen before the allowlist lookup.
			rc, errRc := makeHelperFileLoader(root, map[string]struct{}{})(tt.helperFile, "", nil)
			if errRc == nil {
				_ = rc.Close()
				t.Errorf("makeHelperFileLoader() error = 'nil', wantErr = 'true'")
			}
		})
	}
}

// TestMakeHelperFileLoader_AbsolutePathRejected verifies that absolute paths are rejected.
func TestMakeHelperFileLoader_AbsolutePathRejected(t *testing.T) {

	// Prepare unit test data
	root := t.TempDir()

	// Prepare and run test cases
	var absPath string
	if runtime.GOOS == "windows" {
		absPath = `C:\Windows\System32\drivers\etc\hosts`
	} else {
		absPath = "/etc/passwd"
	}
	rc, errRc := makeHelperFileLoader(root, map[string]struct{}{})(absPath, "", nil)
	if errRc == nil {
		_ = rc.Close()
		t.Errorf("makeHelperFileLoader() error = 'nil', wantErr = 'true'")
	}
}

// TestMakeHelperFileLoader_SymlinkEscape verifies that symlinks resolving outside the templates root are rejected.
func TestMakeHelperFileLoader_SymlinkEscape(t *testing.T) {

	// Skip on platforms where creating symlinks requires elevated privileges
	if runtime.GOOS == "windows" {
		t.Skip("Integration test skipped: symlink creation requires elevated privileges on Windows")
		return
	}

	// Prepare unit test data
	root := t.TempDir()
	helperRelPath := "helpers/wordlists/evil.txt"
	if errMkdir := os.MkdirAll(filepath.Join(root, "helpers", "wordlists"), 0700); errMkdir != nil {
		t.Fatalf("makeHelperFileLoader() could not create helper dir: '%v'", errMkdir)
	}

	// Create a symlink pointing outside the templates root
	symlinkPath := filepath.Join(root, helperRelPath)
	if errSym := os.Symlink("/etc/passwd", symlinkPath); errSym != nil {
		t.Skipf("Integration test skipped: could not create symlink: %v", errSym)
		return
	}

	// Prepare and run test cases
	allowlist := map[string]struct{}{helperRelPath: {}}
	rc, errRc := makeHelperFileLoader(root, allowlist)(helperRelPath, "", nil)
	if errRc == nil {
		_ = rc.Close()
		t.Errorf("makeHelperFileLoader() error = 'nil', wantErr = 'true'")
	}
}

// test_helperLoaderFixture creates a temporary templates directory with one helper file and returns
// the root path, the relative path of the helper file, and its content.
func test_helperLoaderFixture(t *testing.T) (root, relPath string, content []byte) {
	t.Helper()

	// Prepare unit test data
	root = t.TempDir()
	relPath = "helpers/wordlists/numbers.txt"
	content = []byte("1\n2\n3\n")

	helperDir := filepath.Join(root, "helpers", "wordlists")
	if errMkdir := os.MkdirAll(helperDir, 0700); errMkdir != nil {
		t.Fatalf("test_helperLoaderFixture() could not create helper dir: '%v'", errMkdir)
	}

	if errWrite := os.WriteFile(filepath.Join(helperDir, "numbers.txt"), content, 0600); errWrite != nil {
		t.Fatalf("test_helperLoaderFixture() could not write helper file: '%v'", errWrite)
	}

	// Return nil as everything went fine
	return root, relPath, content
}
