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

// TestDiscoverHelperFiles_MultipleDepths verifies that files at arbitrary depths inside helpers/ are
// discovered and returned with forward-slash relative keys, while files outside helpers/ are excluded.
func TestDiscoverHelperFiles_MultipleDepths(t *testing.T) {

	// Prepare unit test data
	root := t.TempDir()

	helpers := []string{
		"helpers/a.txt",
		"helpers/wordlists/b.txt",
		"helpers/wordpress/plugins/c.txt",
	}
	for _, rel := range helpers {
		full := filepath.Join(root, filepath.FromSlash(rel))
		if errMkdir := os.MkdirAll(filepath.Dir(full), 0700); errMkdir != nil {
			t.Fatalf("discoverHelperFiles() could not create dir: '%v'", errMkdir)
		}
		if errWrite := os.WriteFile(full, []byte("content"), 0600); errWrite != nil {
			t.Fatalf("discoverHelperFiles() could not write file: '%v'", errWrite)
		}
	}

	// Place a file outside helpers/ — must NOT appear in the result
	outside := filepath.Join(root, "http", "cves", "foo.yaml")
	if errMkdir := os.MkdirAll(filepath.Dir(outside), 0700); errMkdir != nil {
		t.Fatalf("discoverHelperFiles() could not create outside dir: '%v'", errMkdir)
	}
	if errWrite := os.WriteFile(outside, []byte("template"), 0600); errWrite != nil {
		t.Fatalf("discoverHelperFiles() could not write outside file: '%v'", errWrite)
	}

	// Prepare and run test cases
	got, errGot := discoverHelperFiles(root)
	if errGot != nil {
		t.Fatalf("discoverHelperFiles() error = '%v', wantErr = 'false'", errGot)
	}
	if len(got) != len(helpers) {
		t.Errorf("discoverHelperFiles() len = '%d', want '%d'", len(got), len(helpers))
	}
	for _, rel := range helpers {
		if _, ok := got[rel]; !ok {
			t.Errorf("discoverHelperFiles() missing expected key '%s'", rel)
		}
	}
	if _, ok := got["http/cves/foo.yaml"]; ok {
		t.Errorf("discoverHelperFiles() unexpectedly contains 'http/cves/foo.yaml'")
	}
}

// TestDiscoverHelperFiles_MissingHelpersDir verifies that a missing helpers/ directory yields an empty
// non-nil map and no error.
func TestDiscoverHelperFiles_MissingHelpersDir(t *testing.T) {

	// Prepare unit test data
	root := t.TempDir()

	// Prepare and run test cases
	got, errGot := discoverHelperFiles(root)
	if errGot != nil {
		t.Fatalf("discoverHelperFiles() error = '%v', wantErr = 'false'", errGot)
	}
	if got == nil {
		t.Error("discoverHelperFiles() returned nil map, want empty non-nil map")
	}
	if len(got) != 0 {
		t.Errorf("discoverHelperFiles() len = '%d', want '0'", len(got))
	}
}

// TestDiscoverHelperFiles_FilesOutsideHelpersNotIncluded verifies that a file outside helpers/ is absent
// from the returned map even when helpers/ contains files.
func TestDiscoverHelperFiles_FilesOutsideHelpersNotIncluded(t *testing.T) {

	// Prepare unit test data
	root := t.TempDir()

	helperFile := filepath.Join(root, "helpers", "a.txt")
	if errMkdir := os.MkdirAll(filepath.Dir(helperFile), 0700); errMkdir != nil {
		t.Fatalf("discoverHelperFiles() could not create helper dir: '%v'", errMkdir)
	}
	if errWrite := os.WriteFile(helperFile, []byte("content"), 0600); errWrite != nil {
		t.Fatalf("discoverHelperFiles() could not write helper file: '%v'", errWrite)
	}

	outsideFile := filepath.Join(root, "http", "cves", "foo.yaml")
	if errMkdir := os.MkdirAll(filepath.Dir(outsideFile), 0700); errMkdir != nil {
		t.Fatalf("discoverHelperFiles() could not create outside dir: '%v'", errMkdir)
	}
	if errWrite := os.WriteFile(outsideFile, []byte("template"), 0600); errWrite != nil {
		t.Fatalf("discoverHelperFiles() could not write outside file: '%v'", errWrite)
	}

	// Prepare and run test cases
	got, errGot := discoverHelperFiles(root)
	if errGot != nil {
		t.Fatalf("discoverHelperFiles() error = '%v', wantErr = 'false'", errGot)
	}
	if _, ok := got["http/cves/foo.yaml"]; ok {
		t.Errorf("discoverHelperFiles() unexpectedly contains 'http/cves/foo.yaml'")
	}
	if _, ok := got["helpers/a.txt"]; !ok {
		t.Errorf("discoverHelperFiles() missing expected key 'helpers/a.txt'")
	}
}

// TestDiscoverHelperFiles_EndToEnd feeds discoverHelperFiles output into makeHelperFileLoader and verifies
// that a discovered helper loads successfully while a file outside helpers/ is rejected.
func TestDiscoverHelperFiles_EndToEnd(t *testing.T) {

	// Prepare unit test data
	root, helperRelPath, _ := test_helperLoaderFixture(t)

	outsideRelPath := "http/cves/foo.yaml"
	outsideFull := filepath.Join(root, filepath.FromSlash(outsideRelPath))
	if errMkdir := os.MkdirAll(filepath.Dir(outsideFull), 0700); errMkdir != nil {
		t.Fatalf("discoverHelperFiles() could not create outside dir: '%v'", errMkdir)
	}
	if errWrite := os.WriteFile(outsideFull, []byte("template"), 0600); errWrite != nil {
		t.Fatalf("discoverHelperFiles() could not write outside file: '%v'", errWrite)
	}

	// Prepare and run test cases
	allowlist, errAllowlist := discoverHelperFiles(root)
	if errAllowlist != nil {
		t.Fatalf("discoverHelperFiles() error = '%v', wantErr = 'false'", errAllowlist)
	}

	loader := makeHelperFileLoader(root, allowlist)

	// In-tree helper must load successfully
	rc, errRc := loader(helperRelPath, "", nil)
	if errRc != nil {
		t.Fatalf("makeHelperFileLoader() error = '%v', wantErr = 'false'", errRc)
	}
	_ = rc.Close()

	// File outside helpers/ must be rejected
	rc2, errRc2 := loader(outsideRelPath, "", nil)
	if errRc2 == nil {
		_ = rc2.Close()
		t.Errorf("makeHelperFileLoader() error = 'nil', wantErr = 'true' for path outside helpers/")
	}
}

// TestDiscoverHelperFiles_SymlinkOutsideRoot verifies that a symlink whose resolved target lies outside
// pathTemplates is not included in the returned map.
func TestDiscoverHelperFiles_SymlinkOutsideRoot(t *testing.T) {

	// Skip on platforms where creating symlinks requires elevated privileges
	if runtime.GOOS == "windows" {
		t.Skip("Integration test skipped: symlink creation requires elevated privileges on Windows")
		return
	}

	// Prepare unit test data
	root := t.TempDir()
	helperDir := filepath.Join(root, "helpers", "wordlists")
	if errMkdir := os.MkdirAll(helperDir, 0700); errMkdir != nil {
		t.Fatalf("discoverHelperFiles() could not create dir: '%v'", errMkdir)
	}

	symlinkPath := filepath.Join(helperDir, "evil.txt")
	if errSym := os.Symlink("/etc/passwd", symlinkPath); errSym != nil {
		t.Skipf("Integration test skipped: could not create symlink: %v", errSym)
		return
	}

	// Prepare and run test cases
	got, errGot := discoverHelperFiles(root)
	if errGot != nil {
		t.Fatalf("discoverHelperFiles() error = '%v', wantErr = 'false'", errGot)
	}
	if _, ok := got["helpers/wordlists/evil.txt"]; ok {
		t.Errorf("discoverHelperFiles() unexpectedly contains symlink that escapes root")
	}
}

// TestDiscoverHelperFiles_SymlinkInsideRoot verifies that a symlink whose resolved target lies inside
// pathTemplates is included in the returned map.
func TestDiscoverHelperFiles_SymlinkInsideRoot(t *testing.T) {

	// Skip on platforms where creating symlinks requires elevated privileges
	if runtime.GOOS == "windows" {
		t.Skip("Integration test skipped: symlink creation requires elevated privileges on Windows")
		return
	}

	// Prepare unit test data
	root := t.TempDir()
	helperDir := filepath.Join(root, "helpers", "wordlists")
	if errMkdir := os.MkdirAll(helperDir, 0700); errMkdir != nil {
		t.Fatalf("discoverHelperFiles() could not create dir: '%v'", errMkdir)
	}

	realFile := filepath.Join(helperDir, "real.txt")
	if errWrite := os.WriteFile(realFile, []byte("content"), 0600); errWrite != nil {
		t.Fatalf("discoverHelperFiles() could not write real file: '%v'", errWrite)
	}

	symlinkPath := filepath.Join(helperDir, "link.txt")
	if errSym := os.Symlink(realFile, symlinkPath); errSym != nil {
		t.Skipf("Integration test skipped: could not create symlink: %v", errSym)
		return
	}

	// Prepare and run test cases
	got, errGot := discoverHelperFiles(root)
	if errGot != nil {
		t.Fatalf("discoverHelperFiles() error = '%v', wantErr = 'false'", errGot)
	}
	if _, ok := got["helpers/wordlists/real.txt"]; !ok {
		t.Errorf("discoverHelperFiles() missing expected key 'helpers/wordlists/real.txt'")
	}
	if _, ok := got["helpers/wordlists/link.txt"]; !ok {
		t.Errorf("discoverHelperFiles() missing expected key 'helpers/wordlists/link.txt'")
	}
}
