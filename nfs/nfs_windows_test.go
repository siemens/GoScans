/*
* GoScans, a collection of network scan modules for infrastructure discovery and information gathering.
*
* Copyright (c) Siemens AG, 2016-2026.
*
* This work is licensed under the terms of the MIT license. For a copy, see the LICENSE file in the top-level
* directory or visit <https://opensource.org/licenses/MIT>.
*
 */

package nfs

import (
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/siemens/GoScans/utils"
)

// testFileInfo is a minimal os.FileInfo implementation for delivering specific
// file-mode bit patterns to fileModeFromFattr. Using a real filesystem object
// for all mode combinations (block devices, sockets, etc.) is impractical in CI
// because those require privileged operations and are not available on all systems.
// os.FileInfo is a stdlib interface, not a GoScans production interface, so this
// helper does not violate the company mock policy.
type testFileInfo struct {
	mode os.FileMode
}

func (fi *testFileInfo) Name() string       { return "" }
func (fi *testFileInfo) Size() int64        { return 0 }
func (fi *testFileInfo) Mode() os.FileMode  { return fi.mode }
func (fi *testFileInfo) ModTime() time.Time { return time.Time{} }
func (fi *testFileInfo) IsDir() bool        { return fi.mode.IsDir() }
func (fi *testFileInfo) Sys() any           { return nil }

// TestFileModeFromFattr_ConvertsSpecialBits verifies that fileModeFromFattr correctly maps syscall mode bits to os.FileMode values.
func TestFileModeFromFattr_ConvertsSpecialBits(t *testing.T) {

	// Prepare and run test cases
	tests := []struct {
		name     string
		rawMode  os.FileMode
		wantBits os.FileMode
	}{
		{
			name:     "regular-file-no-special-bits",
			rawMode:  os.FileMode(syscall.S_IFREG | 0644),
			wantBits: 0644,
		},
		{
			name:     "directory-bit-set",
			rawMode:  os.FileMode(syscall.S_IFDIR | 0755),
			wantBits: os.ModeDir | 0755,
		},
		{
			name:     "symlink-bit-set",
			rawMode:  os.FileMode(syscall.S_IFLNK | 0777),
			wantBits: os.ModeSymlink | 0777,
		},
		{
			name:     "named-pipe-bit-set",
			rawMode:  os.FileMode(syscall.S_IFIFO | 0600),
			wantBits: os.ModeNamedPipe | 0600,
		},
		{
			name:     "socket-bit-set",
			rawMode:  os.FileMode(syscall.S_IFSOCK | 0600),
			wantBits: os.ModeSocket | 0600,
		},
		{
			name:     "block-device-bit-set",
			rawMode:  os.FileMode(syscall.S_IFBLK | 0660),
			wantBits: os.ModeDevice | 0660,
		},
		{
			name:     "char-device-bit-set",
			rawMode:  os.FileMode(syscall.S_IFCHR | 0660),
			wantBits: os.ModeDevice | os.ModeCharDevice | 0660,
		},
		{
			name:     "setuid-bit-set",
			rawMode:  os.FileMode(syscall.S_IFREG | syscall.S_ISUID | 0755),
			wantBits: os.ModeSetuid | 0755,
		},
		{
			name:     "setgid-bit-set",
			rawMode:  os.FileMode(syscall.S_IFREG | syscall.S_ISGID | 0755),
			wantBits: os.ModeSetgid | 0755,
		},
		{
			name:     "sticky-bit-set",
			rawMode:  os.FileMode(syscall.S_IFDIR | syscall.S_ISVTX | 0755),
			wantBits: os.ModeDir | os.ModeSticky | 0755,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			// Verify the file mode conversion produces the expected os.FileMode value
			fi := &testFileInfo{mode: tt.rawMode}
			got := fileModeFromFattr(fi)
			if got != tt.wantBits {
				t.Errorf("fileModeFromFattr() = '%v', want = '%v'", got, tt.wantBits)
			}
		})
	}
}

// TestScanner_GetExportsV4_ReturnsEmptyOnWindows verifies that getExportsV4 always returns an empty map on Windows (NFSv4 not supported).
func TestScanner_GetExportsV4_ReturnsEmptyOnWindows(t *testing.T) {

	// Prepare unit test data
	s := Scanner{
		logger: utils.NewTestLogger(),
		target: "192.0.2.1",
	}

	// Verify getExportsV4 returns empty map with no error
	got, errGot := s.getExportsV4()
	if errGot != nil {
		t.Errorf("getExportsV4() error = '%v', want = 'nil'", errGot)
		return
	}
	if len(got) != 0 {
		t.Errorf("getExportsV4() len = '%v', want = '0'", len(got))
	}
}
