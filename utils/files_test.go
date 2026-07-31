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
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/siemens/GoScans/_test"
)

// TestMoveDirSafe verifies that moveDirSafe correctly moves files and directories, and errors on missing sources.
func TestMoveDirSafe(t *testing.T) {

	// Prepare and run test cases
	tests := []struct {
		name    string
		setup   func(t *testing.T) (src, dst string)
		wantErr bool
	}{
		{
			name: "move-file",
			setup: func(t *testing.T) (string, string) {
				t.Helper()
				dir := t.TempDir()
				src := filepath.Join(dir, "file.txt")
				if errWrite := os.WriteFile(src, []byte("content"), 0o644); errWrite != nil {
					t.Fatalf("moveDirSafe() setup error = '%v'", errWrite)
				}
				return src, filepath.Join(dir, "moved.txt")
			},
			wantErr: false,
		},
		{
			name: "move-directory",
			setup: func(t *testing.T) (string, string) {
				t.Helper()
				dir := t.TempDir()
				src := filepath.Join(dir, "srcdir")
				if errMkdir := os.MkdirAll(filepath.Join(src, "sub"), 0o755); errMkdir != nil {
					t.Fatalf("moveDirSafe() setup error = '%v'", errMkdir)
				}
				if errWrite := os.WriteFile(filepath.Join(src, "sub", "a.txt"), []byte("hi"), 0o644); errWrite != nil {
					t.Fatalf("moveDirSafe() setup error = '%v'", errWrite)
				}
				return src, filepath.Join(dir, "dstdir")
			},
			wantErr: false,
		},
		{
			name: "src-not-exist",
			setup: func(t *testing.T) (string, string) {
				t.Helper()
				dir := t.TempDir()
				return filepath.Join(dir, "nonexistent"), filepath.Join(dir, "dst")
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			src, dst := tt.setup(t)

			// Execute and check for expected error
			if errMoveDirSafe := MoveDirSafe(src, dst); (errMoveDirSafe != nil) != tt.wantErr {
				t.Errorf("MoveDirSafe() error = '%v', wantErr = '%v'", errMoveDirSafe, tt.wantErr)
			}

			// Verify source was removed after a successful move
			if !tt.wantErr {
				if _, errSrc := os.Stat(src); !os.IsNotExist(errSrc) {
					t.Errorf("MoveDirSafe() source still exists after successful move")
				}
			}
		})
	}
}

// TestStreamToFile verifies that StreamToFile writes an io.Reader stream to a file in the given output folder.
func TestStreamToFile(t *testing.T) {

	// Retrieve test logger
	testLogger := NewTestLogger()

	// Retrieve test settings
	testSettings := _test.GetSettings()

	// Prepare unit test data
	testContent := "teststream"

	// Prepare and run test cases
	type args struct {
		outputFolder string
		outputName   string
	}
	tests := []struct {
		name       string
		args       args
		testOutput string
		wantErr    bool
	}{
		{
			name:       "simple",
			args:       args{testSettings.PathTmpDir, "output.txt"},
			testOutput: testContent,
			wantErr:    false,
		},
		{
			name:       "complex",
			args:       args{testSettings.PathTmpDir, "!\"§$%&/(()=?`*'_:;><,.-#+´ß0987654321^°|~\\}][{³²µ'`).txt"},
			testOutput: testContent,
			wantErr:    false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			oName := SanitizeFilename(tt.args.outputName, "_")
			p := filepath.Join(testSettings.PathTmpDir, oName)
			source := bytes.NewReader([]byte(testContent))
			if errStreamToFile := StreamToFile(testLogger, source, tt.args.outputFolder, oName); (errStreamToFile != nil) != tt.wantErr {
				t.Errorf("StreamToFile() error = '%v', wantErr = '%v'", errStreamToFile, tt.wantErr)
				return
			}
			content, errContent := os.ReadFile(p)
			if errContent != nil {
				t.Errorf("StreamToFile() errRead: Could not read output file")
				return
			}
			if string(content) != testContent {
				t.Errorf("StreamToFile() = '%v', want = '%v'", string(content), tt.testOutput)
				return
			}
			_ = os.Remove(p)
		})
	}
}

// TestStreamToFile_FolderAutoCreate verifies that StreamToFile automatically creates the output folder when it does not exist.
func TestStreamToFile_FolderAutoCreate(t *testing.T) {

	// Retrieve test logger
	testLogger := NewTestLogger()

	// Prepare unit test data
	parent := t.TempDir()
	subDir := filepath.Join(parent, "sub")
	content := "auto-create-test-content"

	if _, errStat := os.Stat(subDir); !os.IsNotExist(errStat) {
		t.Fatalf("TestStreamToFile_FolderAutoCreate() setup: folder should not exist yet")
	}

	// Prepare and run test cases
	if errStreamToFile := StreamToFile(testLogger, bytes.NewReader([]byte(content)), subDir, "output.txt"); errStreamToFile != nil {
		t.Fatalf("StreamToFile() error = '%v', want = nil", errStreamToFile)
	}

	// Verify output file was written with expected content
	got, errGot := os.ReadFile(filepath.Join(subDir, "output.txt"))
	if errGot != nil {
		t.Fatalf("StreamToFile() could not read output file: '%v'", errGot)
	}
	if string(got) != content {
		t.Errorf("StreamToFile() = '%v', want = '%v'", string(got), content)
	}
}

// TestAccessFile verifies that accessFile correctly detects file access on real and nonexistent paths.
func TestAccessFile(t *testing.T) {

	// Retrieve test settings
	testSettings := _test.GetSettings()

	// Prepare test variables
	crawlFolder := filepath.Join(testSettings.PathDataDir, "filecrawler")

	// Prepare and run test cases
	tests := []struct {
		name     string
		path     string
		flag     int
		wantOpen bool
		wantErr  bool
	}{
		{
			name:     "readable-file",
			path:     filepath.Join(crawlFolder, "file_with_content.txt"),
			flag:     os.O_RDONLY,
			wantOpen: true,
			wantErr:  false,
		},
		{
			name:     "nonexistent-file",
			path:     "/does/not/exist/file.txt",
			flag:     os.O_RDONLY,
			wantOpen: false,
			wantErr:  true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotOpen, errGotOpen := AccessFile(tt.path, tt.flag)
			if (errGotOpen != nil) != tt.wantErr {
				t.Errorf("AccessFile() error = '%v', want = '%v'", errGotOpen, tt.wantErr)
				return
			}
			if gotOpen != tt.wantOpen {
				t.Errorf("AccessFile() opened = '%v', want = '%v'", gotOpen, tt.wantOpen)
			}
		})
	}
}
