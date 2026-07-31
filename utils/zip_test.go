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
	"archive/zip"
	"io"
	"os"
	"path/filepath"
	"testing"
)

// TestUnzip verifies that unzip correctly extracts valid archives, rejects non-existent or malformed ZIP files,
// blocks path-traversal entries (zip slip prevention), and creates explicit directory entries from the archive.
func TestUnzip(t *testing.T) {

	// Prepare and run test cases
	tests := []struct {
		name    string
		setup   func(t *testing.T) (zipPath, destDir string)
		wantErr bool
	}{
		{
			name: "valid-zip-extracts-correctly",
			setup: func(t *testing.T) (string, string) {
				t.Helper()
				dir := t.TempDir()
				zipPath := filepath.Join(dir, "archive.zip")
				test_makeZip(t, zipPath, map[string]string{
					"hello.txt": "hello world",
					"sub/b.txt": "nested file",
				})
				return zipPath, filepath.Join(dir, "out")
			},
			wantErr: false,
		},
		{
			name: "non-existent-zip-returns-error",
			setup: func(t *testing.T) (string, string) {
				t.Helper()
				dir := t.TempDir()
				return filepath.Join(dir, "missing.zip"), filepath.Join(dir, "out")
			},
			wantErr: true,
		},
		{
			name: "malformed-zip-returns-error",
			setup: func(t *testing.T) (string, string) {
				t.Helper()
				dir := t.TempDir()
				zipPath := filepath.Join(dir, "bad.zip")
				if errWrite := os.WriteFile(zipPath, []byte("this is not a zip"), 0600); errWrite != nil {
					t.Fatalf("unzip() setup error = '%v'", errWrite)
				}
				return zipPath, filepath.Join(dir, "out")
			},
			wantErr: true,
		},
		{
			name: "zip-slip-prevention",
			setup: func(t *testing.T) (string, string) {
				t.Helper()
				dir := t.TempDir()
				zipPath := filepath.Join(dir, "slip.zip")
				test_makeZipWithTraversal(t, zipPath, "../evil.txt", "evil content")
				return zipPath, filepath.Join(dir, "out")
			},
			wantErr: true,
		},
		{
			name: "zip-with-directory-entry-creates-dir",
			setup: func(t *testing.T) (string, string) {
				t.Helper()
				dir := t.TempDir()
				zipPath := filepath.Join(dir, "withdir.zip")
				destDir := filepath.Join(dir, "out")
				test_makeZipWithDir(t, zipPath, "mydir/", "mydir/file.txt", "inside")
				return zipPath, destDir
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			// Prepare unit test data
			zipPath, destDir := tt.setup(t)

			// Execute and verify the expected error outcome
			if errUnzip := Unzip(zipPath, destDir); (errUnzip != nil) != tt.wantErr {
				t.Errorf("Unzip() error = '%v', wantErr = '%v'", errUnzip, tt.wantErr)
			}
		})
	}
}

// test_makeZip creates a ZIP archive at zipPath containing one entry per key-value pair in entries,
// where the key is the archive path and the value is the file content.
func test_makeZip(t *testing.T, zipPath string, entries map[string]string) {
	t.Helper()

	// Create the zip file on disk
	f, errF := os.Create(zipPath)
	if errF != nil {
		t.Fatalf("test_makeZip() could not create zip file: '%v'", errF)
	}
	defer func() { _ = f.Close() }()

	// Write each entry into the zip archive
	w := zip.NewWriter(f)
	defer func() { _ = w.Close() }()
	for name, content := range entries {
		fw, errFw := w.Create(name)
		if errFw != nil {
			t.Fatalf("test_makeZip() could not create zip entry '%s': '%v'", name, errFw)
		}
		if _, errWrite := io.WriteString(fw, content); errWrite != nil {
			t.Fatalf("test_makeZip() could not write zip entry '%s': '%v'", name, errWrite)
		}
	}
}

// test_makeZipWithDir creates a ZIP archive at zipPath containing an explicit directory entry and one file entry.
func test_makeZipWithDir(t *testing.T, zipPath, dirEntry, fileEntry, fileContent string) {
	t.Helper()

	// Create the zip file on disk
	f, errF := os.Create(zipPath)
	if errF != nil {
		t.Fatalf("test_makeZipWithDir() could not create zip file: '%v'", errF)
	}
	defer func() { _ = f.Close() }()

	// Write directory and file entries into the zip archive
	w := zip.NewWriter(f)
	defer func() { _ = w.Close() }()

	// Add explicit directory entry
	hdr := &zip.FileHeader{Name: dirEntry, Method: zip.Store}
	hdr.SetMode(0700 | os.ModeDir)
	if _, errDir := w.CreateHeader(hdr); errDir != nil {
		t.Fatalf("test_makeZipWithDir() could not create dir entry: '%v'", errDir)
	}

	// Add file entry inside the directory
	fw, errFw := w.Create(fileEntry)
	if errFw != nil {
		t.Fatalf("test_makeZipWithDir() could not create file entry: '%v'", errFw)
	}
	if _, errWrite := io.WriteString(fw, fileContent); errWrite != nil {
		t.Fatalf("test_makeZipWithDir() could not write file entry: '%v'", errWrite)
	}
}

// test_makeZipWithTraversal creates a ZIP archive at zipPath containing a single entry with the given
// entryName (which may include path traversal sequences like "../") and content.
func test_makeZipWithTraversal(t *testing.T, zipPath, entryName, content string) {
	t.Helper()

	// Create the zip file on disk
	f, errF := os.Create(zipPath)
	if errF != nil {
		t.Fatalf("test_makeZipWithTraversal() could not create zip file: '%v'", errF)
	}
	defer func() { _ = f.Close() }()

	// Write the traversal entry directly via CreateHeader to preserve the raw name
	w := zip.NewWriter(f)
	defer func() { _ = w.Close() }()
	hdr := &zip.FileHeader{Name: entryName, Method: zip.Deflate}
	fw, errFw := w.CreateHeader(hdr)
	if errFw != nil {
		t.Fatalf("test_makeZipWithTraversal() could not create header: '%v'", errFw)
	}
	if _, errWrite := io.WriteString(fw, content); errWrite != nil {
		t.Fatalf("test_makeZipWithTraversal() could not write content: '%v'", errWrite)
	}
}
