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
	"errors"
	"io"
	"os"
	"path/filepath"
)

// MoveDirSafe copies a file or directory recursively and deletes the source afterward.
// This replaces os.Rename to ensure compatibility across all operating systems (Windows, macOS, Linux).
func MoveDirSafe(src, dst string) error {

	// Stat the source path
	info, errInfo := os.Stat(src)
	if errInfo != nil {
		return errInfo
	}

	// If source is a directory, copy recursively
	if info.IsDir() {

		// Create destination directory
		errMkdir := os.MkdirAll(dst, info.Mode())
		if errMkdir != nil {
			return errMkdir
		}

		// Read entries in the source directory
		entries, errEntries := os.ReadDir(src)
		if errEntries != nil {
			return errEntries
		}

		// Move each entry
		for _, entry := range entries {
			errMove := MoveDirSafe(filepath.Join(src, entry.Name()), filepath.Join(dst, entry.Name()))
			if errMove != nil {
				return errMove
			}
		}

		// Remove the source directory after moving contents
		return os.RemoveAll(src)
	}

	// Copy file
	in, errIn := os.Open(src)
	if errIn != nil {
		return errIn
	}
	defer func() { _ = in.Close() }()

	out, errOut := os.Create(dst)
	if errOut != nil {
		return errOut
	}

	// Close file at the end
	defer func() { _ = out.Close() }()

	// Copy the file contents
	_, errCopy := io.Copy(out, in)
	if errCopy != nil {
		return errCopy
	}

	// Close input file
	_ = in.Close()

	// Ensure the file is flushed
	if errClose := out.Close(); errClose != nil {
		return errClose
	}

	// Remove the original file
	return os.Remove(src)
}

// StreamToFile writes the content from the given reader to a file at the given location.
func StreamToFile(logger Logger, source io.Reader, outputFolder string, outputName string) error {

	// Create tmp folder if it does not exist
	if _, errStat := os.Stat(outputFolder); errors.Is(errStat, os.ErrNotExist) {
		errMk := os.Mkdir(outputFolder, 0700)
		if errMk != nil {
			logger.Warningf("Could not create download folder: %s", errMk)
		}
	}

	// Prepare output file path
	file := filepath.Join(outputFolder, outputName)

	// Create output file
	out, errOut := os.Create(file)
	if errOut != nil {
		return errOut
	}

	// Make sure file gets closed on exit
	defer func() { _ = out.Close() }()

	// Write the body to file
	_, errWrite := io.Copy(out, source)

	// Return error or nil
	return errWrite
}

// AccessFile detects and returns if a file could be opened with a given flag (eg. readable/writable). If an error
// (other than a permission error) occurred it, is returned.
func AccessFile(path string, flag int) (opened bool, err error) {

	// Try to open the file
	file, errFile := os.OpenFile(path, flag, 0660) // the perm attribute does not matter, since no file is created
	if errFile != nil {

		// Try to cast to path error
		errPath, isPathError := errFile.(*os.PathError)

		// Check if it is a permission denied error, if yes return that file could not be opened
		if isPathError && (errors.Is(errPath, os.ErrPermission) || errPath.Err.Error() == os.ErrPermission.Error()) {
			return false, nil

			// If it is another error, additionally return the error
		} else {
			return false, errFile
		}
	}

	// If opening was successful, close the handle and return true
	_ = file.Close()

	// Return that file could be opened
	return true, nil
}
