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
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Unzip extracts a ZIP file to the destination directory with security checks to prevent zip slip attacks.
func Unzip(zipPath, destDir string) error {

	// Define helper function to extract a single file from the ZIP archive
	extractZipFile := func(filePath string, file *zip.File) error {

		// Open the file inside the ZIP for reading
		srcFile, errSrcFile := file.Open()
		if errSrcFile != nil {
			return fmt.Errorf("could not open file in zip: %w", errSrcFile)
		}
		// Make sure source file gets closed
		defer func() { _ = srcFile.Close() }()

		// Create the destination file for writing
		dstFile, errDstFile := os.OpenFile(filePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, file.Mode())
		if errDstFile != nil {
			return fmt.Errorf("could not create extraction target: %w", errDstFile)
		}
		// Make sure destination file gets closed
		defer func() { _ = dstFile.Close() }()

		// Copy the file contents from ZIP to destination
		_, errCopy := io.Copy(dstFile, srcFile)
		if errCopy != nil {
			return fmt.Errorf("could not extract file: %w", errCopy)
		}

		// Return nil as file extraction completed successfully
		return nil
	}

	// Open the ZIP file for reading
	zipReader, errZipReader := zip.OpenReader(zipPath)
	if errZipReader != nil {
		return fmt.Errorf("could not open zip file: %w", errZipReader)
	}
	// Make sure Reader gets closed
	defer func() { _ = zipReader.Close() }()

	// Iterate through all files in the ZIP archive
	for _, file := range zipReader.File {

		// Construct the full file path for extraction
		filePath := filepath.Join(destDir, file.Name)

		// Prevent zip slip vulnerability by validating the file path stays within destDir
		cleanFilePath := filepath.Clean(filePath)
		cleanDestDir := filepath.Clean(destDir) + string(os.PathSeparator)
		if !strings.HasPrefix(cleanFilePath, cleanDestDir) {
			return fmt.Errorf("illegal file path in zip: %s", file.Name)
		}

		// Handle directory entries by creating them
		if file.FileInfo().IsDir() {

			// Create the directory with appropriate permissions
			errMkdir := os.MkdirAll(filePath, file.Mode())
			if errMkdir != nil {
				return fmt.Errorf("could not create directory: %w", errMkdir)
			}

			// Continue to the next entry
			continue
		}

		// Create parent directories if they don't exist
		errParentDir := os.MkdirAll(filepath.Dir(filePath), 0700)
		if errParentDir != nil {
			return fmt.Errorf("could not create parent directory: %w", errParentDir)
		}

		// Extract the file from the archive
		errExtractFile := extractZipFile(filePath, file)
		if errExtractFile != nil {
			return errExtractFile
		}
	}

	// Return nil as everything went fine
	return nil
}
