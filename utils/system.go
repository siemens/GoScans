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
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// Execute runs a system command and returns any error, discarding the command output.
func Execute(cmd string, args []string) error {

	// Run command
	out, errOut := exec.Command(cmd, args...).CombinedOutput()
	if errOut != nil {
		return fmt.Errorf("%s", string(out))
	}
	return nil
}

// IsValidFolder checks whether a given path is existing and a folder
func IsValidFolder(path string) error {
	if path != "" { // Empty path = current folder, which is always valid
		fi, errFi := os.Stat(path)
		if os.IsNotExist(errFi) {
			return fmt.Errorf("path not existing: %s", path)
		} else if !fi.IsDir() {
			return fmt.Errorf("path not a folder: %s", path)
		}
	}
	return nil
}

// IsValidFile checks whether a given path is existing and a file
func IsValidFile(path string) error {
	fi, errFi := os.Stat(path)
	if os.IsNotExist(errFi) {
		return fmt.Errorf("path not existing: %s", path)
	}
	if fi != nil && fi.IsDir() {
		return fmt.Errorf("path not a file: %s", path)
	}
	return nil
}

// IsValidExecutable checks whether a given path can be executed
func IsValidExecutable(path string, args ...string) error {
	cmd := exec.Command(path, args...)
	_, errCombinedOutput := cmd.CombinedOutput()
	if errCombinedOutput != nil {
		return fmt.Errorf("path '%s %s' is not an executable: %s", path, strings.Join(args, " "), errCombinedOutput)
	}
	return nil
}

// SanitizeFilename takes a desired file name and converts characters not allowed by the filesystem
func SanitizeFilename(raw string, placeholder string) string {

	// Search and replace invalid characters
	for _, c := range []string{"\"", "/", "?", "\\", "*", ":", "<", ">", "|", " "} {
		raw = strings.Replace(raw, c, placeholder, -1)
	}
	return raw
}
