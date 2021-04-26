/*
* GoScans, a collection of network scan modules for infrastructure discovery and information gathering.
*
* Copyright (c) Siemens AG, 2016-2021.
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

// Execute command without returning output. Just returning potential errors
func Execute(cmd string, args []string) error {

	// Run command
	out, err := exec.Command(cmd, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s", string(out))
	}
	return nil
}

// IsValidFolder checks whether a given path is existing and a folder
func IsValidFolder(path string) error {
	if path != "" { // Empty path = current folder, which is always valid
		fi, err := os.Stat(path)
		if os.IsNotExist(err) {
			return fmt.Errorf("path not existing: %s", path)
		} else if !fi.IsDir() {
			return fmt.Errorf("path not a folder: %s", path)
		}
	}
	return nil
}

// IsValidFile checks whether a given path is existing and a file
func IsValidFile(path string) error {
	fi, err := os.Stat(path)
	if os.IsNotExist(err) {
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
	_, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("path '%s %s' is not an executable: %s", path, strings.Join(args, " "), err)
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
