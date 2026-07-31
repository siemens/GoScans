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
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// discoverHelperFiles walks <pathTemplates>/helpers/ recursively and returns a map of all regular
// files found there, keyed by their path relative to pathTemplates with forward-slash separators.
// If the helpers/ directory does not exist, a non-nil empty map is returned without error.
// Symlinks are followed; entries whose resolved target lies outside pathTemplates are skipped.
// Non-regular files (sockets, devices, directories) are skipped silently.
func discoverHelperFiles(pathTemplates string) (map[string]struct{}, error) {

	// Prepare the result map and resolve the canonical templates root for containment checks
	allowlist := make(map[string]struct{})
	cleanRoot, errCleanRoot := filepath.Abs(filepath.Clean(pathTemplates))
	if errCleanRoot != nil {
		return nil, fmt.Errorf("could not resolve templates path: %w", errCleanRoot)
	}
	rootPrefix := cleanRoot + string(filepath.Separator)

	// Return an empty allowlist when helpers/ does not exist; future template releases may drop the directory
	helpersDir := filepath.Join(cleanRoot, "helpers")
	if _, errStat := os.Stat(helpersDir); os.IsNotExist(errStat) {
		return allowlist, nil
	} else if errStat != nil {
		return nil, fmt.Errorf("could not stat helpers directory: %w", errStat)
	}

	// Walk helpers/ recursively and add each eligible file to the allowlist
	errWalk := filepath.WalkDir(helpersDir, func(path string, d fs.DirEntry, err error) error {

		// Propagate walk errors before processing the entry
		if err != nil {
			return err
		}

		// Skip directory entries
		if d.IsDir() {
			return nil
		}

		// Include only regular files; follow symlinks whose resolved target is inside pathTemplates
		if d.Type()&fs.ModeSymlink != 0 {
			realPath, errRealPath := filepath.EvalSymlinks(path)
			if errRealPath != nil {
				return nil
			}
			cleanReal := filepath.Clean(realPath)
			if !strings.HasPrefix(cleanReal+string(filepath.Separator), rootPrefix) {
				return nil
			}
			info, errInfo := os.Stat(realPath)
			if errInfo != nil || !info.Mode().IsRegular() {
				return nil
			}
		} else if !d.Type().IsRegular() {
			return nil
		}

		// Record the relative path normalized to forward slashes for cross-platform consistency
		rel, errRel := filepath.Rel(cleanRoot, path)
		if errRel != nil {
			return nil
		}
		allowlist[filepath.ToSlash(rel)] = struct{}{}

		// Return nil as everything went fine
		return nil
	})
	if errWalk != nil {
		return nil, fmt.Errorf("could not walk helpers directory: %w", errWalk)
	}

	// Return nil as everything went fine
	return allowlist, nil
}
