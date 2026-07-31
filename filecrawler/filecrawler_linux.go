/*
* GoScans, a collection of network scan modules for infrastructure discovery and information gathering.
*
* Copyright (c) Siemens AG, 2016-2026.
*
* This work is licensed under the terms of the MIT license. For a copy, see the LICENSE file in the top-level
* directory or visit <https://opensource.org/licenses/MIT>.
*
 */

package filecrawler

import (
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"

	"github.com/siemens/GoScans/utils"
)

// getUnixFlags extracts unix file permissions of the fileMode
func getUnixFlags(fm os.FileMode) string {
	return fm.String()
}

// determineSymlinkPermissions checks the read and write access of the symlink on Linux by testing the effective
// permissions of its parent directory, since the mode of symlinks is always 0777 and not independently changeable.
func determineSymlinkPermissions(symlinkInfo *File, logger utils.Logger) {

	// Get the path to the parent folder
	parentDir := filepath.Dir(symlinkInfo.Path)

	// Determine read permission by accessing it with a read-only flag
	errRead := unix.Access(parentDir, unix.R_OK)
	if errRead != nil {
		if os.IsPermission(errRead) { // Distinguish between no access and other errors
			symlinkInfo.Readable = false
		} else {
			logger.Debugf("Could not determine read permissions of %s: %s", symlinkInfo.Path, errRead)
		}
	} else {
		symlinkInfo.Readable = true
	}

	// Same as above but with a write-only flag
	errWrite := unix.Access(parentDir, unix.W_OK)
	if errWrite != nil {
		if os.IsPermission(errWrite) {
			symlinkInfo.Writable = false
		} else {
			logger.Debugf("Could not determine write permissions of %s: %s", symlinkInfo.Path, errWrite)
		}
	} else {
		symlinkInfo.Writable = true
	}
}
