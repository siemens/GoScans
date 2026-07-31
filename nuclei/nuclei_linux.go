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
	"os"
	"path/filepath"
	"syscall"

	"github.com/siemens/GoScans/utils"
)

// chownDirTree sets the ownership of all files and folders within the given path
// to match the owner of the currently executing binary
func chownDirTree(logger utils.Logger, pathTemplates string) error {

	// Get the path to the currently executing binary
	exePath, errExePath := os.Executable()
	if errExePath != nil {
		return fmt.Errorf("could not get executable path: %w", errExePath)
	}

	// Get absolute path
	exePathAbs, errExePathAbs := filepath.Abs(exePath)
	if errExePathAbs != nil {
		return fmt.Errorf("could not get absolute path of executable: %w", errExePathAbs)
	}

	// Get info of the binary
	info, errInfo := os.Stat(exePathAbs)
	if errInfo != nil {
		return fmt.Errorf("could not stat executable: %w", errInfo)
	}

	// Get stat_t to extract UID/GID
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("could not get raw stat for executable")
	}

	// Get UID/GID
	uid := int(stat.Uid)
	gid := int(stat.Gid)

	// Recursively walk template directory and set ownership
	return filepath.WalkDir(pathTemplates, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if errChown := os.Chown(p, uid, gid); err != nil {
			logger.Warningf("could not chown '%s': %v", p, errChown) // log a warning but continue
		}
		return nil
	})
}
