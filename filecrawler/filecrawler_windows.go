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
	"errors"
	"os"
	"syscall"

	"github.com/siemens/GoScans/utils"
)

// determineSymlinkPermissions checks the read and write access of the symlink target on Windows by
// opening it with CreateFile and the FILE_FLAG_OPEN_REPARSE_POINT flag to avoid following the link.
func determineSymlinkPermissions(symlinkInfo *File, logger utils.Logger) {

	// Determine Read permission
	readable, errReadable := accessSymlink(symlinkInfo.Path, syscall.GENERIC_READ)
	if errReadable != nil {
		logger.Debugf("Could not file permissions of %s: %s", symlinkInfo.Path, errReadable)
	}
	symlinkInfo.Readable = readable

	// Determine Write permission
	writable, errWritable := accessSymlink(symlinkInfo.Path, syscall.GENERIC_WRITE)
	if errWritable != nil {
		logger.Debugf("Could not file permissions of %s: %s", symlinkInfo.Path, errWritable)
	}
	symlinkInfo.Writable = writable
}

// accessSymlink detects and returns if a symlink could be opened with a given access flag, (eg. syscall.GENERIC_READ).
// We need to use the syscall CreateFile instead of Golang's OpenFile() since we need to specify to not follow symlinks.
func accessSymlink(path string, accessFlag uint32) (access bool, err error) {

	// Convert path to a UTF16 string
	pathUTF16, errPathUTF16 := syscall.UTF16PtrFromString(path)
	if errPathUTF16 != nil {
		return false, errPathUTF16
	}

	// Specify that file can be used by other processes while we open it
	sharemode := uint32(syscall.FILE_SHARE_READ | syscall.FILE_SHARE_WRITE)

	// Use FILE_FLAG_BACKUP_SEMANTICS to be able to open symlinks to folders.
	// Use FILE_FLAG_OPEN_REPARSE_POINT, otherwise CreateFile will follow symlink.
	attrs := uint32(syscall.FILE_FLAG_BACKUP_SEMANTICS | syscall.FILE_FLAG_OPEN_REPARSE_POINT)

	// Try to open file with the specified access flag
	fileHandle, errFileHandle := syscall.CreateFile(
		pathUTF16, accessFlag, sharemode, nil, syscall.OPEN_EXISTING, attrs, 0)
	if errFileHandle != nil {
		if errors.Is(errFileHandle, syscall.ERROR_ACCESS_DENIED) {
			return false, nil
		} else {
			return false, errFileHandle
		}
	}

	// If opening was successful, close the handle and return true
	errClose := syscall.CloseHandle(fileHandle)
	if errClose != nil {
		return true, errClose // return additionally the error of the failed file handle closing
	}

	// Return flag that file could be accessed
	return true, nil
}

// getUnixFlags extracts unix file permissions of the fileMode, which are not existing on Windows
func getUnixFlags(fm os.FileMode) string {
	return ""
}
