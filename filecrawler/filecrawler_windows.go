package filecrawler

import (
	"github.com/siemens/GoScans/utils"
	"os"
	"syscall"
)

func determineSymlinkPermissions(symlinkInfo *File, logger utils.Logger) {

	// Determine Read permission
	readable, errRead := accessSymlink(symlinkInfo.Path, syscall.GENERIC_READ)
	if errRead != nil {
		logger.Debugf("Could not file permissions of %s: %s", symlinkInfo.Path, errRead)
	}
	symlinkInfo.Readable = readable

	// Determine Write permission
	writable, errWrite := accessSymlink(symlinkInfo.Path, syscall.GENERIC_WRITE)
	if errWrite != nil {
		logger.Debugf("Could not file permissions of %s: %s", symlinkInfo.Path, errWrite)
	}
	symlinkInfo.Writable = writable
}

// accessSymlink detects and returns if a symlink could be opened with a given access flag, (eg. syscall.GENERIC_READ).
// We need to use the syscall CreateFile instead of Golang's OpenFile() since we need to specify to not follow symlinks.
func accessSymlink(path string, accessFlag uint32) (access bool, err error) {

	// Convert path to a UTF16 string
	pathUTF16, errUTF16 := syscall.UTF16PtrFromString(path)
	if errUTF16 != nil {
		return false, errUTF16
	}

	// Specify that file can be used by other processes while we open it
	sharemode := uint32(syscall.FILE_SHARE_READ | syscall.FILE_SHARE_WRITE)

	// Use FILE_FLAG_BACKUP_SEMANTICS to be able to open symlinks to folders.
	// Use FILE_FLAG_OPEN_REPARSE_POINT, otherwise CreateFile will follow symlink.
	attrs := uint32(syscall.FILE_FLAG_BACKUP_SEMANTICS | syscall.FILE_FLAG_OPEN_REPARSE_POINT)

	// Try to open file with the specified access flag
	fileHandle, errOpen := syscall.CreateFile(
		pathUTF16, accessFlag, sharemode, nil, syscall.OPEN_EXISTING, attrs, 0)
	if errOpen != nil {
		if errOpen == syscall.ERROR_ACCESS_DENIED {
			return false, nil
		} else {
			return false, errOpen
		}
	}

	// If opening was successful, close the handle and return true
	errClose := syscall.CloseHandle(fileHandle)
	if errClose != nil {
		return true, err // return additionally the error of the failed file handle closing
	}

	// Return flag that file could be accessed
	return true, nil
}

// getUnixFlags extracts unix file permissions of the fileMode, which are not existing on Windows
func getUnixFlags(fm os.FileMode) string {
	return ""
}
