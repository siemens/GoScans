package filecrawler

import (
	"go-scans/utils"
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
)

// prepareCrawling prepares the OS to crawl files
func prepareCrawling(logger utils.Logger) error {
	return nil
}

// cleanupCrawling restores preparations of the OS that were required to crawl files
func cleanupCrawling() {
}

// extractSensitivity retrieves the sensitivity label of the file, but is not available on Linux
func extractSensitivity(path string) string {
	return ""
}

// getUnixFlags extracts unix file permissions of the fileMode
func getUnixFlags(fm os.FileMode) string {
	return fm.String()
}

// Determines the read and write permission of a symlink. Since in most Linux distros the mode of symlinks is 0777 and
// is not changeable, we determine the (effective) symlink permissions by the effective permissions of its parent folder.
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

// No custom properties determination implemented yet
func getCustomProperties(filepath string, logger utils.Logger) ([]string, error) {
	return []string{}, nil
}
