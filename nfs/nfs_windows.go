/*
* GoScans, a collection of network scan modules for infrastructure discovery and information gathering.
*
* Copyright (c) Siemens AG, 2016-2026.
*
* This work is licensed under the terms of the MIT license. For a copy, see the LICENSE file in the top-level
* directory or visit <https://opensource.org/licenses/MIT>.
*
 */

package nfs

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"

	nfsClient "github.com/krp2/go-nfs-client/nfs"
	"github.com/siemens/GoScans/filecrawler"
	"github.com/siemens/GoScans/utils"
	"github.com/vmware/go-nfs-client/nfs/rpc"
	"golang.org/x/sys/windows"
)

const nfsFeature = "ClientForNFS-Infrastructure"     // Name of the required NFS client feature on Windows clients
const nfsFeatureHigher = "ServicesForNFS-ClientOnly" // Additionally required NFS client feature on Windows clients
const nfsFeatureServer = "NFS-Client"                // Name of the required NFS client feature on Windows servers
const VerNtWorkstation = 1                           // The product type of Windows clients

const adminRights = ""   // We do not need admin rights for the scan on Windows
const unmountArgs = "-f" // Force unmounting the NFS share

// setupOs configures the environment accordingly, if the scan module has some special requirements. A successful setup
// is required before a scan can be started.
func setupOs(logger utils.Logger) error {

	// Get version of Windows os
	winVersion := windows.RtlGetVersion()
	if winVersion == nil {
		return fmt.Errorf("could not determine version of the operating system")
	}

	// The Windows Nfs Client needs to be activated to provide the protocol support
	if winVersion.ProductType != VerNtWorkstation { // NFS client activation for Windows server OS

		// Run command for installing the nfs client
		logger.Infof("Enabling Windows feature '%s'.", nfsFeatureServer)
		outCmd, errOutCmd := exec.Command(
			"powershell",
			"-NonInteractive",
			fmt.Sprintf("Install-WindowsFeature %s", nfsFeatureServer)).CombinedOutput()
		if errOutCmd != nil {
			return fmt.Errorf("could not enable Windows feature '%s': %s", nfsFeatureServer, string(outCmd))
		}

	} else { // NFS client activation for Windows client OS

		// Enable Higher feature of Windows Nfs Client
		logger.Infof("Enabling Windows feature '%s'.", nfsFeatureHigher)
		outHigher, errOutHigher := exec.Command(
			"dism", "/online", "/Enable-Feature", "/FeatureName:"+nfsFeatureHigher).CombinedOutput()
		if errOutHigher != nil {
			return fmt.Errorf("could not enable Windows feature '%s': %s", nfsFeatureHigher, string(outHigher))
		}

		// Enable Windows Nfs Client
		logger.Infof("Enabling Windows feature '%s'.", nfsFeature)
		outClient, errOutClient := exec.Command(
			"dism", "/online", "/Enable-Feature", "/FeatureName:"+nfsFeature).CombinedOutput()
		if errOutClient != nil {
			return fmt.Errorf("could not enable Windows feature '%s': %s", nfsFeature, string(outClient))
		}
	}

	// Return nil as everything went fine
	return nil
}

// checkSetupOs checks whether Setup() executed accordingly. Scan arguments should be checked by the scanner.
func checkSetupOs() error {

	// Check the "showmount" command
	_, errShowmount := exec.Command("showmount").CombinedOutput()
	if errShowmount != nil {
		return fmt.Errorf("could not find Windows command 'showmount'")
	}

	// Check the mount command
	_, errMount := exec.Command("mount").CombinedOutput()
	if errMount != nil {
		return fmt.Errorf("could not find Windows command 'mount'")
	}

	// Check the umount command
	_, errUmount := exec.Command("umount").CombinedOutput()
	if errUmount != nil {
		return fmt.Errorf("could not find Windows command 'umount'")
	}

	// Return nil as everything went fine
	return nil
}

// getExportsV4 works only on clients that support NFSv4, which windows is not supporting yet. The day it does, this
// function can be removed and "getExportsV4()" from "nfs_linux.go" moved to "nfs.go".
func (s *Scanner) getExportsV4() (map[string][]string, error) {
	return make(map[string][]string), nil
}

// mountExport mounts an export and returns its mount point
func (s *Scanner) mountExport(export string, option string) (string, error) {

	// Build mount arguments as discrete values to prevent shell injection via export names
	var mountArgs []string
	if option != "" {
		mountArgs = append(mountArgs, strings.Fields(option)...)
	}
	mountArgs = append(mountArgs,
		"-o", fmt.Sprintf("timeout=%v", s.mountTimeout.Seconds()),
		fmt.Sprintf("%s:%s", s.target, export),
		"*",
	)

	// Mount export and let windows assign the mount point (map network drive)
	out, errOut := exec.Command("mount", mountArgs...).CombinedOutput()

	// Prepare output message and return if an error occurred
	outStr := strings.ReplaceAll(string(out), "\n", " ")
	if errOut != nil {
		return "", fmt.Errorf("%s", outStr)
	}

	// Return an error if we got no drive letter
	if len(outStr) < 1 {
		return "", fmt.Errorf("windows did not assign a drive letter for export")
	}

	// Extract and return the mapped drive letter
	return fmt.Sprintf("%s:", string(outStr[0])), nil
}

// prepareMountBase prepares a base folder for mounting NFS shares, which is only required on Linux
func prepareMountBase() error {
	return nil
}

// deleteMountPoint is not needed on windows
func deleteMountPoint(mountPoint string) error {
	return nil
}

// getUnixFlagsWindows extracts unix file permissions of a file. On Linux systems, this can already be done directly
// by the file crawler. On Windows this needs to be done additionally.
func (s *Scanner) getUnixFlagsWindows(exportName string, exportResults *filecrawler.Result) {

	// DialMount creates an rpc client for sending mount/umount procedure calls to the target
	rpcTarget, errRpcTarget := nfsClient.DialMount(s.target)
	if errRpcTarget != nil {
		s.logger.Debugf("Could not dial MOUNT service: %s", errRpcTarget)
		return
	}
	defer func() {
		errClo := rpcTarget.Close()
		if errClo != nil {
			s.logger.Debugf("Could not close connection to host: %s", errClo)
		}
	}()

	// Get another rpc client for performing file operations on the mounted export
	auth := rpc.NewAuthUnix("", 65534, 65534) // Empty auth 65534 maps to nobody
	rpcExport, errRpcExport := rpcTarget.Mount(exportName, auth.Auth())
	if errRpcExport != nil {
		s.logger.Debugf("Could not mount volume: %s", errRpcExport)
		return
	}
	defer func() {
		errExClo := rpcExport.Close()
		if errExClo != nil {
			s.logger.Debugf("Could not close connection to export: %s", errExClo)
		}
	}()

	// Get the file mode for every file in the results
	for _, file := range exportResults.Data {
		relativeToExport := strings.TrimPrefix(file.Path, file.Share)

		// Get file attributes from the nfs lookup procedure
		relativeToExport2 := strings.ReplaceAll(relativeToExport, "\\", "/") // Replace the slashes just in case
		fattr, _, errLkp := rpcExport.Lookup(relativeToExport2)
		if errLkp != nil {
			s.logger.Debugf("Could not lookup file %s: %s", file.Path, errLkp)
			continue
		}

		// Assign the string version of the file mode to the flags attribute
		file.Flags = fileModeFromFattr(fattr).String()
	}
}

// fileModeFromFattr converts a Linux file-mode (from NFS file attributes) to os.FileMode.
func fileModeFromFattr(fs os.FileInfo) os.FileMode {

	// Get the read, write and execute permissions
	fileMode := fs.Mode() & 0777

	// Get file mode
	switch fs.Mode() & syscall.S_IFMT {
	case syscall.S_IFBLK:
		fileMode |= os.ModeDevice
	case syscall.S_IFCHR:
		fileMode |= os.ModeDevice | os.ModeCharDevice
	case syscall.S_IFDIR:
		fileMode |= os.ModeDir
	case syscall.S_IFIFO:
		fileMode |= os.ModeNamedPipe
	case syscall.S_IFLNK:
		fileMode |= os.ModeSymlink
	case syscall.S_IFREG:
		// nothing to do
	case syscall.S_IFSOCK:
		fileMode |= os.ModeSocket
	}
	if fs.Mode()&syscall.S_ISGID != 0 {
		fileMode |= os.ModeSetgid
	}
	if fs.Mode()&syscall.S_ISUID != 0 {
		fileMode |= os.ModeSetuid
	}
	if fs.Mode()&syscall.S_ISVTX != 0 {
		fileMode |= os.ModeSticky
	}

	return fileMode
}
