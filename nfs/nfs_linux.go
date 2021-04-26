/*
* GoScans, a collection of network scan modules for infrastructure discovery and information gathering.
*
* Copyright (c) Siemens AG, 2016-2021.
*
* This work is licensed under the terms of the MIT license. For a copy, see the LICENSE file in the top-level
* directory or visit <https://opensource.org/licenses/MIT>.
*
 */

package nfs

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"go-scans/filecrawler"
	"go-scans/utils"
	"io/ioutil"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"time"
)

const (
	nfsLibrary  = "nfs-common"
	mountDir    = "/nfs"
	sudoersDir  = "/etc/sudoers.d"
	sudoersFile = "nfs-sudoers"

	// Create the sudoers config file and use visudo to safely make an entry for the needed commands
	createSudoersConfig = "echo \"[USERNAME] ALL=NOPASSWD: /usr/bin/mount, /usr/bin/umount, /usr/sbin/showmount \" | " +
		"EDITOR=\"tee\" visudo -f /etc/sudoers.d/" + sudoersFile

	shellToUse  = "sh" // Choose the systems shell
	shellArg    = "-c" // Read commands from the command_string operand instead of the standard input
	adminRights = "sudo"
	unmountArgs = "-f -l"
)

// setupOs configures the environment accordingly, if the scan module has some special requirements. A successful setup
// is required before a scan can be started.
func setupOs(logger utils.Logger) error {

	// Install/upgrade the needed nfs client for the scanner
	logger.Infof("Installing Linux package '%s'.", nfsLibrary)
	cmdStr := fmt.Sprintf("apt-get install %s", nfsLibrary)
	_, err := execWithUserInput(cmdStr, []string{"y"})
	if err != nil {
		return fmt.Errorf("could not install '%s': %s", nfsLibrary, err)
	}

	// Get username from command line arguments if available. If the flag packages wasn't used or initialized by main,
	// this will just result in an empty string.
	userArg := flag.CommandLine.Lookup("user")
	nfsUser := ""
	if userArg != nil {
		nfsUser = userArg.Value.String()
	}

	// Log action
	sudoersPath := filepath.Join(sudoersDir, sudoersFile)
	if len(nfsUser) > 0 {
		logger.Infof("Adding '%s' to sudoers file '%s' for NFS commands.", nfsUser, sudoersPath)
	} else {
		logger.Infof("Adding user to sudoers file '%s' for NFS commands.", sudoersPath)
	}

	// Create the needed configuration for the sudo command
	err = createSudoersConf(logger, nfsUser)
	if err != nil {
		return err
	}

	// Return nil as everything went fine
	return nil
}

// checkSetupOs checks whether Setup() executed accordingly. Scan arguments should be checked by the scanner.
func checkSetupOs() error {

	// Define commands to be checked
	cmdShwMnt := fmt.Sprintf("%s -S showmount -h", adminRights) // "-S" means read password input from stdin.
	cmdMnt := fmt.Sprintf("%s -S mount -h", adminRights)
	cmdUMnt := fmt.Sprintf("%s -S umount -h", adminRights)
	cmdStrs := []string{cmdShwMnt, cmdMnt, cmdUMnt}

	// Run all commands consecutively and check if and what kind of errors occurred
	for _, cmdStr := range cmdStrs {

		// We use 3 times empty input since we could be ask for sudo password 3 times if sudoers configuration failed
		_, errExec := execWithUserInput(cmdStr, []string{"", "", ""})

		// Return specific error if possible, generic otherwise
		if errExec != nil && strings.Contains(errExec.Error(), "command not found") {
			return fmt.Errorf("package '%s' not found", nfsLibrary)
		}
		if errExec != nil && strings.Contains(errExec.Error(), "3 incorrect password attempts") {
			return fmt.Errorf("invalid sudoers configuration for '%s'", nfsLibrary)
		}
		if errExec != nil {
			return fmt.Errorf("invalid command '%s': %s", cmdStr, errExec)
		}
	}

	// Return nil as everything went fine
	return nil
}

// getExportsV4 works only on clients supporting NFSv4. It mounts the exported root filesystem of the target and
// reads all contained exports
func (s *Scanner) getExportsV4() (map[string][]string, error) {

	// Prepare memory for export results
	exports := make(map[string][]string)

	// Try to mount the root of the exported file system (if NFSv4 is used). Should work without the option, but with
	// it, it is more robust
	mountPoint, errMount := s.mountExport("/", "-t nfs4")
	if errMount != nil {
		if strings.Contains(errMount.Error(), "No such file or directory") || // If there is simply no export "/"
			strings.Contains(errMount.Error(), "access denied by server") { // If there is no access
			return exports, nil
		} else {
			return exports, errMount
		}
	}

	// Clean up mounted NFS shares
	defer func() {

		// Unmount export
		errUnmount := s.unmountExport(mountPoint)
		if errUnmount != nil {
			s.logger.Warningf("Could not unmount export '%s'.", mountPoint)
			return
		}

		// Delete mount point
		errDelete := deleteMountPoint(mountPoint)
		if errDelete != nil {
			s.logger.Warningf("Could not delete '%s'.", mountPoint)
		}
	}()

	// Try to read all sub folders aka the exports (of an NFSv4)
	dirs, errRead := ioutil.ReadDir(mountPoint)
	if errRead != nil {
		return exports, errRead
	}
	for _, dir := range dirs {
		exports["/"+dir.Name()] = []string{}
	}

	// Return exports
	return exports, nil
}

// mountExport mounts an export and returns its mount point, option ist not necessary but can be used to specify e.g. a
// filesystem type like "t- nfs4"
func (s *Scanner) mountExport(export string, option string) (string, error) {

	// Prepare a valid and distinguishable mount point folder name
	mountPoint := fmt.Sprintf(
		"%s/scan_%s_%s_%s",
		mountDir,
		s.target,
		strings.ReplaceAll(export, "/", "-"),
		time.Now().Format("2006-01-02-15:04:05.000"),
	)

	// Create directory as mount point
	errMntPnt := os.Mkdir(mountPoint, 0700)
	if errMntPnt != nil {
		return "", errMntPnt
	}

	// Prepare mount command
	cmdStr := fmt.Sprintf(
		"%s mount %s -o soft,retry=0,timeo=%v %s:%s %s",
		adminRights,
		option,
		s.mountTimeout.Seconds()*10,
		s.target,
		export,
		mountPoint,
	)

	// Execute mount
	out, errMnt := exec.Command(shellToUse, shellArg, cmdStr).CombinedOutput()
	if errMnt != nil {

		// Delete the created mount point, if it couldn't be used for mounting
		errDel := deleteMountPoint(mountPoint)
		if errDel != nil {
			s.logger.Warningf("Could not delete mount point '%s'.", mountPoint)
		}

		// Sanitize command output
		outStr := strings.Replace(string(out), "\n", " ", -1)

		// Return error
		return "", fmt.Errorf(outStr)
	}

	// Return mount point
	return mountPoint, nil
}

// prepareMountBase prepares a base folder for mounting NFS shares, which is only required on Linux
func prepareMountBase() error {

	// Check whether path is existing and a not a directory
	info, errStat := os.Stat(mountDir)
	existing := !os.IsNotExist(errStat)

	// Check validity or try to create file
	if existing {
		if !info.IsDir() { // File path is existing but a folder
			return fmt.Errorf("mount base '%s' already exists", mountDir)
		}
	} else {
		errMountBase := os.MkdirAll(mountDir, 0660)
		if errMountBase != nil {
			return fmt.Errorf("could not craete mount base '%s': %s", mountDir, errMountBase)
		}
	}

	// Return nil as everything went fine
	return nil
}

// deleteMountPoint removes unused mount points
func deleteMountPoint(mountPoint string) error {

	// remove empty mounting point folder
	cmdStr := fmt.Sprintf("rmdir %s", mountPoint)
	out, err := exec.Command(shellToUse, shellArg, cmdStr).CombinedOutput()
	if err != nil {
		return fmt.Errorf(string(out))
	}

	// Return nil as everything went fine
	return nil
}

// createSudoersConf makes the "showmount", "mount" and "umount" command executable without sudo password by creating
// a sudoers configuration file with corresponding entry
func createSudoersConf(logger utils.Logger, username string) error {

	// Discover username if it wasn't passed
	if len(username) == 0 {

		// Get username of current user
		username = getUsername(logger)
	}

	// Check if username is available
	if len(username) == 0 {
		return fmt.Errorf("invalid user for sudoers file")
	}

	// Validate username
	_, errorLookup := user.Lookup(username)
	if errorLookup != nil {
		return fmt.Errorf("unknown user '%s' for sudoers file", username)
	}

	// Create folder for the configuration file with recommended permissions (does nothing if folder already exists)
	errMkDir := os.Mkdir(sudoersDir, 0755) // Standard permissions in Debian for this folder
	if errMkDir != nil && !strings.Contains(errMkDir.Error(), "file exists") {
		return fmt.Errorf("could not prepare sudoers config file: %s", errMkDir)
	}

	// Create the sudoers config file and use visudo to safely make an entry for the needed commands
	cmdStr := strings.Replace(createSudoersConfig, "[USERNAME]", username, 1)
	out, errSuConf := exec.Command(shellToUse, shellArg, cmdStr).CombinedOutput()
	if errSuConf != nil {
		return fmt.Errorf("could not create sudoers config file: %s", string(out))
	}

	// return nil as everything went fine
	return nil
}

// getUsername determines the username which the agent will be executed as. It first tries to find it out with the
// "who" command (It ignores empty output and "root" as username) and prompts the user for confirmation. If this
// fails then the user is prompted to enter the username.
func getUsername(logger utils.Logger) string {

	// Get username of current user
	username := ""
	out, errCmd := exec.Command(shellToUse, shellArg, "who").CombinedOutput()

	// Check if username is not empty or root
	if errCmd == nil {
		lineSplit := strings.Fields(string(out))
		if len(lineSplit) > 0 && lineSplit[0] != "root" {
			username = lineSplit[0]
		}
	}

	// Define reader for user input
	scanner := bufio.NewScanner(os.Stdin)

	// If a username could be determined, prompt user for confirmation
	if username != "" {
		logger.Infof("Your current user is '%s', is this the user the agent will be executed as? (y/n)", username)
	InputLoop:
		for {
			scanner.Scan()
			switch answer := scanner.Text(); answer {
			case "y":
				return username
			case "n":
				break InputLoop
			default:
				logger.Infof("Please answer with 'y' or 'n'")
			}
		}
	}

	// If username could not be determined correctly, ask the user for it and check if it exists
	logger.Infof("Please enter the username the agent will be executed as:")
	scanner.Scan()
	username = scanner.Text()

	// Don't accept root as username
	if username == "root" {
		username = ""
	}

	// Return username
	return username
}

// execWithUserInput executes a given command with multiple user input (it is submitted consecutively when the
// process ask for it). If you use "sudo" in your command, use "sudo -s" instead for better input handling of golang.
// The output is always returned in english.
func execWithUserInput(cmdStr string, userInput []string) (string, error) {

	// Create Command object
	cmd := exec.Command(shellToUse, shellArg, cmdStr)
	cmd.Env = os.Environ()
	cmd.Env = append(cmd.Env, "LC_ALL=C")

	// Create a pipe to stdin
	stdin, errPipe := cmd.StdinPipe()
	if errPipe != nil {
		return "", fmt.Errorf("could not create stdin-pipe for command: %s", errPipe)
	}

	// Create Buffer for saving the output of the shell
	bufOut := new(bytes.Buffer)
	cmd.Stderr = bufOut
	cmd.Stdout = bufOut

	// Start the command
	if errStart := cmd.Start(); errStart != nil {
		return "", fmt.Errorf("could not start: %s", errStart)
	}

	// Write to the pipe
	for _, input := range userInput {
		_, errWr := stdin.Write([]byte(input + "\n")) // Add \n to submit
		if errWr != nil {
			return "", fmt.Errorf("could not write to stdin-pipe of command: %s", errWr)
		}
	}

	// Execute Command and wait for the shell to ask for input, return output when an error occurred
	errCmd := cmd.Wait()
	if errCmd != nil {
		return "", fmt.Errorf("error while executing command %s: %s: %s", cmdStr, bufOut.String(), errCmd)
	}

	// Command succeeded, return output
	return bufOut.String(), nil
}

// getUnixFlagsWindows extracts unix file permissions of a file. On Linux systems, this can already be done directly
// by the file crawler. On Windows this needs to be done additionally.
func (s *Scanner) getUnixFlagsWindows(exportName string, exportResults *filecrawler.Result) {
	return
}
