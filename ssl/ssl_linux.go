/*
* GoScans, a collection of network scan modules for infrastructure discovery and information gathering.
*
* Copyright (c) Siemens AG, 2016-2021.
*
* This work is licensed under the terms of the MIT license. For a copy, see the LICENSE file in the top-level
* directory or visit <https://opensource.org/licenses/MIT>.
*
 */

package ssl

import (
	"bytes"
	"fmt"
	"github.com/siemens/GoScans/utils"
	"os/exec"
	"strings"
)

var (
	pythonVersion = []int{3, 7, -1}
)

// NewScanner initializes a new SSLyze scan. Linux specific implementation, Python3 and sslyze package required
func NewScanner(
	logger utils.Logger,
	pythonPath string,
	sslyzeAdditionalTruststore string, // Sslyze always applies default CAs, but you can add additional ones via custom trust store
	target string,
	port int,
	vhosts []string,
) (*Scanner, error) {

	var out bytes.Buffer
	var stderr bytes.Buffer

	// Check whether the python path is a real executable and check if the version is sufficient
	args := []string{"--version"}
	cmd := exec.Command(pythonPath, args...)
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	errCmd := cmd.Run()
	if errCmd != nil {
		return nil, fmt.Errorf("'%s %v' can not be executed: %s: %s", pythonPath, args, errCmd, stderr.String())
	}

	// Trim the Python version number
	version := strings.Trim(strings.TrimPrefix(out.String(), "Python "), "\n\t\r ")
	versionOk, errVersion := compareVersion(version, pythonVersion)
	if errVersion != nil {
		return nil, fmt.Errorf("could not validate the Python version '%s': %s", out.String(), errVersion)
	}

	// Check if the Python version is up-to-date
	if !versionOk {
		return nil, fmt.Errorf("insufficient Python version '%s', please update to '%s'",
			version, versionSliceToString(pythonVersion))
	}

	// Check whether we can execute the sslyze library and retrieve the version
	args = []string{"-m", "sslyze", "--help"}
	cmd = exec.Command(pythonPath, args...)
	out.Reset()
	stderr.Reset()
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	errCmd = cmd.Run()
	if errCmd != nil {
		return nil, fmt.Errorf("'%s %v' can not be executed: %s: %s", pythonPath, args, errCmd, stderr.String())
	}

	// Trim the SSLyze version number
	version = strings.Trim(strings.Trim(out.String(), "\n\t\r "), "\n\t\r ")
	versionOk, errVersion = compareVersion(version, sslyzeVersion)
	if errVersion != nil {
		return nil, fmt.Errorf("could not validate the SSLyze version '%s': %s", version, errVersion)
	}

	// Check if the SSLyze version is up-to-date
	if !versionOk {
		return nil, fmt.Errorf(
			"insufficient SSLyze version '%s', please update to '%s'",
			version,
			versionSliceToString(sslyzeVersion),
		)
	}

	// Initialize and return actual scanner
	return newScanner(
		logger,
		pythonPath,
		[]string{"-m", "sslyze"},
		sslyzeAdditionalTruststore,
		target,
		port,
		vhosts,
	)
}
