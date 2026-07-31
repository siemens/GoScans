/*
* GoScans, a collection of network scan modules for infrastructure discovery and information gathering.
*
* Copyright (c) Siemens AG, 2016-2026.
*
* This work is licensed under the terms of the MIT license. For a copy, see the LICENSE file in the top-level
* directory or visit <https://opensource.org/licenses/MIT>.
*
 */

package ssl

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"

	"github.com/siemens/GoScans/utils"
)

var pythonMinVersion = utils.Version{
	Major: 3,
	Minor: 7,
	Patch: 0,
}

// NewScanner initializes a new SSLyze scan. Linux specific implementation, Python and SSLyze package required
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

	// Sanitize target before validation so leading/trailing whitespace does not cause false rejects
	target = strings.TrimSpace(target)

	// Check whether the python path is a real executable and check if the version is sufficient
	args := []string{"--version"}
	cmd := exec.Command(pythonPath, args...)
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	errCmd := cmd.Run()
	if errCmd != nil {
		return nil, fmt.Errorf("'%s %v' could not be executed: %s: %s", pythonPath, args, errCmd, stderr.String())
	}

	// Trim the Python version number
	pythonVersionStr := strings.Trim(strings.TrimPrefix(out.String(), "Python "), "\n\t\r ")

	// Parse version from string
	pythonVersion, errPythonVersion := utils.NewVersion(pythonVersionStr)
	if errPythonVersion != nil {
		return nil, fmt.Errorf(
			"could not parse Python version '%s', please update to '%s'",
			pythonVersionStr,
			pythonMinVersion.String(),
		)
	}

	// Check if the Python version is up-to-date
	if !pythonVersion.IsGreaterEqualThan(pythonMinVersion) {
		return nil, fmt.Errorf(
			"insufficient Python version '%s', please update to '%s'",
			pythonVersionStr,
			pythonMinVersion.String(),
		)
	}

	// Check whether we can execute the SSLyze library and retrieve the version
	args = []string{"-m", "sslyze", "--help"}
	cmd = exec.Command(pythonPath, args...)
	out.Reset()
	stderr.Reset()
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	errCmd2 := cmd.Run()
	if errCmd2 != nil {
		return nil, fmt.Errorf("'%s %v' could not be executed: %s: %s", pythonPath, args, errCmd2, stderr.String())
	}

	// Build version string based on output
	msgHelp := out.String()
	sslyzeVersion, errSslyzeVersion := parseSslyzeVersion(msgHelp)
	if errSslyzeVersion != nil {
		return nil, errSslyzeVersion
	}

	// Check if the SSLyze version is up-to-date
	if !sslyzeVersion.IsGreaterEqualThan(sslyzeMinVersion) {
		return nil, fmt.Errorf(
			"insufficient SSLyze version '%s', please update to '%s'",
			sslyzeVersion.String(),
			sslyzeMinVersion.String(),
		)
	}

	// Initialize and return actual scanner
	return newScanner(
		logger,
		pythonPath,
		[]string{"-m", "sslyze"},
		sslyzeAdditionalTruststore,
		sslyzeVersion,
		target,
		port,
		vhosts,
	)
}
