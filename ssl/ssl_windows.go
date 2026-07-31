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

// NewScanner initializes a new SSLyze scan. Windows specific implementation, SSLyze executable path required
func NewScanner(
	logger utils.Logger,
	sslyzePath string,
	sslyzeAdditionalTruststore string, // SSLyze always applies default CAs, but you can add additional ones via custom trust store
	target string,
	port int,
	vhosts []string,
) (*Scanner, error) {

	var out bytes.Buffer
	var stderr bytes.Buffer

	// Sanitize target before validation so leading/trailing whitespace does not cause false rejects
	target = strings.TrimSpace(target)

	// Check whether we can execute the SSLyze library and retrieve the help message
	args := []string{"--help"}
	cmd := exec.Command(sslyzePath, args...)
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	errCmd := cmd.Run()
	if errCmd != nil {
		return nil, fmt.Errorf("'%s %v' could not be executed: %s: %s", sslyzePath, args, errCmd, stderr.String())
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
		sslyzePath,
		[]string{},
		sslyzeAdditionalTruststore,
		sslyzeVersion,
		target,
		port,
		vhosts,
	)
}
