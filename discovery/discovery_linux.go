/*
* GoScans, a collection of network scan modules for infrastructure discovery and information gathering.
*
* Copyright (c) Siemens AG, 2016-2026.
*
* This work is licensed under the terms of the MIT license. For a copy, see the LICENSE file in the top-level
* directory or visit <https://opensource.org/licenses/MIT>.
*
 */

package discovery

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/siemens/GoScans/utils"
)

// Linux implementation of discovery scan setup
func setupOs(logger utils.Logger, nmapDir string, nmap string) error {

	// Check for Admin rights
	if !utils.IsElevated() {
		return fmt.Errorf("insufficient privileges")
	}

	// Set necessary root capabilities for nmap
	logger.Infof("Setting root capabilities to allow Nmap for normal users.")
	_, errCapabilities := exec.Command(
		"setcap",
		"cap_net_raw,cap_net_admin,cap_net_bind_service+eip",
		nmap,
	).Output()
	if errCapabilities != nil {
		return fmt.Errorf("could not set root capabilities for Nmap: %s", errCapabilities)
	}

	// Set cap_net_raw on the agent binary for OT discovery protocols (PROFINET DCP, EtherCAT, LLDP)
	// that require raw sockets without running the entire agent as root.
	logger.Infof("Setting raw socket capabilities on agent for OT discovery.")
	agentBin, errAgentBin := os.Executable()
	if errAgentBin != nil {
		return fmt.Errorf("could not determine agent path: %s", errAgentBin)
	}
	_, errAgentCap := exec.Command("setcap", "cap_net_raw+ep", agentBin).Output()
	if errAgentCap != nil {
		return fmt.Errorf("could not set raw socket capabilities for agent: %s", errAgentCap)
	}

	// Return nil as everything went fine
	return nil
}

// Linux implementation of discovery scan setup check
func checkSetupOs(nmapDir string, nmap string) error {

	// Verify whether root capabilities are set for nmap executable
	result, errResult := exec.Command(
		"setcap",
		"-v",
		"cap_net_raw,cap_net_admin,cap_net_bind_service+eip",
		nmap,
	).Output()
	if errResult != nil {
		return fmt.Errorf("could not check root capabilities for Nmap: %s", errResult)
	} else if !strings.Contains(strings.Trim(string(result), "\n"), ": OK") {
		return fmt.Errorf("root capabilities are not set for Nmap: %s", result)
	}

	// Verify whether raw socket capabilities are set for the agent binary (required for OT discovery)
	agentBin, errAgentBin := os.Executable()
	if errAgentBin != nil {
		return fmt.Errorf("could not determine agent binary path: %s", errAgentBin)
	}
	resultAgent, errResultAgent := exec.Command("setcap", "-v", "cap_net_raw+ep", agentBin).Output()
	if errResultAgent != nil {
		return fmt.Errorf("could not check raw socket capabilities for agent: %s", errResultAgent)
	} else if !strings.Contains(strings.Trim(string(resultAgent), "\n"), ": OK") {
		return fmt.Errorf("raw socket capabilities are not set for agent: %s", resultAgent)
	}

	// Set ENV variable to instruct Nmap to make use of root capabilities
	// ATTENTION: This cannot be done in setupOs(), because it would be set in the wrong environment,
	// 			  it must be done in the environment the command is executed within!
	errEnv := os.Setenv("NMAP_PRIVILEGED", "")
	if errEnv != nil {
		return fmt.Errorf("environment variable 'NMAP_PRIVILEGED' not set: %s", errEnv)
	}

	// Check ENV variable instructing Nmap to make use of root capabilities
	_, ok := os.LookupEnv("NMAP_PRIVILEGED")
	if !ok {
		return fmt.Errorf("environment variable 'NMAP_PRIVILEGED' missing")
	}

	// Return nil as everything went fine
	return nil
}
