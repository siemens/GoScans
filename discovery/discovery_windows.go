/*
* GoScans, a collection of network scan modules for infrastructure discovery and information gathering.
*
* Copyright (c) Siemens AG, 2016-2021.
*
* This work is licensed under the terms of the MIT license. For a copy, see the LICENSE file in the top-level
* directory or visit <https://opensource.org/licenses/MIT>.
*
 */

package discovery

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/noneymous/go-redistributable-checker"
	"go-scans/utils"
	"golang.org/x/sys/windows/registry"
	"os/exec"
	"path/filepath"
	"strings"
)

var errNpcapPermission = fmt.Errorf("NPcap is set to admin only")

// Windows implementation of discovery scan setup
func setupOs(logger utils.Logger, nmapDir, nmap string) error {

	// Check for Admin rights
	if !utils.IsElevated() {
		return fmt.Errorf("insufficient privileges")
	}

	// Build Nmap path, required for Windows firewall
	errNmapPath := utils.IsValidExecutable(nmap, "-h") // args required
	if errNmapPath != nil {
		return fmt.Errorf("could not find Nmap executable: %s", nmap)
	}

	// Configure Windows firewall
	logger.Infof("Setting firewall to allow Nmap '%s'.", nmap)
	errFw := SetNmapFirewall(nmap)
	if errFw != nil {
		return fmt.Errorf("could not add Nmap firewall rule: %s", errFw)
	}

	// Calculate Nmap dir
	errNmapDir := utils.IsValidFolder(nmapDir)
	if errNmapDir != nil {
		return fmt.Errorf("could calculate Nmap directory")
	}

	// Import Nmap performance patch for Windows registry
	patchFile := filepath.Join(nmapDir, "nmap_performance.reg")
	logger.Infof("Applying Nmap performance patch '%s'.", patchFile)
	errReg := ImportRegistryFile(patchFile)
	if errReg != nil {
		return fmt.Errorf("could not apply Nmap performance patch: %s", errReg)
	}

	// Check if Npcap is available, if so the admin-only mode has to be deactivated.
	errNpcap := CheckNpcap()
	if errNpcap == nil {

		// Set the Admin-only field to false, otherwise every instance of Nmap (and therefore Npcap) has to run with
		// elevated privileges.
		logger.Infof("Allowing Npcap for normal users.")
		errNoAdmin := SetNpcapNoAdmin()
		if errNoAdmin != nil {
			return fmt.Errorf("could not grant Npcap rights: %s", errNoAdmin)
		}
	}

	// Return nil as everything went fine
	return nil
}

// Windows implementation of discovery scan setup check
func checkSetupOs(nmapDir, nmap string) error {

	// Build Nmap path, required for Windows firewall
	errNmapPath := utils.IsValidExecutable(nmap, "-h") // args required
	if errNmapPath != nil {
		return fmt.Errorf("could not find Nmap executable: %s, %s", nmap, errNmapPath)
	}

	// Check if Nmap is whitelisted on firewall under Windows
	errFw := CheckNmapFirewall(nmap)
	if errFw != nil {
		return errFw
	}

	// Check if Nmap performance patch is applied under Windows
	errPatch := CheckNmapPerformancePatch()
	if errPatch != nil {
		return errPatch
	}

	// Check if Winpcap or Npcap is installed
	errWinpcap := CheckWinpcap()
	if errWinpcap != nil {
		if errNpcap := CheckNpcap(); errNpcap != nil {
			if errors.Is(errNpcap, errNpcapPermission) {
				return errNpcapPermission
			} else {
				return fmt.Errorf("either WinPcap or Npcap must be installed")
			}
		}
	}

	// Check if Visual studio redistributable required by Nmap are installed
	installed1 := redistributable.IsInstalled(redistributable.VC2013x86)
	installed2 := redistributable.IsInstalled(redistributable.VC2015to2019x86)
	if !installed1 && !installed2 {
		return fmt.Errorf("'Microsoft Visual C++ 2013 Redistributable (x86)' required by Nmap")
	}

	// Return nil as everything went fine
	return nil
}

func CheckWinpcap() error {

	// Define command
	cmd := "wmic"
	args := []string{"Service", "get", "pathname"}

	// Run command
	out, err := exec.Command(cmd, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s", out)
	}

	// Search command for Nmap executable
	// Keep it simple, if the right path to the executable is found, it was probably set by us and is set to "allow"
	if !strings.Contains(strings.ToLower(string(out)), "winpcap") {
		return fmt.Errorf("WinPcap not installed")
	}

	return nil
}

func CheckNpcap() error {

	// Look for the executable path. It should be sufficient to find any string, as long as the entry is existing.
	// Derived this from the Npcap installer. (https://github.com/nmap/npcap/blob/master/installer/CheckStatus.bat)
	path1 := `SOFTWARE\WOW6432Node\Npcap`
	path2 := `SOFTWARE\Npcap`

	// Check the first possible path
	_, errNpcap1 := GetRegistryStringValue(registry.LOCAL_MACHINE, path1, "") // The default key
	if errNpcap1 != nil {

		// Check the second possible path
		_, errNpcap2 := GetRegistryStringValue(
			registry.LOCAL_MACHINE,
			path2,
			"", // The default key
		)

		if errNpcap2 != nil {
			return fmt.Errorf("NPcap not installed")
		}
	}

	// Check that Npcap is NOT set to admin only mode. Otherwise every new nmap scan would ask for admin authentication.
	errAdminOnly := CheckRegistryIntValue(
		registry.LOCAL_MACHINE,
		`SOFTWARE\WOW6432Node\Npcap`,
		"AdminOnly",
		0,
	)
	if errAdminOnly != nil {
		return errNpcapPermission
	}

	return nil
}

func SetNpcapNoAdmin() error {

	// Look for the executable path. It should be sufficient to find any string, as long as the entry is existing.
	// Derived this from the Npcap installer. (https://github.com/nmap/npcap/blob/master/installer/CheckStatus.bat)
	path1 := `SOFTWARE\WOW6432Node\Npcap`
	path2 := `SOFTWARE\Npcap`

	errAdminOnly1 := SetRegistryIntValue(
		registry.LOCAL_MACHINE,
		path1,
		"AdminOnly",
		0,
	)

	// Check the second path if the first one resulted in an error.
	if errAdminOnly1 != nil {
		errAdminOnly2 := SetRegistryIntValue(
			registry.LOCAL_MACHINE,
			path2,
			"AdminOnly",
			0,
		)
		return fmt.Errorf("could not set Npcap values in registry for either paths:"+
			"\n\t- 'SOFTWARE\\WOW6432Node\\Npcap': %s"+
			"\n\t- 'SOFTWARE\\Npcap':              '%s'", errAdminOnly1, errAdminOnly2,
		)
	}

	return nil
}

func ImportRegistryFile(filePath string) error {
	return utils.Execute("reg", []string{"import", filePath})
}

func CheckNmapPerformancePatch() error {
	msg := "performance patch (nmap_performance.reg) not applied"

	errCheck1 := CheckRegistryIntValue(
		registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Services\Tcpip\Parameters`,
		"MaxUserPort",
		65534,
	)
	if errCheck1 != nil {
		return fmt.Errorf(msg)
	}

	errCheck2 := CheckRegistryIntValue(
		registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Services\Tcpip\Parameters`,
		"TcpTimedWaitDelay",
		30,
	)
	if errCheck2 != nil {
		return fmt.Errorf(msg)
	}

	errCheck3 := CheckRegistryIntValue(
		registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Services\Tcpip\Parameters`,
		"StrictTimeWaitSeqCheck",
		1,
	)
	if errCheck3 != nil {
		return fmt.Errorf(msg)
	}

	// Return nil if everything is fine
	return nil
}

// CheckRegistryIntValue will try to retrieve the integer associated with the provided full-path (root + path) and key
// and compare it to the provided value.
func CheckRegistryIntValue(root registry.Key, path, key string, value int) error {

	// Retrieve the value from the registry
	val, errGet := GetRegistryIntValue(root, path, key)
	if errGet != nil {
		return errGet
	}

	// Return validation result or error
	if val == uint64(value) {
		return nil
	}

	return fmt.Errorf("registry value for '%s' does not match ('%d' != '%d')", key, val, value)
}

// GetRegistryIntValue will try to retrieve the integer of the registry entry corresponding to the provided
// full-path (root + path) and key.
func GetRegistryIntValue(root registry.Key, path, key string) (uint64, error) {

	// Attach to registry
	k, errOpen := registry.OpenKey(root, path, registry.QUERY_VALUE)
	if errOpen != nil {
		return 0, errOpen
	}

	// Make sure registry key gets closed on exit
	defer func() { _ = k.Close() }()

	// Read value
	val, _, errGet := k.GetIntegerValue(key)
	if errGet != nil {
		return 0, errGet
	}

	return val, nil
}

// GetRegistryIntValue will try to retrieve the string of the registry entry corresponding to the provided
// full-path (root + path) and key.
func GetRegistryStringValue(root registry.Key, path, key string) (string, error) {

	// Attach to registry
	k, errOpen := registry.OpenKey(root, path, registry.QUERY_VALUE)
	if errOpen != nil {
		return "", errOpen
	}

	// Make sure registry key gets closed on exit
	defer func() { _ = k.Close() }()

	// Read value
	val, _, errGet := k.GetStringValue(key)
	if errGet != nil {
		return "", errGet
	}

	return val, nil
}

// SetRegistryIntValue will try to set the registry entry corresponding to the provided full-path (root + path) and key
// to the provided value.
func SetRegistryIntValue(root registry.Key, path, key string, value uint32) error {

	// Attach to registry
	k, errOpen := registry.OpenKey(root, path, registry.SET_VALUE)
	if errOpen != nil {
		return errOpen
	}

	// Make sure registry key gets closed on exit
	defer func() { _ = k.Close() }()

	// Read value
	errGet := k.SetDWordValue(key, value)
	if errGet != nil {
		return errGet
	}

	return nil
}

func CheckNmapFirewall(nmap string) error {

	// Define command
	cmd := "netsh"
	args := []string{"Advfirewall", "firewall", "show", "rule", "all", "verbose"}

	// Run command
	out, err := exec.Command(cmd, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s", out)
	}

	// Search command for Nmap executable
	// Keep it simple, if the right path to the executable is found, it was probably set by us and is set to "allow"
	match := []byte(nmap)
	if !bytes.Contains(out, match) {
		return fmt.Errorf("no firewall approval for Nmap")
	}

	// Return nil if everything is okay
	return nil
}

func SetNmapFirewall(nmap string) error {

	// Check if the path is absolute, if not making a firewall rule is not possible
	if !filepath.IsAbs(nmap) {
		fmt.Errorf("expected absolute path for firewall rule, but '%s' is relative", nmap)
	}

	// Delete old firewall rule by name. If it returns an error there is no old rule
	_ = utils.Execute("netsh", []string{
		"Advfirewall",
		"firewall",
		"delete",
		"rule",
		fmt.Sprintf("name=%s", firewallRuleName),
		"profile=any",
		"protocol=any",
		"direction=in",
	})

	// Create new rule. This might fail without Admin process privileges
	err := utils.Execute("netsh", []string{
		"Advfirewall",
		"firewall",
		"Add",
		"rule",
		"action=allow",
		"enable=yes",
		fmt.Sprintf("name=%s", firewallRuleName),
		"profile=any",
		"protocol=any",
		"direction=in",
		fmt.Sprintf("program=%s", nmap),
	})

	// Return error or nil
	return err
}
