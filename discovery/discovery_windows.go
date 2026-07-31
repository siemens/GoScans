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
	"bytes"
	"debug/pe"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/noneymous/go-redistributable-checker"
	"github.com/siemens/GoScans/utils"
	"golang.org/x/sys/windows/registry"
)

// errNpcapPermission indicates insufficient permission to access Npcap
var errNpcapPermission = fmt.Errorf("NPcap is set to admin only")

// Windows implementation of discovery scan setup
func setupOs(logger utils.Logger, nmapDir, nmap string) error {

	// Check for Admin rights
	if !utils.IsElevated() {
		return fmt.Errorf("insufficient privileges")
	}

	// Check the Nmap runtime before trying to execute Nmap, so a missing DLL produces an actionable error.
	errRedistributable := checkNmapRedistributable(nmap)
	if errRedistributable != nil {
		return errRedistributable
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

	// Check the Nmap runtime before trying to execute Nmap, so a missing DLL produces an actionable error.
	errRedistributable := checkNmapRedistributable(nmap)
	if errRedistributable != nil {
		return errRedistributable
	}

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

	// Return nil as everything went fine
	return nil
}

// checkNmapRedistributable verifies the Visual C++ runtime required by Nmap
func checkNmapRedistributable(nmapPath string) error {

	// Read the runtime version before trying to execute Nmap
	version, errVersion := getNmapRedistributableVersion(nmapPath)
	if errVersion != nil || version == 0 {
		return errVersion
	}

	// Official Windows Nmap 7.50 and newer builds require the x86 runtime
	installed, errInstalled := redistributable.IsInstalled(version, redistributable.ArchitectureX86)
	if errInstalled != nil {
		return errInstalled
	}
	if !installed {
		return fmt.Errorf(
			"missing Microsoft Visual C++ %s Redistributable (x86) required by Nmap",
			version,
		)
	}

	// Return nil as everything went fine
	return nil
}

// getNmapRedistributableVersion reads the runtime family imported by Nmap
func getNmapRedistributableVersion(nmapPath string) (redistributable.Version, error) {

	// Open Nmap as PE without executing it
	nmapPe, errNmapPe := pe.Open(nmapPath)
	if errNmapPe != nil {
		return 0, fmt.Errorf("could not inspect Nmap executable '%s': %w", nmapPath, errNmapPe)
	}
	defer func() { _ = nmapPe.Close() }()

	// Read and map its imported runtime
	imports, errImports := nmapPe.ImportedSymbols()
	if errImports != nil {
		return 0, fmt.Errorf("could not inspect Nmap executable imports '%s': %w", nmapPath, errImports)
	}

	// Return the detected runtime
	return findNmapRedistributableVersion(imports), nil
}

// findNmapRedistributableVersion maps Nmap imports to the supported runtime families
func findNmapRedistributableVersion(imports []string) redistributable.Version {

	// Return the first supported runtime
	for _, imported := range imports {
		library := strings.ToLower(imported[strings.LastIndex(imported, ":")+1:])
		switch library {
		case "msvcp120.dll", "msvcr120.dll":
			return redistributable.Version2013
		case "concrt140.dll", "msvcp140.dll", "msvcp140_1.dll", "msvcp140_2.dll",
			"vcruntime140.dll", "vcruntime140_1.dll":
			return redistributable.VersionV14
		}
	}

	// Return zero when no redistributable is required
	return 0
}

// CheckWinpcap checks whether WinPcap is installed on the system.
func CheckWinpcap() error {

	// Define command
	cmd := "wmic"
	args := []string{"Service", "get", "pathname"}

	// Run command
	out, errOut := exec.Command(cmd, args...).CombinedOutput()
	if errOut != nil {
		return fmt.Errorf("%s", out)
	}

	// Search command for Nmap executable
	// Keep it simple, if the right path to the executable is found, it was probably set by us and is set to "allow"
	if !strings.Contains(strings.ToLower(string(out)), "winpcap") {
		return fmt.Errorf("WinPcap not installed")
	}

	// Return nil as everything went fine
	return nil
}

// CheckNpcap checks whether Npcap is installed and not restricted to admin-only mode.
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

// SetNpcapNoAdmin disables the Npcap admin-only restriction so Nmap can run without elevated privileges.
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

	// Return nil as everything went fine
	return nil
}

// ImportRegistryFile imports the given Windows registry file using the reg.exe tool.
func ImportRegistryFile(filePath string) error {
	return utils.Execute("reg", []string{"import", filePath})
}

// CheckNmapPerformancePatch verifies that the Nmap Windows performance registry patch has been applied.
func CheckNmapPerformancePatch() error {
	msg := "performance patch (nmap_performance.reg) not applied"

	errCheck1 := CheckRegistryIntValue(
		registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Services\Tcpip\Parameters`,
		"MaxUserPort",
		65534,
	)
	if errCheck1 != nil {
		return fmt.Errorf("%s", msg)
	}

	errCheck2 := CheckRegistryIntValue(
		registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Services\Tcpip\Parameters`,
		"TcpTimedWaitDelay",
		30,
	)
	if errCheck2 != nil {
		return fmt.Errorf("%s", msg)
	}

	errCheck3 := CheckRegistryIntValue(
		registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Services\Tcpip\Parameters`,
		"StrictTimeWaitSeqCheck",
		1,
	)
	if errCheck3 != nil {
		return fmt.Errorf("%s", msg)
	}

	// Return nil if everything is fine
	return nil
}

// CheckRegistryIntValue will try to retrieve the integer associated with the provided full-path (root + path) and key
// and compare it to the provided value.
func CheckRegistryIntValue(root registry.Key, path, key string, value int) error {

	// Retrieve the value from the registry
	val, errVal := GetRegistryIntValue(root, path, key)
	if errVal != nil {
		return errVal
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
	k, errK := registry.OpenKey(root, path, registry.QUERY_VALUE)
	if errK != nil {
		return 0, errK
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

// GetRegistryStringValue will try to retrieve the string of the registry entry corresponding to the provided
// full-path (root + path) and key.
func GetRegistryStringValue(root registry.Key, path, key string) (string, error) {

	// Attach to registry
	k, errK := registry.OpenKey(root, path, registry.QUERY_VALUE)
	if errK != nil {
		return "", errK
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
	k, errK := registry.OpenKey(root, path, registry.SET_VALUE)
	if errK != nil {
		return errK
	}

	// Make sure registry key gets closed on exit
	defer func() { _ = k.Close() }()

	// Read value
	errGet := k.SetDWordValue(key, value)
	if errGet != nil {
		return errGet
	}

	// Return nil as everything went fine
	return nil
}

// CheckNmapFirewall verifies that the Windows firewall allows the given Nmap executable path.
func CheckNmapFirewall(nmap string) error {

	// Define command
	cmd := "netsh"
	args := []string{
		"Advfirewall",
		"firewall",
		"show",
		"rule",
		fmt.Sprintf("name=\"%s\"", firewallRuleName), // Some antivirus might silently kill the process if *all* rules are queried
		"verbose",
	}

	// Run command
	out, errOut := exec.Command(cmd, args...).CombinedOutput()
	if errOut != nil {
		return fmt.Errorf("%s", out)
	}

	// Search command for Nmap executable
	// Keep it simple, if the right path to the executable is found, it was probably set by us and is set to "allow"
	match := []byte(nmap)
	if !bytes.Contains(out, match) {
		return fmt.Errorf("no firewall approval for Nmap")
	}

	// Return nil if everything went fine
	return nil
}

// SetNmapFirewall creates or updates the Windows firewall rule that permits the given Nmap executable.
func SetNmapFirewall(nmap string) error {

	// Check if the path is absolute, if not making a firewall rule is not possible
	if !filepath.IsAbs(nmap) {
		return fmt.Errorf("expected absolute path for firewall rule, but '%s' is relative", nmap)
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
	errExecute := utils.Execute("netsh", []string{
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
	return errExecute
}
