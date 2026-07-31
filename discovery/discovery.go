/*
* GoScans, a collection of network scan modules for infrastructure discovery and information gathering.
*
* Copyright (c) Siemens AG, 2016-2026.
*
* This work is licensed under the terms of the MIT license. For a copy, see the LICENSE file in the top-level
* directory or visit <https://opensource.org/licenses/MIT>.
*
 */

// Package discovery implements a host discovery scan module using Nmap and related protocols.
package discovery

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/Ullaakut/nmap/v3"
	"github.com/siemens/GoScans/discovery/ad"
	"github.com/siemens/GoScans/discovery/netapi"
	"github.com/siemens/GoScans/discovery/ot"
	"github.com/siemens/GoScans/utils"
)

const Label = "Discovery"           // Scan-module label
const firewallRuleName = "Nmap-LSD" //lint:ignore U1000 used in discovery_windows.go, invisible on Linux builds

// defaultScriptsOnce ensures the default script list is initialized once
var defaultScriptsOnce sync.Once
var defaultScripts = []string{ // List of default scripts to be executed
	"smb-os-discovery",    // Might leak DNS name information
	"ssl-cert",            // Might leak DNS name information
	"http-ntlm-info",      // Might leak DNS name information
	"rdp-ntlm-info",       // Might leak DNS name information
	"telnet-ntlm-info",    // Might leak DNS name information
	"smtp-ntlm-info",      // Might leak DNS name information
	"pop3-ntlm-info",      // Might leak DNS name information
	"imap-ntlm-info",      // Might leak DNS name information
	"ms-sql-ntlm-info",    // Might leak DNS name information
	"rdp-enum-encryption", // RDP is a common service and this script will enumerate its security settings
}

// defaultScriptsMissing contains unavailable default scripts that require a warning
var defaultScriptsMissing []string

// Global throttles that need to hold across all parallel scan tasks
var chThrottleGlobalDns = make(chan struct{}, 100) // Max number of parallel DNS queries
var chThrottleGlobalAd = make(chan struct{}, 100)  // Max number of parallel Active Directory queries

// Setup configures the environment accordingly, if the scan module has some special requirements. A successful setup
// is required before a scan can be started.
func Setup(logger utils.Logger, nmapDir string, nmapPath string) error {

	// Execute setup with OS specific implementation
	errOsDependant := setupOs(logger, nmapDir, nmapPath)
	if errOsDependant != nil {
		return errOsDependant
	}

	// Check default scripts availability
	errScripts := initDefaultScripts(nmapPath)
	if errScripts != nil {
		return errScripts
	}

	// Return nil as everything went fine
	return nil
}

// CheckSetup checks whether Setup() executed accordingly. Scan arguments should be checked by the scanner.
func CheckSetup(nmapDir, nmapPath string) error {

	// Check setup with OS specific implementation
	errOsDependant := checkSetupOs(nmapDir, nmapPath)
	if errOsDependant != nil {
		return errOsDependant
	}

	// Return nil as everything went fine
	return nil
}

// Script holds the result of a single Nmap script execution associated with a host or port.
type Script struct {
	Type     string
	Port     int
	Protocol string
	Name     string
	Result   string
}

// Service holds information about a single network service detected on a scanned host.
type Service struct {
	Port       int
	Protocol   string
	Name       string // ATTENTION: Nmap sometimes uses the tunnel attribute (XML output) to indicate an encrypted service port.
	Tunnel     string // ATTENTION: Nmap sometimes describes a service like "https" as "http" in combination with the tunnel attribute set to "SSL"!
	Product    string
	Version    string
	DeviceType string
	Flavor     string
	Cpes       []string // "Common Platform Enumeration" describes platform indicated by the Service
	Info       string
	Method     string // Detection method used by Nmap
	Ttl        int    // TTL to Service. If host has ports with different TTL there might be port forwarding active
}

// Host holds all discovered information about a single scanned network host.
type Host struct {
	MacAddress      string
	Ip              string
	DnsName         string
	OtherNames      []string
	OtherIps        []string
	Hops            []string // Traceroute hops to the target host
	OsGuesses       []string
	OsSmb           string
	LastBoot        time.Time
	Uptime          time.Duration
	DetectionReason string // Reason why Nmap considers this host "up"
	AdminUsers      []string
	RdpUsers        []string
	Services        []Service // mapping port to Service result
	Scripts         []Script  // list of Script results

	Company    string // Optional attribute that could be filled by the agent with asset inventory information
	Department string // Optional attribute that could be filled by the agent with asset inventory information
	Owner      string // Optional attribute that could be filled by the agent with asset inventory information
	Critical   bool   // Optional attribute that could be filled by the agent with asset inventory information

	Ad *ad.Ad
}

// Result holds the complete output of a discovery scan, including all found hosts and a final status.
type Result struct {
	Data      []*Host
	Status    string // Final scan status (success or graceful error). Should be stored along with the scan results.
	Exception bool   // Indicates if something went wrong badly and results shall be discarded. This should never be
	// true, because all errors should be handled gracefully. Logging an error message should always precede setting
	// this flag! This flag may Additionally come along with a message put into the status attribute.
}

// ldapConf groups all LDAP/Active Directory connection parameters passed to a scanner instance.
type ldapConf struct {
	ldapServer    string // (Optional) Active Directory server to query host details
	ldapDomain    string // (Optional) Active Directory access credentials (Domain only required and used as realm for GSSAPI authentication (Kerberos))
	ldapUser      string // (Optional) Active Directory access credentials
	ldapPassword  string // (Optional) Active Directory access credentials
	disableGssapi bool   // Flag to disable GssApi
}

// Scanner wraps an Nmap process and coordinates all host discovery sub-tasks for a single scan run.
type Scanner struct {
	Label             string
	Started           time.Time
	Finished          time.Time
	logger            utils.Logger  // Can be any logger implementing our minimalistic interface. Wrap your logger to satisfy the interface, if necessary (like utils.LoggerTest).
	targetDescription string        // Target to be scanned by Nmap (might be IPv4, IPv6, Hostname or range)
	domainOrder       []string      // List of potential (sub) domains, ordered by plausibility. This is used to choose the most likely discovered DNS name. E.g. allows to select domain.internal over domain.com.
	nmapPath          string        // Path to the Nmap executable
	nmapParameters    []string      // List of Nmap scan arguments
	nmapVersionAll    bool          // Toggle to enable/disable extensive version detection
	nmapBlacklistFile string        // Path to blacklist list of targets to be skipped at any case
	otScanner         *ot.Scanner   // Filling out this attribute enables OT discovery scan. This is required to execute L2 OT discovery scripts. Leave empty to skip executing additional OT-related NSE scripts.
	ldapConf          ldapConf      // Struct holding LDAP configuration data, ready to be passed on as single value
	excludeDomains    []string      // Domains to be ignored when discovered
	dialTimeout       time.Duration // The duration a dial is allowed to take before it will be canceled.

	proc          *nmap.Scanner      // Actual Nmap scanner object to be executed
	procInputs    map[string]string  // Map of original input hostnames
	procCtx       context.Context    // Context for managing scan lifecycle and cancellation
	procCtxCancel context.CancelFunc // Function to cancel scan context
}

func NewScanner(
	logger utils.Logger, // Can be any logger implementing our minimalistic interface. Wrap your logger to satisfy the interface, if necessary (like utils.LoggerTest).
	targets []string,
	nmapPath string,
	nmapArgs []string,
	nmapVersionAll bool,
	nmapBlacklist []string, // Single blacklist targets
	nmapBlacklistFile string, // File with list of blacklist targets. Can be combined with nmapBlacklist
	domainOrder []string, // (Sub) domains ordered by plausibility
	ldapServer string, // Only required if you want to connect to a static LDAP server for looking up additional AD data
	ldapDomain string, // Only required and used as realm for GSSAPI authentication (Kerberos)
	ldapUser string, // Implicit authentication will be used on domain-joined Windows machines. Otherwise, explicit authentication is required. No AD lookups will be done if neither is possible.
	ldapPassword string, // Implicit authentication will be used on domain-joined Windows machines. Otherwise, explicit authentication is required. No AD lookups will be done if neither is possible.
	disableGssapi bool, // Allows to disable GSSAPI and fall back to standard credentials authentication
	excludeDomains []string, // Domains to be ignored when discovered
	dialTimeout time.Duration, // Timeout for e.g. AD queries to enrich data (used AD fqdn might not exist)
) (*Scanner, error) {

	// Prepare map of original input hostnames referenced by IP for later lookup
	targetsOriginal := make(map[string]string, len(targets))

	// Check whether input target is valid
	for _, target := range targets {

		// Sanitize target before validation so leading/trailing whitespace does not cause false rejects
		target = strings.TrimSpace(target)

		// Check whether input target is valid
		if !utils.IsValidAddress(target) && !utils.IsValidIpRange(target) {
			return nil, fmt.Errorf("invalid target '%s'", target)
		}

		// Resolve hostname's IP addresses and remember associations
		if utils.IsValidHostname(target) {
			if ips, errIps := net.LookupIP(target); errIps == nil {
				for _, ip := range ips {
					targetsOriginal[ip.String()] = target
				}
			}
		}
	}

	// Check whether LDAP server is plausible
	ldapServer = strings.ToLower(ldapServer)
	if strings.HasPrefix(ldapServer, "http://") ||
		strings.HasPrefix(ldapServer, "https://") {
		return nil, fmt.Errorf("invalid LDAP server '%s'", ldapServer)
	}

	// Check whether given credentials are plausible
	if !utils.ValidOrEmptyCredentials(ldapDomain, ldapUser, ldapPassword) {
		return nil, fmt.Errorf("ldap credentials incomplete")
	}

	// Build Nmap path. "nmapExecutable" will be taken from the OS-specific Golang-file during compilation.
	errNmapExec := utils.IsValidExecutable(nmapPath, "-h") // args required on linux
	if errNmapExec != nil {
		return nil, fmt.Errorf("could not find Nmap executable: %s", nmapPath)
	}

	// Check if Nmap blacklist file can be found and is an actual file (if set)
	if len(nmapBlacklistFile) != 0 {
		if errBlacklist := utils.IsValidFile(nmapBlacklistFile); errBlacklist != nil {
			return nil, errBlacklist
		}
	}

	// Warn about missing scripts
	if len(defaultScriptsMissing) > 0 {
		logger.Warningf(
			"Your Nmap version does not support the following recommended script(s): %s",
			strings.Join(defaultScriptsMissing, ", "),
		)
	}

	// Prepare mandatory args and scripts
	forceArgs := []string{"--reason", "--webxml"}

	// Compile list of Nmap configurations
	var options []nmap.Option
	options = append(options, nmap.WithBinaryPath(nmapPath))
	options = append(options, nmap.WithCustomArguments(nmapArgs...))  //lint:ignore SA1019 needed for raw nmap argument pass-through in security scanning
	options = append(options, nmap.WithCustomArguments(forceArgs...)) //lint:ignore SA1019 needed for raw nmap argument pass-through in security scanning
	options = append(options, nmap.WithScripts(defaultScripts...))
	if nmapVersionAll {
		options = append(options, nmap.WithVersionAll())
	}
	if len(nmapBlacklist) > 0 {
		options = append(options, nmap.WithTargetExclusions(nmapBlacklist...))
	}
	if len(nmapBlacklistFile) != 0 {
		options = append(options, nmap.WithTargetExclusionInput(nmapBlacklistFile))
	}
	options = append(options, nmap.WithTargets(targets...))

	// Prepare scan context with cancel function (useful for Dry Runs)
	ctx, ctxCancel := context.WithCancel(context.Background())

	// Prepare Nmap scan to receive direct feedback in case of errors
	proc, errProc := nmap.NewScanner(ctx, options...)
	if errProc != nil {
		ctxCancel()
		return nil, errProc
	}

	// Initiate scanner with sanitized input values
	scan := Scanner{
		Label,
		time.Time{}, // zero time
		time.Time{}, // zero time
		logger,
		strings.Join(targets, ", "),
		domainOrder,
		nmapPath,
		nmapArgs,
		nmapVersionAll,
		nmapBlacklistFile,
		nil, // Initially, the optional OT discovery scan is disabled. Call EnableOtScanner() to initialize.
		ldapConf{
			ldapServer,
			ldapDomain,
			ldapUser,
			ldapPassword,
			disableGssapi,
		},
		excludeDomains,
		dialTimeout,
		proc,
		targetsOriginal,
		ctx,
		ctxCancel,
	}

	// Return scan struct
	return &scan, nil
}

// EnableOtScanner initializes the OT discovery scanner (PROFINET DCP, EtherCAT, LLDP, etc.)
// and enables OT discovery scanning. A network interface to use for the OT scans must be defined.
// The OT scan can only target a local L2 network segment. sets the network interface for
func (s *Scanner) EnableOtScanner(nwInterface string) error {

	// Initialize OT discovery scanner
	otScanner, errOtScanner := ot.NewScanner(s.logger, nwInterface)
	if errOtScanner != nil {
		return errOtScanner
	}

	// Assign OT discovery scanner to discovery scanner
	s.otScanner = otScanner

	// Return nil as everything went fine
	return nil
}

// Run starts scan execution. This must either be executed as a goroutine, or another thread must be active listening
// on the scan's result channel, in order to avoid a deadlock situation.
// The timeout argument is optional and allows cancelling the scan after a given duration.
// This timeout is intended for dry runs only. For actual scan timeouts, use appropriate Nmap arguments instead.
func (s *Scanner) Run(timeout time.Duration) (res *Result) {

	// Recover potential panics to gracefully shut down scan
	defer func() {
		if r := recover(); r != nil {

			// Log exception with stacktrace
			s.logger.Errorf(fmt.Sprintf("Unexpected error: %s", r))

			// Build error status from error message and formatted stacktrace
			errMsg := fmt.Sprintf("%s%s", r, utils.StacktraceIndented("\t"))

			// Return result set indicating exception
			res = &Result{
				nil,
				errMsg,
				true,
			}
		}
	}()

	// Clean up process context if it hasn't timed out before process completion
	defer s.procCtxCancel()

	// Set scan started flag and calculate deadline
	s.Started = time.Now()
	s.logger.Infof("Started  scan of %s.", s.targetDescription)

	// Optionally cancel via timeout
	if timeout > 0 {
		go func() {
			select {
			case <-s.procCtx.Done():
				// Quit goroutine
			case <-time.After(timeout):
				s.logger.Errorf("Nmap scan of '%s' killed after timeout.", s.targetDescription) // You should preferably make sure Nmap gracefully ends e.g. using --host-timeout
				s.procCtxCancel()                                                               // Cancel proc context and quit goroutine
			}
		}()
	}

	// Execute scan logic
	res = s.execute()

	// Log scan completion message
	s.Finished = time.Now()
	duration := s.Finished.Sub(s.Started).Minutes()
	s.logger.Infof("Finished scan of %s in %fm.", s.targetDescription, duration)

	// Return result set
	return res
}

// initDefaultScripts checks which default Nmap scripts are available and removes unsupported ones from the list.
func initDefaultScripts(nmapPath string) (errScripts error) {

	// Iterate default scripts and remove missing ones
	defaultScriptsOnce.Do(func() {

		// Remove missing scripts (some might not exist in case of outdated nmap versions)
		scriptsAvailable := make([]string, 0, len(defaultScripts))
		scriptsMissing := make([]string, 0, len(defaultScripts))
		for _, script := range defaultScripts {

			// Prepare check for script support
			checkScript, errCheckScript := nmap.NewScanner(
				context.Background(),
				nmap.WithBinaryPath(nmapPath),
				nmap.WithScripts(script),
			)
			if errCheckScript != nil {
				errScripts = fmt.Errorf("could not check script support: %s", errCheckScript)
				return
			}

			// Check script support
			_, _, errScripts = checkScript.Run()
			if strings.Contains(fmt.Sprintf("%s", errScripts), "did not match a category, filename, or directory") {
				scriptsMissing = append(scriptsMissing, script)
			} else {
				scriptsAvailable = append(scriptsAvailable, script)
			}
		}

		// Update global list of forced scripts with available ones
		defaultScripts = scriptsAvailable
		defaultScriptsMissing = scriptsMissing
	})

	// Return nil or error
	return errScripts
}

// execute runs the Nmap scan and all post-processing steps, returning a Result with all discovered hosts.
func (s *Scanner) execute() *Result {

	// Declare result variable to be returned
	var results []*Host // Slice of pointers to host structs, goroutines may alter these structs until completion.

	// Prepare interrupt channel and listen for interrupts
	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, syscall.SIGINT, syscall.SIGTERM) // Keyboard interrupt + Linux termination signal

	// Execute Nmap scan
	result, warnings, errRun := s.proc.Run()

	// Check for nmap errors
	if errRun != nil {

		// Check if nmap terminated with error due to interrupt or by itself
		select {
		case <-interrupt:
			s.logger.Infof("Nmap aborted due to interrupt.")
			return &Result{
				nil,
				utils.StatusFailed,
				false, // Intended shutdown
			}
		default:

			// Handle interrupts (sigint, ctrl+c) that might have slipped through due to a race condition
			// via interrupt channel
			if errors.Is(errRun, nmap.ErrScanInterrupt) {
				s.logger.Infof("Nmap aborted due to interrupt.")
				return &Result{
					nil,
					utils.StatusFailed,
					false, // Intended shutdown
				}
			}

			// Handle scan timeout error, which should not happen in this discovery module, because no global
			// scan timeout is specified. It's rather advised to set scan timeouts indirectly with Nmap's
			// '--host-timeout' attribute.
			if errors.Is(errRun, nmap.ErrScanTimeout) {
				s.logger.Errorf("Scan aborted due to timeout.")
				return &Result{
					nil,
					utils.StatusFailed,
					false, // Intended shutdown
				}
			}

			// Re-check interrupt channel with a short timeout before treating parse errors as
			// exceptions. The non-blocking select above can miss the OS signal due to goroutine
			// scheduling, even though Nmap was already killed by it.
			if errors.Is(errRun, nmap.ErrParseOutput) {
				select {
				case <-interrupt:
					s.logger.Infof("Nmap aborted due to interrupt.")
					return &Result{
						nil,
						utils.StatusFailed,
						false, // Intended shutdown
					}
				case <-time.After(100 * time.Millisecond):
				}
			}

			// Prepare error message
			exceptionMsg := ""
			if errors.Is(errRun, nmap.ErrParseOutput) {
				exceptionMsg = "Nmap output could not be parsed:"
				for _, warning := range *warnings {
					if utils.SubstrContained(warning, []string{ // Skip useless warnings
						"QUITTING!",
						"-- is this port really open?",
					}) {
						continue
					}
					exceptionMsg += fmt.Sprintf("\n%s", warning)
				}
			} else if errors.Is(errRun, nmap.ErrMallocFailed) {
				exceptionMsg = "Nmap could not scan such large target network."
			} else if errors.Is(errRun, nmap.ErrResolveName) { // Critical resolve error only thrown if related to blacklist hosts
				exceptionMsg = "Nmap could not resolve host(s) on exclude list."
			} else {
				exceptionMsg = fmt.Sprintf("Nmap scan failed with unexpected error: %s", errRun)
			}

			// Log the nmap command for debugging (e.g. exit code 1 gives no other context)
			s.logger.Debugf("Nmap command: %s %s", s.nmapPath, strings.Join(s.proc.Args(), " "))

			// Log error message
			s.logger.Errorf(exceptionMsg)

			// Return result set indicating critical error.
			return &Result{
				nil,
				exceptionMsg,
				true,
			}
		}
	}

	// Execute L2 OT discovery scan if configured. Independent of the Nmap IP scan; run here so its
	// findings survive the resolve/blacklist/nil-result checks below.
	hostsOt := make([]ot.Host, 0)
	if s.otScanner != nil {
		s.logger.Debugf("Executing OT discovery on interface '%s'.", s.otScanner.NetworkInterface)
		hostsOt = s.otScanner.Run()

		// Abort early with OT results, if
		//   - OT results have been discovered
		//   - Nmap failed or didn't deliver results
		// There is no need to try to read and post-process Nmap results.
		resultsNmap := result != nil && len(result.Hosts) > 0
		if len(hostsOt) > 0 && !resultsNmap {

			// Append OT discovery results
			results = appendMissingOtHosts(s.logger, hostsOt, nil, nil, results, s.domainOrder, s.excludeDomains)

			// Return pointer to result struct
			s.logger.Debugf("Returning OT scan result.")
			return &Result{
				results,
				utils.StatusCompleted,
				false,
			}
		}
	}

	// Check for nmap warnings that are critical to us
	for _, warning := range *warnings {
		if warning == "" || warning == " " {
			continue
		} else if strings.Contains(warning, "Failed to resolve") { // The same warning is returned if host from blacklist could not be resolved, but in that case an error is already returned and handled above
			s.logger.Debugf("Target could not be resolved.")
			return &Result{
				results,
				utils.StatusNotReachable,
				false,
			}
		} else if strings.Contains(warning, "No targets were specified") { // Comes together with above warning, but standalone if target is on blacklist
			s.logger.Debugf("Target is blacklisted.")
			return &Result{
				results,
				utils.StatusSkipped,
				false,
			}
		} else {
			s.logger.Debugf("Nmap warning: %s", warning)
		}
	}

	// Abort if result is nil, which it should not be at this stage
	if result == nil {
		msg := "No nmap result, although expected!"
		s.logger.Errorf(msg)

		// Return critical error unless OT discovery found devices to report
		return &Result{
			nil,
			msg,
			true,
		}
	}

	// Log successful scan
	s.logger.Debugf("Extracting results for '%s'.", s.targetDescription)

	// Prepare processing throttles and result return channels
	chThrottleUsers := make(chan struct{}, 30)
	chThrottleIps := make(chan struct{}, 30)
	chThrottleSans := make(chan struct{}, 30)

	// Close channels after scan completion
	defer close(chThrottleUsers)
	defer close(chThrottleIps)
	defer close(chThrottleSans)

	// Prepare wait group for post-processing goroutines
	var wgHosts sync.WaitGroup

	// Prepare memory of MAC addresses and IPs found during port scan
	seenMacs := make(map[string]struct{}, 0)
	seenIps := make(map[string]struct{}, 0)

	// Read scan result and fill results structure
	for _, h := range result.Hosts {

		// Prepare memory for host attributes
		var ip string
		var macAddress string

		// Extract Host IP and MAC
		for _, addr := range h.Addresses {
			if ip == "" && addr.AddrType != "mac" { // Extract primary host IP
				ip = addr.String()
			}
			if macAddress == "" && addr.AddrType == "mac" { // Extract MAC address if available (L2 adjacency + privileged scan required)
				macAddress = addr.String()
			}
		}

		// Skip offline Hosts
		if h.Status.State != "up" { // State will ALWAYS be "up" if nmap's host discovery is skipped
			s.logger.Debugf("Skipping '%s' because it is not online.", ip)
			continue
		}

		// Extract host details
		s.logger.Debugf("Extracting host data of '%s'.", ip)
		hostnames, hops, osGuesses, lastBoot, uptime := extractHostData(h)

		// Extract host's services
		s.logger.Debugf("Extracting port data of '%s'.", ip)
		services, hostnamesServices := extractPortData(h.Ports)

		// Extract NSE scripts run against the host
		s.logger.Debugf("Extracting script data of '%s'.", ip)
		scriptsHost, hostnamesScriptsHost, osSmb := extractHostScriptData(h.HostScripts)

		// Extract NSE scripts run against the host's ports
		scriptsPort, hostnamesScriptsPort, sslPorts := extractPortScriptData(h.Ports)

		// Concatenate host and port scripts
		scripts := append(scriptsHost, scriptsPort...)

		// If Nmap host discovery is disabled, all hosts are shown as "up", but we don't want to bloat our
		// Result database with ghost host entries.
		if len(services) == 0 && len(scripts) == 0 {
			s.logger.Debugf("Ignoring unused network address '%s'.", ip)
			continue
		} else {
			s.logger.Debugf("Discovered %d services and %d script outputs at '%s'.",
				len(services), len(scripts), ip)
		}

		// Extract host-related data from OT discovery to enrich Nmap scan results.
		// Devices found during OT discovery but not by Nmap will be injected later.
		var hostnamesOt []string
		var otherIpsOt []string
		if len(hostsOt) > 0 {
			s.logger.Debugf("Extracting OT data of '%s'.", ip)
			for _, hostOt := range hostsOt {
				if (ip != "" && utils.StrContained(ip, hostOt.Ips)) || (macAddress != "" && macAddress == hostOt.MacAddress) {

					// Extract hostnames from OT results
					hostnamesOt = append(hostnamesOt, hostOt.DnsNames...)

					// Extract MAC from OT results, if missing
					if macAddress == "" {
						macAddress = hostOt.MacAddress
					}

					// Extract OS guesses from OT results, if missing
					if len(osGuesses) == 0 {
						osGuesses = hostOt.OsGuesses
					}

					// Extract additional IPs from OT results
					for _, otIp := range hostOt.Ips {
						if otIp != ip {
							otherIpsOt = append(otherIpsOt, otIp)
						}
					}
				}
			}
		}

		// Merge discovered hostnames
		s.logger.Debugf("Merging discovered hostnames of '%s'.", ip)
		hostnames = append(hostnames, hostnamesServices...)
		hostnames = append(hostnames, hostnamesScriptsHost...)
		hostnames = append(hostnames, hostnamesScriptsPort...)
		hostnames = append(hostnames, hostnamesOt...)

		// Add original discovery input hostname if Nmap hasn't discovered it. Nmap first resolves input
		// hostnames to IP addresses and proceeds ignoring the original input hostname. It might not be able to
		// rediscover it throughout the scan.
		originalHostname := s.procInputs[ip]
		if len(originalHostname) != 0 && !utils.StrContained(originalHostname, hostnames) {
			hostnames = append(hostnames, originalHostname)
		}

		// Create host struct
		hData := Host{
			MacAddress:      macAddress,
			Ip:              ip,
			DnsName:         "",         // To be decided later after extracting SANs
			OtherNames:      hostnames,  // To be updated later after deciding DNS name from it
			OtherIps:        otherIpsOt, // Seeded from OT discovery, extended later by OXID Resolver script
			Hops:            hops,
			OsGuesses:       osGuesses,
			OsSmb:           osSmb,
			LastBoot:        lastBoot,
			Uptime:          uptime,
			DetectionReason: h.Status.Reason,
			AdminUsers:      []string{}, // To be added asynchronously later during user extraction
			RdpUsers:        []string{}, // To be added asynchronously later during user extraction
			Services:        services,
			Scripts:         scripts,
			Company:         "",       // To be added asynchronously later by asset inventory lookup
			Department:      "",       // To be added asynchronously later by asset inventory lookup
			Owner:           "",       // To be added asynchronously later by asset inventory lookup
			Ad:              &ad.Ad{}, // To be added asynchronously later by asset AD lookup
		}

		// Add reference of host struct to results. The actual host struct may be altered subsequently by
		// post-processing launched goroutines.
		results = append(results, &hData)

		// Remember MAC addresses and IPs that are now part of the result data
		if macAddress != "" {
			seenMacs[macAddress] = struct{}{}
		}
		if ip != "" {
			seenIps[ip] = struct{}{}
		}

		// Initiate asynchronous post-processing to collect additional host data.
		// This will enrich host results with additional information that can be gathered from the remote host. E.g.,
		// it will do Windows user enumeration, SANs extraction, interface enumeration via OXID Resolver,...
		// Dns validation and Ad extraction will be launched later, once post-processing is completed.
		wgHosts.Add(1)
		go postprocess(
			s.logger,
			&wgHosts,
			&hData, // To be updated in place
			sslPorts,
			s.domainOrder,
			s.excludeDomains,
			s.ldapConf,
			s.dialTimeout,
			chThrottleUsers,
			chThrottleIps,
			chThrottleSans,
		)
	}

	// Wait for post-processing to complete.
	s.logger.Debugf("Waiting for all post-processing to complete.")
	wgHosts.Wait()

	// Injecting missing OT discovery hosts
	if len(hostsOt) > 0 {
		results = appendMissingOtHosts(s.logger, hostsOt, seenMacs, seenIps, results, s.domainOrder, s.excludeDomains)
	}

	// Return pointer to result struct
	s.logger.Debugf("Returning scan result.")
	return &Result{
		results,
		utils.StatusCompleted,
		false,
	}
}

// appendMissingOtHosts iterates available OT scan results and appends hosts whose MAC was not seen before.
// It prefers an IP not already present in the nmap results as the primary IP and runs decideDnsName to
// sanitize and order the OT-discovered hostnames.
func appendMissingOtHosts(
	logger utils.Logger,
	hostsOt []ot.Host,
	seenMacs map[string]struct{},
	seenIps map[string]struct{},
	results []*Host,
	domainOrder []string,
	excludeDomains []string,
) []*Host {

	// Iterating OT data to inject into results
	logger.Debugf("Appending missing OT data.")
	for _, hostOt := range hostsOt {

		// Skip injecting hosts with already existing MAC addresses
		if hostOt.MacAddress != "" {
			if _, seen := seenMacs[hostOt.MacAddress]; seen {
				logger.Debugf("Appending OT data of '%s' skipped. MAC already contained.", hostOt.MacAddress)
				continue
			}
		}

		// Pick a primary IP, preferring one not already in the nmap results to avoid
		// confusing duplicate rows. Falls back to Ips[0] if all IPs are already seen.
		primaryIp := ""
		for _, ip := range hostOt.Ips {
			if _, seen := seenIps[ip]; !seen { // nil map lookup is always false
				primaryIp = ip
				break
			}
		}
		if primaryIp == "" && len(hostOt.Ips) > 0 {
			primaryIp = hostOt.Ips[0]
		}

		// Collect remaining IPs
		var otherIps []string
		for _, ip := range hostOt.Ips {
			if ip != primaryIp {
				otherIps = append(otherIps, ip)
			}
		}

		// Prepare identifier for host
		var identifier string
		if len(hostOt.MacAddress) > 0 {
			identifier = hostOt.MacAddress
		} else if len(hostOt.Ips) > 0 {
			identifier = hostOt.Ips[0]
		} else if len(hostOt.DnsNames) > 0 {
			identifier = hostOt.DnsNames[0]
		}

		// Inject devices exclusively found via OT discovery
		logger.Debugf("Appending OT data of '%s'.", identifier)
		hData := &Host{
			MacAddress: hostOt.MacAddress,
			Ip:         primaryIp,
			OtherNames: hostOt.DnsNames,
			OtherIps:   otherIps,
			Hops:       []string{},
			OsGuesses:  hostOt.OsGuesses,
			Services:   []Service{},
			Scripts:    []Script{},
			Ad:         &ad.Ad{},
		}

		// Decide best DNS name from domain ordering
		logger.Debugf("Deciding DNS name for '%s'.", identifier)
		decideDnsName(hData, domainOrder, excludeDomains) // OT names won't resolve, but this sanitizes and sorts OtherNames

		// Append host to results
		results = append(results, hData)
	}

	// Return the updated results
	return results
}

// extractHostData parses Nmap host-level attributes into discovery-ready values including hostnames, hops, OS guesses, and timing data.
func extractHostData(h nmap.Host) ([]string, []string, []string, time.Time, time.Duration) {

	var hostnames []string
	var hops []string

	// Extract host details
	for _, hostname := range h.Hostnames {
		hostnames = append(hostnames, hostname.String())
	}

	// Extract traceroute hops
	for _, hop := range h.Trace.Hops {
		hops = append(hops, hop.IPAddr)
	}

	// Extract OS matches
	var osGuesses []string
	for _, match := range h.OS.Matches {

		// Simply use the match name and accuracy to describe the os. It's easier to maintain than parsing the cpe
		// string and generating multiple class strings from that. Additionally, there were some instances where the
		// match.Name hold more information than the CPE and class fields.
		osGuesses = append(osGuesses,
			fmt.Sprintf(
				"%d%% %s",
				match.Accuracy,
				match.Name,
			))
	}

	// Extract last boot timestamp
	lastBoot := time.Time(h.StartTime)

	// Extract uptime duration
	uptime := time.Duration(h.Uptime.Seconds) * time.Second

	// Return host details
	return hostnames, hops, osGuesses, lastBoot, uptime
}

// extractPortData converts Nmap port entries into Service structs and collects any hostnames embedded in service data.
func extractPortData(ports []nmap.Port) ([]Service, []string) {
	services := make([]Service, 0, len(ports))
	hostnames := make([]string, 0, len(ports))

	// Extract services
	for _, port := range ports {

		// Skip closed or filtered ports
		if port.State.State != "open" {
			continue
		}

		// Prepare CPE string
		var cpes []string
		for _, cpe := range port.Service.CPEs {
			cpes = append(cpes, string(cpe))
		}

		// Create and append Service struct filled with data
		services = append(services, Service{
			int(port.ID),
			port.Protocol,
			port.Service.Name,
			port.Service.Tunnel, // Sometimes Nmap doesn't set a service to HTTPs, but HTTP in combination with the tunnel attribute set to "SSL"
			port.Service.Product,
			port.Service.Version,
			port.Service.DeviceType,
			port.Service.OSType,
			cpes,
			port.Service.ExtraInfo,
			port.Service.Method,
			int(port.State.ReasonTTL),
		})

		// Remember Hostname if one got discovered along
		if len(port.Service.Hostname) > 0 {
			hostnames = append(hostnames, port.Service.Hostname)
		}
	}

	// Return extracted services
	return services, hostnames
}

// extractHostScriptData parses host-level Nmap script results, extracting Script entries, embedded hostnames, and the SMB OS string.
func extractHostScriptData(hostScripts []nmap.Script) ([]Script, []string, string) {
	var hostnames []string
	var osSmb = ""
	scripts := make([]Script, 0, len(hostScripts))

	// Extract general scripts run against the host
	for _, hostScript := range hostScripts {

		// Create and append service struct with values
		scripts = append(scripts, Script{
			"Host",
			-1,
			"",
			hostScript.ID,
			hostScript.Output,
		})

		// Check smb-os-discovery result for Hostname
		if strings.ToLower(hostScript.ID) == "smb-os-discovery" {

			// Attention: Accessing these two elements is tailored to the 'smb-os-discovery' script and not
			// applicable in general. This approach might also fail in future versions of this script.
			for _, e := range hostScript.Elements {

				// Extract FQDN if found in smb-os-discovery Script output
				if e.Key == "fqdn" && len(e.Value) > 0 {
					hostnames = append(hostnames, e.Value)
				}

				// Extract OS if found in smb-os-discovery Script output
				if e.Key == "os" {
					osSmb = e.Value
				}
			}
		}
	}

	// Return extracted host data
	return scripts, hostnames, osSmb
}

// extractPortScriptData parses port-level Nmap script results, returning Script entries, embedded hostnames, and the list of SSL-enabled port numbers.
func extractPortScriptData(ports []nmap.Port) ([]Script, []string, []int) {
	var hostnames []string
	var sslPorts []int
	var scripts []Script

	for _, port := range ports {
		for _, portScript := range port.Scripts {

			// Create and append Service struct with values
			scripts = append(scripts, Script{
				"port",
				int(port.ID),
				port.Protocol,
				portScript.ID,
				portScript.Output,
			})

			// Check ssl-cert result for Hostname
			if strings.ToLower(portScript.ID) == "ssl-cert" {

				// Remember port as SSL port, which is required later for certificate SANS extraction
				sslPorts = append(sslPorts, int(port.ID))

				// Extract Hostname(s) if found in ssl-cert Script output
				// Attention: Accessing these two elements is tailored to the 'ssl-cert' script and not
				// applicable in general. This approach might also fail in future versions of this script.
				for _, t := range portScript.Tables {
					if t.Key == "subject" {
						for _, e := range t.Elements {
							if e.Key == "commonName" && len(e.Value) > 0 {
								hostnames = append(hostnames, e.Value)
							}
						}
					}
				}

			}

			// Check *-ntlm-info result for Hostname
			// This does only work with the current list of scripts:
			// - rdp-ntlm-info
			// - smtp-ntlm-info
			// - telnet-ntlm-info
			// - pop3-ntlm-info
			// - ms-sql-ntlm-info
			// - http-ntlm-info
			// - imap-ntlm-info
			if strings.Contains(strings.ToLower(portScript.ID), "ntlm-info") {

				// Attention: Accessing this element is tailored to the '*-ntlm-info' scripts and not
				// applicable in general. This approach might also fail in future versions of these scripts.
				for _, e := range portScript.Elements {
					if e.Key == "DNS_Computer_Name" && len(e.Value) > 0 {

						// Append the hostname, duplicates will be removed later
						hostnames = append(hostnames, e.Value)
					}
				}
			}
		}
	}

	// Remove any duplicates that may hae been added to the hostnames
	hostnames = utils.UniqueStrings(hostnames)

	// Return extracted port data
	return scripts, hostnames, sslPorts
}

// postprocess enriches a discovered host with DNS name selection, AD data, and admin user lookups in a background goroutine.
func postprocess(
	logger utils.Logger,
	wgHosts *sync.WaitGroup,
	hData *Host,
	sslPorts []int,
	domainOrder []string,
	excludeDomains []string,
	ldapConf ldapConf,
	dialTimeout time.Duration,
	chThrottleUsers chan struct{},
	chThrottleIps chan struct{},
	chThrottleSans chan struct{},
) {

	// Log potential panics before letting them move on
	defer func() {
		if r := recover(); r != nil {
			logger.Errorf(fmt.Sprintf("Panic: %s%s", r, utils.StacktraceIndented("\t")))
			panic(r)
		}
	}()

	// Make sure wait group decremented once the post-processing is done
	defer wgHosts.Done()

	// Prepare wait group for post-processing steps
	var wg sync.WaitGroup

	// Log action
	logger.Debugf("Post-processing '%s'.", hData.Ip)

	// Submit dataset for asynchronous enumeration of Windows Admin/rdp group members.
	// ATTENTION: The attributes written by this function CANNOT be changed by other goroutines in parallel!
	smbPortOpen := false
	for _, service := range hData.Services {
		if service.Port == 445 || service.Port == 139 {
			smbPortOpen = true
		}
	}
	if smbPortOpen || strings.Contains(strings.ToLower(hData.OsSmb), "windows") {
		wg.Add(1)
		go hostExtractUsers(logger, &wg, hData, chThrottleUsers)
	}

	// Prepare channels for discovered hostnames and IPs
	chHostnames := make(chan string)
	chIps := make(chan string)
	chWait := make(chan struct{})

	// Launch hostname collection
	go func() {
		for hostname := range chHostnames {
			logger.Debugf("Post-processing '%s': Hostname received.", hData.Ip)
			hData.OtherNames = append(hData.OtherNames, hostname) // Read values delivered by goroutines
		}

		// Cleanup collected other IPs
		hData.OtherNames = utils.UniqueStrings(hData.OtherNames) // Remove duplicate hostnames

		// Log collector completion
		logger.Debugf("Post-processing '%s': Ending hostname collector.", hData.Ip)
		chWait <- struct{}{}
	}()

	// Launch IP collection
	go func() {
		for ip := range chIps {
			logger.Debugf("Post-processing '%s': IP received.", hData.Ip)
			hData.OtherIps = append(hData.OtherIps, ip) // Read values delivered by goroutines
		}

		// Cleanup collected other IPs
		hData.OtherIps = utils.UniqueStrings(hData.OtherIps)             // Remove duplicate IPs
		hData.OtherIps = utils.RemoveFromSlice(hData.OtherIps, hData.Ip) // Remove own IP

		// Log collector completion
		logger.Debugf("Post-processing '%s': Ending IP collector.", hData.Ip)
		chWait <- struct{}{}
	}()

	// Launch OXID resolver if port 135 is open
	for _, service := range hData.Services {
		if service.Port == 135 {
			wg.Add(1)
			go hostExtractIps(logger, &wg, hData.Ip, chThrottleIps, chHostnames, chIps)
			break
		}
	}

	// Launch SANS extraction
	wg.Add(1)
	go hostExtractSans(logger, &wg, hData.Ip, sslPorts, dialTimeout, chThrottleSans, chHostnames)

	// Launch inventory lookup
	wg.Add(1)
	go hostLookupInventory(logger, &wg, hData, true, chHostnames, chIps) // Throttle to be defined in the actual lookup code, because depending on the inventory

	// Wait for goroutines
	logger.Debugf("Post-processing '%s': Waiting for goroutines.", hData.Ip)
	wg.Wait()

	// Close receiver channels to terminate goroutines
	close(chHostnames)
	close(chIps)

	// Wait for both goroutines to terminate to avoid race conditions
	<-chWait
	<-chWait

	// Decide DNS name from collected candidates
	logger.Debugf("Deciding DNS name for '%s'.", hData.Ip)
	decideDnsName(hData, domainOrder, excludeDomains) // Forward host struct into next processing step
	logger.Debugf("Deciding DNS name for '%s' done.", hData.Ip)

	// Execute some additional post-processing if DNS name is available
	if hData.DnsName != "" {

		// Launch AD lookup
		wg.Add(1)
		go hostLookupAd(logger, &wg, hData, ldapConf, dialTimeout)

		// Launch asset inventory lookup again with DNS name if information is still missing
		if hData.Company == "" && hData.Department == "" && hData.Owner == "" {
			wg.Add(1)
			go hostLookupInventory(logger, &wg, hData, false, nil, nil)
		}
	}

	// Wait for goroutines
	logger.Debugf("Post-processing '%s': Waiting for final goroutines.", hData.Ip)
	wg.Wait()
	logger.Debugf("Post-processing '%s': Waiting for final goroutines done.", hData.Ip)
}

// hostExtractUsers connects to a host and tries to extract remote users in admin/RDP group
func hostExtractUsers(
	logger utils.Logger,
	wg *sync.WaitGroup,
	hData *Host,
	chThrottleUsers chan struct{},
) {

	// Log potential panics before letting them move on
	defer func() {
		if r := recover(); r != nil {
			logger.Errorf(fmt.Sprintf("Panic: %s%s", r, utils.StacktraceIndented("\t")))
			panic(r)
		}
	}()

	// Make sure wait group decremented once the goroutine returned
	defer wg.Done()

	// Log action
	logger.Debugf("Post-processing '%s': Extracting users.", hData.Ip)
	defer logger.Debugf("Post-processing '%s': Extracting users done.", hData.Ip)

	// Acquire slot to throttle goroutines active in parallel
	chThrottleUsers <- struct{}{}
	defer func() { <-chThrottleUsers }()

	// Connect to Windows machine with default user credentials and extract Admin/rdp users if allowed
	var errAdmins error
	var sidAdmin = "S-1-5-32-544"
	hData.AdminUsers, errAdmins = netapi.GetGroupInfo(logger, hData.Ip, sidAdmin)
	if errAdmins != nil {
		logger.Debugf("Could not extract admin users: %s", errAdmins)
	}

	var sidRdp = "S-1-5-32-555"
	rdpUsers, errRdpUsers := netapi.GetGroupInfo(logger, hData.Ip, sidRdp)
	if errRdpUsers != nil {
		logger.Debugf("Could not extract RDP users: %s", errRdpUsers)
	}

	// Admin users are always allowed to connect via RDP
	rdpUsers = append(rdpUsers, hData.AdminUsers...)
	hData.RdpUsers = utils.UniqueStrings(rdpUsers)
}

// hostExtractIps connects to a host in order to extract its hostname and IPs from other network interfaces.
func hostExtractIps(
	logger utils.Logger,
	wg *sync.WaitGroup,
	ip string,
	chThrottleIps chan struct{},
	chHostnames chan<- string,
	chIps chan<- string,
) {

	// Log potential panics before letting them move on
	defer func() {
		if r := recover(); r != nil {
			logger.Errorf(fmt.Sprintf("Panic: %s%s", r, utils.StacktraceIndented("\t")))
			panic(r)
		}
	}()

	// Make sure wait group decremented once the goroutine returned
	defer wg.Done()

	// Log action
	logger.Debugf("Post-processing '%s': Extracting alternative IPs.", ip)
	defer logger.Debugf("Post-processing '%s': Extracting alternative IPs done.", ip)

	// Acquire slot to throttle goroutines active in parallel
	chThrottleIps <- struct{}{}
	defer func() { <-chThrottleIps }()

	// Execute hostname and IPs of network interfaces extraction using OXID Resolver
	hostname, interfaceIps, errInterfaces := QueryInterfaces(ip)
	if errInterfaces != nil {
		logger.Debugf("Post-processing '%s': Could not extract remote interfaces: %s", ip, errInterfaces)
	}

	// Yield discovered interfaces
	for _, interfaceIp := range interfaceIps {
		chIps <- interfaceIp
	}

	// Yield discovered hostname
	chHostnames <- hostname
}

// hostExtractSans connects to an IP address and a given list of SSL endpoints (ports) in order to extract
// subject alternative names (SANSs) from SSL certificates. SANS might present a plausible hostname for this host.
func hostExtractSans(
	logger utils.Logger,
	wg *sync.WaitGroup,
	ip string,
	ports []int,
	dialTimeout time.Duration,
	chThrottleSans chan struct{},
	chHostnames chan<- string,
) {

	// Log potential panics before letting them move on
	defer func() {
		if r := recover(); r != nil {
			logger.Errorf(fmt.Sprintf("Panic: %s%s", r, utils.StacktraceIndented("\t")))
			panic(r)
		}
	}()

	// Make sure wait group decremented once the goroutine returned
	defer wg.Done()

	// Log action
	logger.Debugf("Post-processing '%s': Extracting SANs.", ip)
	defer logger.Debugf("Post-processing '%s': Extracting SANs done.", ip)

	// Acquire slot to throttle goroutines active in parallel
	chThrottleSans <- struct{}{}
	defer func() { <-chThrottleSans }()

	// Iterate SSL endpoints
	for _, port := range ports {

		// Extract SANS from SSL endpoint
		sans, errSans := utils.GetSubjectAlternativeNames(ip, port, dialTimeout)
		if errSans != nil {
			// Don't warn on connection issues, but warn on unexpected errors during SANs extraction
			var errNet net.Error
			var errRecord tls.RecordHeaderError
			if errors.As(errSans, &errNet) { // Check if error is connection related (timeout errors count as connection related as well)
				logger.Debugf(
					"Post-processing '%s': Could not connect on port %d for subject alternative names extraction: %s", ip, port, errSans)
			} else if errors.Is(errSans, io.ErrUnexpectedEOF) || errors.Is(errSans, io.EOF) { // Connection closed by other side
				logger.Debugf(
					"Post-processing '%s': Could not establish SSL connection on port %d for subject alternative names extraction: %s", ip, port, errSans)
			} else if errors.As(errSans, &errRecord) {
				logger.Debugf(
					"Post-processing '%s': Could not execute SSL handshake on port %d for subject alternative names extraction: %s", ip, port, errSans)
			} else { // Otherwise log warning message with details
				logger.Warningf(
					"Post-processing '%s': Could not extract subject alternative names on port %d: %s", ip, port, errSans)
			}
		}

		// Yield discovered hostnames
		for _, san := range sans {
			chHostnames <- san
		}
	}
}

// hostLookupAd tries to identify an active directory domain/server to connect to based on the targets DNS
// name, in order to query system details to expand the scan result data. The result data is directly written
// into the host data struct.
func hostLookupAd(
	logger utils.Logger,
	wg *sync.WaitGroup,
	hData *Host,
	ldapConf ldapConf,
	dialTimeout time.Duration,
) {

	// Log potential panics before letting them move on
	defer func() {
		if r := recover(); r != nil {
			logger.Errorf(fmt.Sprintf("Panic: %s%s", r, utils.StacktraceIndented("\t")))
			panic(r)
		}
	}()

	// Make sure wait group decremented once the goroutine returned
	defer wg.Done()

	// Log action
	logger.Debugf("Post-processing '%s': Looking up AD.", hData.Ip)
	defer logger.Debugf("Post-processing '%s': Looking up AD done.", hData.Ip)

	// Acquire slot to throttle goroutines active in parallel
	chThrottleGlobalAd <- struct{}{}
	defer func() { <-chThrottleGlobalAd }()

	// Extract CN and domain from DNS name
	var host string
	var domain string
	if strings.Contains(hData.DnsName, ".") {
		splits := strings.SplitN(hData.DnsName, ".", 2)
		host, domain = splits[0], splits[1]
	} else {
		host = hData.DnsName
	}

	// Decide which server to connect to for AD lookups
	ldapAddress := ldapConf.ldapServer
	if ldapAddress == "" {
		ldapAddress = domain
	}

	// Continue with AD lookup if server is available
	if ldapAddress != "" {

		// Use LDAP if explicit authentication is configured, ADODB with implicit authentication otherwise (only
		// working on Windows!)
		if ldapConf.ldapUser != "" {

			// Query LDAP with explicit authentication (independent of OS)
			logger.Debugf("Searching LDAP with explicit authentication for '%s'.", host)
			hData.Ad = ad.LdapQuery(
				logger,
				host,
				ldapAddress,
				389,
				ldapConf.ldapDomain,
				ldapConf.ldapUser,
				ldapConf.ldapPassword,
				ldapConf.disableGssapi,
				dialTimeout,
			)
		} else {

			// Query ADODB with implicit authentication (only working on Windows with suitable domain membership)
			logger.Debugf("Searching ADODB with implicit authentication for '%s'.", host)
			hData.Ad = ad.AdodbQuery(logger, host, ldapAddress)
		}
	}
}

// hostLookupInventory searches an asset information inventory for additional information about a host. Ownership
// information and maybe plausible hostnames might be available.
func hostLookupInventory(
	logger utils.Logger,
	wg *sync.WaitGroup,
	hData *Host,
	searchByIp bool, // Whether the IP or DnsName from hData should be used to query
	chHostnames chan<- string,
	chIps chan<- string,
) {

	// Log potential panics before letting them move on
	defer func() {
		if r := recover(); r != nil {
			logger.Errorf(fmt.Sprintf("Panic: %s%s", r, utils.StacktraceIndented("\t")))
			panic(r)
		}
	}()

	// Make sure wait group decremented once the goroutine returned
	defer wg.Done()

	// Log action
	logger.Debugf("Post-processing '%s': Looking up asset inventory.", hData.Ip)
	defer logger.Debugf("Post-processing '%s': Looking up asset inventory done.", hData.Ip)

	// Prepare memory for search result
	var errLookup error
	var company string
	var department string
	var owner string
	var hostnames []string
	var ips []string
	var critical bool

	// Search asset information inventories
	for inventoryName, inventory := range inventories {

		// Check if inventory is initialized
		if !inventory.Initialized() {
			continue
		}

		// Abort search once data was found
		if company != "" || department != "" || owner != "" {
			break
		}

		// Prepare slice of IPs to search for
		allIps := append([]string{hData.Ip}, hData.OtherIps...)
		for _, otherName := range hData.OtherNames {
			if utils.IsValidIp(otherName) {
				allIps = append(allIps, otherName)
			}
		}
		allIps = utils.UniqueStrings(allIps)

		// Search asset information inventory
		if searchByIp {

			// Log warning on big lookups
			if len(allIps) > 10 {
				logger.Warningf("Searching '%s' asset inventory inventory with %d IPs.", inventoryName, len(allIps))
			}

			// Iterate IPs and lookup
			for _, ip := range allIps {

				// Log asset inventory action
				logger.Debugf("Searching '%s' asset inventory for '%s'", inventoryName, hData.Ip)

				// Search asset inventory by IP. The lookup should only return information about assets with fixed IP
				// addresses, or if it is certain that the inventory has reliable information in case of dynamic ones!
				company, department, owner, hostnames, ips, critical, errLookup = inventory.ByIp(logger, ip)

				// Handle lookup error
				if errLookup != nil {
					logger.Warningf("Searching '%s' asset inventory inventory by '%s' failed: %s", inventoryName, ip, errLookup)
				}

				// Abort further lookups on success
				if company != "" || department != "" || owner != "" {
					break
				}
			}

		} else {

			// Prepare slice of IPs to search for
			allDnsNames := []string{hData.DnsName}
			for _, otherName := range hData.OtherNames {
				if utils.IsValidHostname(otherName) {
					allDnsNames = append(allDnsNames, otherName)
				}
			}
			allDnsNames = utils.UniqueStrings(allDnsNames)

			// Log warning on big lookups
			if len(allDnsNames) > 10 {
				logger.Warningf("Searching '%s' asset inventory inventory with %d DNS names.", inventoryName, len(allDnsNames))
			}

			// Iterate IPs and lookup
			for _, dnsName := range allDnsNames {

				// Log asset inventory action
				logger.Debugf("Searching '%s' asset inventory for '%s'", inventoryName, dnsName)

				// Search asset inventory by FQDN
				company, department, owner, hostnames, ips, critical, errLookup = inventory.ByFqdn(
					logger,
					dnsName,
					allIps,
				)

				// Handle lookup error
				if errLookup != nil {
					logger.Warningf("Searching '%s' asset inventory inventory failed: %s", inventoryName, errLookup)
				}

				// Abort further lookups on success
				if company != "" || department != "" || owner != "" {
					break
				}
			}
		}
	}

	// Add retrieved asset information to host data
	hData.Company = company
	hData.Department = department
	hData.Owner = owner
	hData.Critical = critical

	// Yield discovered IPs
	if chIps != nil {
		for _, ip := range ips {
			chIps <- ip
		}
	} else { // Alternatively, directly attach to host data
		hData.OtherIps = append(hData.OtherIps, ips...)
	}

	// Yield discovered hostnames
	if chHostnames != nil {
		for _, hostname := range hostnames {
			if hostname != hData.DnsName {
				chHostnames <- hostname
			}
		}
	}
}

// decideDnsName resolves and assigns the most plausible DNS name for a host based on domain order preferences and exclusions.
func decideDnsName(hData *Host, domainOrder []string, excludeDomains []string) {

	// Acquire slot to throttle goroutines active in parallel
	chThrottleGlobalDns <- struct{}{}
	defer func() { <-chThrottleGlobalDns }()

	// Sanitize list of DNS names
	//   - to-lower
	//   - remove duplicates,
	//   - remove IP Addresses
	//	 - remove excluded hostnames
	//   but leave interesting stuff (even if not a legit DNS name)
	hData.OtherNames = sanitizeDnsNames(hData.OtherNames, excludeDomains)

	// Sort DNS names by plausibility
	dnsNames := orderDnsNames(hData.OtherNames, domainOrder)

	// Decide working DNS name
	dns, otherNames := identifyDnsName(dnsNames, hData.Ip)

	// Update host struct with new data
	hData.DnsName = dns
	hData.OtherNames = otherNames
}

// sanitizeDnsNames normalizes, deduplicates, and filters a slice of DNS names according to exclusion rules.
func sanitizeDnsNames(dnsNames []string, excludeDomains []string) []string {

	// Sanitize input list
	dnsNames = utils.TrimToLower(dnsNames)                                                  // Trim and to-lower all
	dnsNames = utils.Filter(dnsNames, func(s string) bool { return len(s) > 0 })            // Remove empty DNS names
	dnsNames = utils.Filter(dnsNames, func(s string) bool { return net.ParseIP(s) == nil }) // Filter IPv4 and IPv6

	// Remove excluded hostnames
	dnsNames = utils.Filter(dnsNames, func(s string) bool { return !utils.StrContained(s, excludeDomains) })

	// Search for DNS wildcards. Add wildcard sample and wildcard's base domain
	var newDnsNames []string
	for i := 0; i < len(dnsNames); i++ {
		if strings.HasPrefix(dnsNames[i], "*.") {
			newDnsNames = append(newDnsNames, strings.Replace(dnsNames[i], "*.", "wildcard.", 1)) // Generate * sample
			dnsNames[i] = strings.Replace(dnsNames[i], "*.", "", 1)                               // Replace wildcard with base host
		}
	}
	dnsNames = append(dnsNames, newDnsNames...)

	// Remove duplicates
	dnsNames = utils.UniqueStrings(dnsNames)

	// Strings with spaces might not be valid DNS name but still interesting to learn about a system!
	return dnsNames
}

// orderDnsNames orders DNS names by plausibility to ensure a deterministic DNS name discovery output (in case
// multiple DNS names resolve equally). DNS names are sorted by domain depth and alphabetic order.
// DNS names without any dot, respectively domain names, are moved to the end of the order (seems hostname only).
// A manually sorted list of domains can be passed to customize the output order, respectively, to prioritize DNS
// names containing known (e.g. internal) domains.
func orderDnsNames(dnsNames []string, domainOrder []string) []string {

	// Define sort function
	lessFn := func(i, j int) bool {

		// Get DNS names to compare
		hostI := dnsNames[i]
		hostJ := dnsNames[j]

		// Check if DNS name "A" has a lower plausibility then DNS name "B", based on the custom domain order
		indexI := len(domainOrder) // default index value outside of slice to indicate not found within
		indexJ := len(domainOrder) // default index value outside of slice to indicate not found within
		for index := len(domainOrder) - 1; index >= 0; index-- {
			if strings.HasSuffix(hostI, domainOrder[index]) {
				indexI = index
			}
			if strings.HasSuffix(hostJ, domainOrder[index]) {
				indexJ = index
			}
		}
		if indexI < indexJ {
			return true
		} else if indexI > indexJ {
			return false
		}

		// Make sure toplevel domains are pushed to the back, as they are most likely not valid FQDNs
		if strings.Count(hostJ, ".") == 0 && strings.Count(hostI, ".") > 0 {
			return true
		} else if strings.Count(hostI, ".") == 0 && strings.Count(hostJ, ".") > 0 {
			return false
		}

		// Decide based on domain depth
		cI := strings.Count(hostI, ".")
		cJ := strings.Count(hostJ, ".")
		if cI < cJ {
			return true
		} else if cI > cJ {
			return false
		}

		// Sort by toplevel domain. Domain depth of both domains must be equal, after passing above test
		hostSplitsI := strings.Split(hostI, ".")
		hostSplitsJ := strings.Split(hostJ, ".")
		for index := len(hostSplitsI) - 1; index >= 0; index-- {
			if hostSplitsI[index] < hostSplitsJ[index] {
				return true
			} else if hostSplitsI[index] > hostSplitsJ[index] {
				return false
			}
		}

		// If nothing else distinguishes their priority, sort by alphabet
		if hostI < hostJ {
			return true
		}

		// Return false otherwise
		return false
	}

	// Sort according to specific criteria
	sort.SliceStable(dnsNames, lessFn)

	// Return prioritized DNS name
	return dnsNames
}

// identifyDnsName takes a list of potential DNS names and extracts the most likely and stable one
func identifyDnsName(potentialDnsNames []string, expectedIp string) (string, []string) {

	// Prepare variables
	var dnsName string
	var dnsNamesOther []string
	var dnsNameQuality int // 0 = not chosen, 1 = resolves forward, 2 = resolves forward and backward

	// Iterate potential DNS names and check for validity
	// Please note, potential DNS names are already sorted by plausibility! Hence, it's iterate over them backwards, so
	// that more plausible DNS names (equally resolving) can replace less plausible ones
	for i := len(potentialDnsNames) - 1; i >= 0; i-- {

		// Grab potential hostname
		hostname := potentialDnsNames[i]

		// Check how DNS name resolves
		resolvesForward := utils.ResolvesToIp(hostname, expectedIp)
		resolvesBackward := utils.ResolvesToHostname(expectedIp, hostname)

		// Validate situation
		if resolvesForward && resolvesBackward { // DNS name resolves forward and backward, perfect!
			dnsNameQuality = 2
			if len(dnsName) != 0 {
				dnsNamesOther = append(dnsNamesOther, dnsName)
			}
			dnsName = hostname
		} else if resolvesForward && dnsNameQuality < 2 { // DNS name resolves forward, good enough to reference host
			dnsNameQuality = 1
			if len(dnsName) != 0 {
				dnsNamesOther = append(dnsNamesOther, dnsName)
			}
			dnsName = hostname
		} else { // DNS name does not resolve to the given IP
			dnsNamesOther = append(dnsNamesOther, hostname)
		}
	}

	// Reverse order, it got upside-down because it was iterated in reverse order
	utils.Reverse(dnsNamesOther)

	// Return validated DNS name and the other ones
	return dnsName, dnsNamesOther
}
