/*
* GoScans, a collection of network scan modules for infrastructure discovery and information gathering.
*
* Copyright (c) Siemens AG, 2016-2026.
*
* This work is licensed under the terms of the MIT license. For a copy, see the LICENSE file in the top-level
* directory or visit <https://opensource.org/licenses/MIT>.
*
 */

package ad

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
	cmap "github.com/orcaman/concurrent-map/v2"
	"github.com/siemens/GoScans/utils"
)

// cache is the package-wide instance of Cache
var cache = &Cache{
	dcEntries:  cmap.New[dcEntry](),
	kdcEntries: cmap.New[kdcEntry](),
	ttl:        7 * 24 * time.Hour,
}

// dialTimeout is the maximum duration allowed for each LDAP connection attempt during discovery.
const dialTimeout = 30 * time.Second

// Cache stores domain controller (dc) and key distribution centers (kdc) per domain/realm with TTL management.
type Cache struct {
	dcEntries  cmap.ConcurrentMap[string, dcEntry]  // Domain -> DC data
	kdcEntries cmap.ConcurrentMap[string, kdcEntry] // Realm -> KDC data
	ttl        time.Duration                        // Time-To-Live for cached entries
}

// dcEntry represents a cached Domain Controller entry.
type dcEntry struct {
	dc     string
	expiry time.Time
}

// kdcEntry represents a cached Key Distribution Center entry.
type kdcEntry struct {
	kdcs   []string
	expiry time.Time
}

// GetDc returns a cached or newly discovered domain controller for a given domain.
// If a valid entry exists in the cache, it is returned. Otherwise, GetDc attempts to discover
// a new DC and caches it. If discovery fails but a stale cache entry existed, the stale
// entry is returned with a debug log.
func (c *Cache) GetDc(logger utils.Logger, domain string) (string, error) {

	// Get current time
	now := time.Now()

	// Lookup Domain Controller
	entry, found := c.dcEntries.Get(domain)

	// Check if a valid, non-expired entry exists in the cache
	if found && now.Before(entry.expiry) && entry.dc != "" {
		return entry.dc, nil
	}

	// If not found or expired, discover a new domain controller
	dcNew, errDcNew := findDc(logger, domain)
	if errDcNew != nil {

		// If discovery fails, check if a stale cache entry can be used as a fallback
		if found && entry.dc != "" {
			logger.Debugf("Using stale domain controller for '%s' due to discovery error: %v", domain, errDcNew)
			return entry.dc, nil
		}

		// Return error otherwise
		return "", errDcNew
	}

	// Add new entry to the cache
	c.dcEntries.Set(domain, dcEntry{dc: dcNew, expiry: now.Add(c.ttl)}) // Store new DC with its expiry time

	// Return newly discovered domain controller
	return dcNew, nil
}

// GetKdc returns cached or resolved key distribution center addresses for a given kerberos realm.
// It first checks the cache for valid entries. If none are found, or they are expired,
// it performs an SRV lookup to discover key distribution centers and caches the results.
// If SRV lookup fails but a stale cache entry exists, it falls back to the stale entry.
func (c *Cache) GetKdc(logger utils.Logger, realm string) ([]string, error) {

	// Get current time
	now := time.Now()

	// Sanitize input
	realmLower := strings.ToLower(realm)

	// Lookup kdc
	entry, found := c.kdcEntries.Get(realmLower)

	// Check if a valid, non-expired entry with key distribution center exists in the cache
	if found && now.Before(entry.expiry) && len(entry.kdcs) > 0 {

		// Return cached KDCs
		return entry.kdcs, nil
	}

	// If not found or expired, resolve key distribution centers using SRV records
	kdcsNew := resolveSrvIps(logger, "kerberos", "tcp", realmLower)
	if len(kdcsNew) == 0 {

		// If no key distribution centers were found via SRV lookup, check for stale cache fallback
		if found && len(entry.kdcs) > 0 {
			logger.Debugf("Using stale key distribution center for '%s' due to empty SRV lookup", realmLower)
			return entry.kdcs, nil
		}

		// Return error otherwise
		return nil, fmt.Errorf("could not find key distribution center SRV records for realm '%s'", realmLower)
	}

	// Add new entry to the cache
	c.kdcEntries.Set(realmLower, kdcEntry{kdcs: kdcsNew, expiry: now.Add(c.ttl)}) // Store new KDCs with expiry

	// Return newly discovered key distribution centers
	return kdcsNew, nil
}

// resolveSrvIps resolves SRV records to IP:port addresses for Kerberos services.
// It looks up SRV records for the specified service, protocol, and domain,
// then resolves each target to its IP addresses and returns them in "IP:port" format.
func resolveSrvIps(logger utils.Logger, service, proto, domain string) []string {

	// Prepare memory
	var results []string

	// Look up SRV records for the service
	_, srvs, errSrvs := net.LookupSRV(service, proto, domain)
	if errSrvs != nil {
		logger.Debugf("Could not lookup SRV for '_%s._%s.%s': %v", service, proto, domain, errSrvs)
		return results
	}

	// For each SRV record, resolve the target to IP addresses
	for _, srv := range srvs {

		// Remove trailing dot from SRV target
		target := strings.TrimSuffix(srv.Target, ".")

		// Resolve the target hostname to IP addresses
		ips, errIps := net.LookupHost(target)
		if errIps != nil {
			logger.Debugf("Could not resolve SRV host '%s': %v", target, errIps)
			continue
		}

		// For each resolved IP, create an "IP:port" string and add to results
		for _, ip := range ips {
			results = append(results, net.JoinHostPort(ip, fmt.Sprint(srv.Port)))
		}
	}
	return results
}

// findDc performs an SRV lookup for active directory domain controllers,
// verifies connectivity to port 389 on each and returns the first reachable one.
func findDc(logger utils.Logger, domainName string) (string, error) {

	// Standard SRV record for LDAP services on a domain controller
	// The service is "ldap", protocol is "tcp", name is "dc._msdcs.<domainName>"
	_, srvs, errSrvs := net.LookupSRV("ldap", "tcp", fmt.Sprintf("dc._msdcs.%s", domainName))
	if errSrvs != nil {
		return "", fmt.Errorf("could not lookup SRV records for '%s': %w", domainName, errSrvs)
	}

	// If not found return error
	if len(srvs) == 0 {
		return "", fmt.Errorf("could not find SRV records for '%s'", domainName)
	}

	// Prepare some flags
	var dcReachable string
	var tlsSupport = false

	// Iterate over the discovered SRV records, which represent potential domain controllers
	for _, srv := range srvs {

		// Extract the hostname and port from the SRV record
		dcHost := strings.TrimSuffix(srv.Target, ".")
		dcPort := srv.Port // 389 for LDAP

		// Resolve hostname to IP addresses
		ips, errIps := net.LookupHost(dcHost)
		if errIps != nil {
			continue // Skip to the next SRV record if hostname cannot be resolved
		}

		// Test connectivity
		for _, ip := range ips {

			// Connect
			addr := net.JoinHostPort(ip, fmt.Sprint(dcPort))
			conn, errConn := net.DialTimeout("tcp", addr, dialTimeout)
			if errConn != nil {
				continue // Try next IP if current one fails
			}

			// Close the connection immediately after successful dial and set the dcReachable
			_ = conn.Close()
			dcReachable = dcHost

			// Break from inner loop, no need to check other IPs for this DC
			break
		}

		// If a reachable DC is found, check if it supports StartTLS.
		// If it does, we can stop searching as we prefer TLS-enabled domain controllers.
		if dcReachable != "" && testStartTls(dcReachable, 389) {
			tlsSupport = true
			break
		}
	}

	// Return an error if no reachable DC was found after checking all options
	if dcReachable == "" {
		return "", fmt.Errorf("could not find reachable domain controllers for '%s' after checking connectivity to port 389", domainName)
	}

	// Warn the user if the found DC does not support TLS
	if !tlsSupport {
		logger.Debugf("Domain controller '%s' does not support TLS.", dcReachable)
	}

	// Return found DC
	return dcReachable, nil
}

// testStartTls checks if a given LDAP server (domain controller) supports the StartTLS operation.
// It attempts to establish an LDAP connection and then upgrade it to TLS.
func testStartTls(server string, port int) bool {

	// Attempt to dial the LDAP server
	conn, errConn := ldap.DialURL(fmt.Sprintf("ldap://%s:%d", server, port), ldap.DialWithDialer(&net.Dialer{Timeout: dialTimeout}))
	if errConn != nil {
		return false // If dialing fails, TLS cannot be tested
	}

	// Ensure the connection is closed when the function exits
	defer func() { _ = conn.Close() }()

	// Attempt to perform the StartTLS operation
	errTls := conn.StartTLS(utils.InsecureTlsConfigFactory()) // Insecure, because this is not a user interface, we are trying to discover content...

	// If errTls is nil, StartTLS was successful
	return errTls == nil
}
