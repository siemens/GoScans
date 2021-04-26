/*
* GoScans, a collection of network scan modules for infrastructure discovery and information gathering.
*
* Copyright (c) Siemens AG, 2016-2021.
*
* This work is licensed under the terms of the MIT license. For a copy, see the LICENSE file in the top-level
* directory or visit <https://opensource.org/licenses/MIT>.
*
 */

package utils

import (
	"net"
	"regexp"
	"strings"
)

// Resolves a given DNS name and checks whether the result matches the expected IP address.
func ResolvesToIp(hostname string, expectedIp string) bool {

	// Return false if expected IP is invalid
	if len(expectedIp) == 0 || net.ParseIP(expectedIp) == nil {
		return false
	}

	// Return false if given hostname is not valid
	if len(hostname) == 0 {
		return false
	}

	// Return false if hostname lookup failed
	ips, err := net.LookupIP(hostname)
	if err != nil {
		return false
	}

	// Return true if hostname lookup returned single IP which matches expected IP
	if len(ips) == 1 && ips[0].String() == expectedIp {
		return true
	}

	// Return false if lookup returned zero or more than one IPs
	// If zero: Hostname obviously not pointing to expected IP
	// If >1: Hostname not clearly pointing to expected IP
	return false

}

// ResolvesToHostname checks whether a given IP reverse resolves to the expected hostname
func ResolvesToHostname(ip string, hostname string) bool {

	// Return false if IP is invalid
	if len(ip) == 0 || net.ParseIP(ip) == nil {
		return false
	}

	// Return false if given hostname is not valid
	if len(hostname) == 0 {
		return false
	}

	// Return false if reverse lookup failed
	resolvedHostnames, err := net.LookupAddr(ip)
	if err != nil {
		return false
	}

	// Return true if one of the resolved hostnames matches the given one
	for _, resolvedHostname := range resolvedHostnames {
		resolvedHostname = strings.TrimRight(resolvedHostname, ".")
		if resolvedHostname == hostname {
			return true
		}
	}

	// Return false if reverse lookup results do not contain hostname
	return false
}

// IsValidHostname determines whether a given hostname is a plausible one
func IsValidHostname(hostname string) bool {

	// convert to lower case, as cases don't have semantic in domains
	hostname = strings.ToLower(hostname)

	// Return false on empty strings
	if len(hostname) == 0 {
		return false
	}

	// Return false if invalid start character
	firstCharRegex := regexp.MustCompile(`^[[:alnum:]]`)
	if !firstCharRegex.MatchString(hostname) {
		return false
	}

	// Return false if invalid end
	lastCharRegex := regexp.MustCompile(`[[:alpha:]]$`)
	if !lastCharRegex.MatchString(hostname) {
		return false
	}

	// Return false if hostname does not match RFC1035
	hostnameRegex := regexp.MustCompile(`^[[:alnum:]][[:alnum:]\-]{0,61}[[:alnum:]]?|[[:alpha:]]?$`)
	if !hostnameRegex.MatchString(hostname) {
		return false
	}

	// Return false if hostname is actually an IPv4/6 address
	if net.ParseIP(hostname) != nil {
		return false
	}

	// Return false on strings with invalid characters
	for _, fChar := range []string{" ", "=", ":", "?", "!", "\\", "/", "\x00", "\\x00"} {
		if strings.Contains(hostname, fChar) {
			return false
		}
	}

	// Return true as valid hostname
	return true
}

// IsValidIp determines whether a given string is a valid IPv4/IPv6 address
func IsValidIp(s string) bool {
	if net.ParseIP(s) != nil {
		return true
	}
	return false
}

// IsValidIpV4 determines whether a given string is a valid IPv4 address
func IsValidIpV4(s string) bool {
	if IsValidIp(s) && strings.Count(s, ":") < 2 {
		return true
	}
	return false
}

// IsValidIpV6 determines whether a given string is a valid IPv6 address
func IsValidIpV6(s string) bool {
	if IsValidIp(s) && strings.Count(s, ":") >= 2 {
		return true
	}
	return false
}

// IsValidIpRange determines whether a given string is a valid network range
func IsValidIpRange(s string) bool {
	_, _, err := net.ParseCIDR(s)
	if err == nil {
		return true
	}
	return false
}

// IsValidAddress determines whether a given string is a valid IPv4, IPv6 or hostname, but NOT a network range
func IsValidAddress(s string) bool {
	if IsValidIp(s) {
		return true
	} else if IsValidHostname(s) {
		return true
	}
	return false
}
