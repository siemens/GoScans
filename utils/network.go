/*
* GoScans, a collection of network scan modules for infrastructure discovery and information gathering.
*
* Copyright (c) Siemens AG, 2016-2026.
*
* This work is licensed under the terms of the MIT license. For a copy, see the LICENSE file in the top-level
* directory or visit <https://opensource.org/licenses/MIT>.
*
 */

package utils

import (
	"net"
	"net/url"
	"regexp"
	"strings"
)

var dnsLookupIp func(host string) ([]net.IP, error) = net.LookupIP     // DNS hostname lookup, replaceable in tests
var dnsLookupAddr func(addr string) ([]string, error) = net.LookupAddr // Reverse-DNS lookup, replaceable in tests

// OverrideDNS replaces the DNS lookup functions used by ResolvesToIp and ResolvesToHostname.
// Returns a restore function. For use in tests only.
func OverrideDNS(ipFn func(string) ([]net.IP, error), addrFn func(string) ([]string, error)) func() {
	oldIP, oldAddr := dnsLookupIp, dnsLookupAddr
	dnsLookupIp, dnsLookupAddr = ipFn, addrFn
	return func() { dnsLookupIp, dnsLookupAddr = oldIP, oldAddr }
}

// ResolvesToIp resolves a given DNS name and checks whether the result matches the expected IP address.
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
	ips, errIps := dnsLookupIp(hostname)
	if errIps != nil {
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
	resolvedHostnames, errResolvedHostnames := dnsLookupAddr(ip)
	if errResolvedHostnames != nil {
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
	lastCharRegex := regexp.MustCompile(`[[:alnum:]]$`)
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
	return net.ParseIP(s) != nil
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
	_, _, errParseCIDR := net.ParseCIDR(s)
	return errParseCIDR == nil
}

// IsValidAddress determines whether a given string is a valid IPv4, IPv6 or hostname, but NOT a network range
func IsValidAddress(s string) bool {
	if IsValidIp(s) {
		return true
	}
	if IsValidHostname(s) {
		return true
	}
	return false
}

// IsValidUrl determines whether a given string is a valid url (with any scheme)
func IsValidUrl(s string) bool {

	// Attempt to parse as URL
	parsedUrl, errParsedUrl := url.Parse(s)
	if errParsedUrl != nil {
		return false
	}

	// Ensure scheme is present
	if parsedUrl.Scheme == "" {
		return false
	}

	// Ensure host is present
	if parsedUrl.Host == "" {
		return false
	}

	// Return valid if all checks passed
	return true
}

// IsValidUrlHttp determines whether a given string is a valid HTTP(s) url
func IsValidUrlHttp(s string) bool {

	// Attempt to parse as URL
	parsedUrl, errParsedUrl := url.Parse(s)
	if errParsedUrl != nil {
		return false
	}

	// Check if scheme is http or https
	if parsedUrl.Scheme != "http" && parsedUrl.Scheme != "https" {
		return false
	}

	// Ensure host is present
	if parsedUrl.Host == "" {
		return false
	}

	// Return valid if all checks passed
	return true
}
