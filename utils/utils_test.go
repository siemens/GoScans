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
	"fmt"
	"net"
	"os"
	"testing"

	"github.com/siemens/GoScans/_test"
)

// mockDNSForward maps hostnames to the single IP returned by the test resolver.
var mockDNSForward = map[string]string{
	"www.ccc.de": "195.54.164.39",
}

// mockDNSReverse maps IPs to the reverse-DNS hostname returned by the test resolver.
var mockDNSReverse = map[string]string{
	"8.8.4.4":       "dns.google.",
	"195.54.164.39": "www.ccc.de.",
}

// TestMain initializes the test environment and runs all tests in the utils package.
func TestMain(m *testing.M) {

	// Retrieve test settings
	_ = _test.GetSettings()

	// Replace DNS lookups with deterministic mocks so tests are network-independent.
	dnsLookupIp = func(host string) ([]net.IP, error) {
		if ip, ok := mockDNSForward[host]; ok {
			return []net.IP{net.ParseIP(ip)}, nil
		}
		return nil, &net.DNSError{Err: "no such host", Name: host}
	}
	dnsLookupAddr = func(addr string) ([]string, error) {
		if name, ok := mockDNSReverse[addr]; ok {
			return []string{name}, nil
		}
		return nil, &net.DNSError{Err: fmt.Sprintf("lookup %s: no such host", addr), Name: addr}
	}

	// Prepare test directory
	tmpDir, errTmpDir := os.MkdirTemp(".", "goscans-utils-test-*")
	if errTmpDir != nil {
		panic(errTmpDir)
	}
	if errChdir := os.Chdir(tmpDir); errChdir != nil {
		panic(errChdir)
	}

	// Run tests
	code := m.Run()

	// Prepare cleanup
	_ = os.Chdir("..")
	_ = os.RemoveAll(tmpDir)

	// Return nil as everything went fine
	os.Exit(code)
}
