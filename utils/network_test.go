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
	"testing"
)

func TestResolvesToIp(t *testing.T) {

	// Prepare and run test cases
	type args struct {
		hostname   string
		expectedIp string
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{"valid-resolving", args{"www.ccc.de", "195.54.164.39"}, true},
		{"invalid-confused-input", args{"195.54.164.39", "www.ccc.de"}, false}, // Ip as hostname can be resolved to itself :)
		{"invalid-resolving", args{"sub.domain.tld", "195.54.164.39"}, false},
		{"invalid-not-resolving", args{"notexisting.domain.tld", "195.54.164.39"}, false},
		{"invalid-hostname", args{"", "195.54.164.39"}, false},
		{"invalid-ip1", args{"google.com", "notanipaddress"}, false},
		{"invalid-ip2", args{"google.com", ""}, false},
		{"invalid-input", args{"", ""}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ResolvesToIp(tt.args.hostname, tt.args.expectedIp); got != tt.want {
				t.Errorf("ResolvesToIp() = '%v', want = '%v'", got, tt.want)
			}
		})
	}
}

func TestResolvesToHostname(t *testing.T) {

	// Prepare and run test cases
	type args struct {
		ip               string
		expectedHostanme string
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{"valid-resolving", args{"8.8.4.4", "dns.google"}, true},
		{"invalid", args{"8.8.4.4", "notexisting"}, false},
		{"invalid-ip", args{"a.12.12.a", "google.com"}, false},
		{"invalid-empty-ip", args{"", "google.com"}, false},
		{"invalid-empty-hostname", args{"192.168.0.1", ""}, false},
		{"invalid-not-resolving", args{"192.168.0.1", "scan.domain.tld"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ResolvesToHostname(tt.args.ip, tt.args.expectedHostanme); got != tt.want {
				t.Errorf("ResolvesToHostname() = '%v', want = '%v'", got, tt.want)
			}
		})
	}
}

func TestIsValidHostname(t *testing.T) {

	// Prepare and run test cases
	tests := []struct {
		name     string
		hostname string
		want     bool
	}{
		{"valid", "hostname", true},     // hostname without domain can be valid too in local environments, systems are automatically resolving to the local domain
		{"valid2", "tfpr-a0-p03", true}, // hostname without domain can be valid too in local environments, systems are automatically resolving to the local domain
		{"valid3", "sub.domain.tld", true},
		{"valid-hyphen", "s-ub.domain.tld", true},
		{"valid-localhost", "localhost", true},
		{"valid-hostname", "hostname", true}, // within an AD domain it's also possible to contact hostnames, instead of fqdns
		{"invalid-hyphen", "-sub.domain.tld", false},
		{"invalid1", "!=§$%", false},
		{"invalid2", "sub.domain.tld/26", false},
		{"invalid4", "sub.domain.tld\\26", false},
		{"invalid-dn", "cn=0123456ab,cn=forrest,cn=domain,cn=tld", false},
		{"invalid-empty", "", false},
		{"invalid-empty", " ", false},
		{"invalid-space", "su b.domain.tld", false},
		{"invalid-space2", "t ld", false},
		{"invalid-start", ".tld", false},
		{"invalid-start2", " tld", false},
		{"invalid-start3", "-tld", false},
		{"invalid-end", "tld.", false},
		{"invalid-end2", "tld ", false},
		{"invalid-end3", "tld-", false},
		{"invalid-ipv4", "127.0.0.1", false},
		{"invalid-ipv6", "1::", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsValidHostname(tt.hostname); got != tt.want {
				t.Errorf("IsValidHostname() = '%v', want = '%v'", got, tt.want)
			}
		})
	}
}

func TestIsValidIp(t *testing.T) {

	// Prepare and run test cases
	tests := []struct {
		name string
		s    string
		want bool
	}{
		{"ipv4-localhost", "127.0.0.1", true},
		{"ipv4-1", "8.8.8.8", true},
		{"ipv4-2", "123.123.123.123", true},

		{"ipv6-localhost", "1::", true},
		{"ipv6", "fe80:3::1ff:fe23:4567:890a", true},
		{"ipv6-embraced", "[fe80:3::1ff:fe23:4567:890a]", false},

		{"ipv4-range-1", "192.168.0.1/32", false},
		{"ipv4-range-254", "192.168.0.1/24", false},
		{"ipv4-range-4294967294", "192.168.0.1/0", false},
		{"ipv4-range-2147483646", "192.168.0.1/1", false},
		{"ipv6-range-20282409603651670423947251286016", "1::/24", false},
		{"ipv6-range-20282409603651670423947251286016", "fe80:3::1ff:fe23:4567:890a/24", false},
		{"ipv6-range-20282409603651670423947251286016-embraced", "[fe80:3::1ff:fe23:4567:890a]/24", false},

		{"domain-tld", "domain.tld", false},
		{"domain-root", "domain", false},

		{"ipv4-with-port", "123.123.123.123:443", false},
		{"ipv6-with-port", "[2001:db8:85a3:8d3:1319:8a2e:370:7348]:443", false},
		{"domain-with-port", "domain.tld:443", false},

		{"grabage", "in valid", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsValidIp(tt.s); got != tt.want {
				t.Errorf("IsValidIp() = '%v', want = '%v'", got, tt.want)
			}
		})
	}
}

func TestIsValidIpV4(t *testing.T) {

	// Prepare and run test cases
	tests := []struct {
		name string
		s    string
		want bool
	}{
		{"ipv4-localhost", "127.0.0.1", true},
		{"ipv4-1", "8.8.8.8", true},
		{"ipv4-2", "123.123.123.123", true},

		{"ipv6-localhost", "1::", false},
		{"ipv6", "fe80:3::1ff:fe23:4567:890a", false},
		{"ipv6-embraced", "[fe80:3::1ff:fe23:4567:890a]", false},

		{"ipv4-range-1", "192.168.0.1/32", false},
		{"ipv4-range-254", "192.168.0.1/24", false},
		{"ipv4-range-4294967294", "192.168.0.1/0", false},
		{"ipv4-range-2147483646", "192.168.0.1/1", false},
		{"ipv6-range-20282409603651670423947251286016", "1::/24", false},
		{"ipv6-range-20282409603651670423947251286016", "fe80:3::1ff:fe23:4567:890a/24", false},
		{"ipv6-range-20282409603651670423947251286016-embraced", "[fe80:3::1ff:fe23:4567:890a]/24", false},

		{"domain-tld", "domain.tld", false},
		{"domain-root", "domain", false},

		{"ipv4-with-port", "123.123.123.123:443", false},
		{"ipv6-with-port", "[2001:db8:85a3:8d3:1319:8a2e:370:7348]:443", false},
		{"domain-with-port", "domain.tld:443", false},

		{"grabage", "in valid", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsValidIpV4(tt.s); got != tt.want {
				t.Errorf("IsValidIpV4() = '%v', want = '%v'", got, tt.want)
			}
		})
	}
}

func TestIsValidIpV6(t *testing.T) {

	// Prepare and run test cases
	tests := []struct {
		name string
		s    string
		want bool
	}{
		{"ipv4-localhost", "127.0.0.1", false},
		{"ipv4-1", "8.8.8.8", false},
		{"ipv4-2", "123.123.123.123", false},

		{"ipv6-localhost", "1::", true},
		{"ipv6", "fe80:3::1ff:fe23:4567:890a", true},
		{"ipv6-embraced", "[fe80:3::1ff:fe23:4567:890a]", false},

		{"ipv4-range-1", "192.168.0.1/32", false},
		{"ipv4-range-254", "192.168.0.1/24", false},
		{"ipv4-range-4294967294", "192.168.0.1/0", false},
		{"ipv4-range-2147483646", "192.168.0.1/1", false},
		{"ipv6-range-20282409603651670423947251286016", "1::/24", false},
		{"ipv6-range-20282409603651670423947251286016", "fe80:3::1ff:fe23:4567:890a/24", false},
		{"ipv6-range-20282409603651670423947251286016-embraced", "[fe80:3::1ff:fe23:4567:890a]/24", false},

		{"domain-tld", "domain.tld", false},
		{"domain-root", "domain", false},

		{"ipv4-with-port", "123.123.123.123:443", false},
		{"ipv6-with-port", "[2001:db8:85a3:8d3:1319:8a2e:370:7348]:443", false},
		{"domain-with-port", "domain.tld:443", false},

		{"grabage", "in valid", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsValidIpV6(tt.s); got != tt.want {
				t.Errorf("IsValidIpV6() = '%v', want = '%v'", got, tt.want)
			}
		})
	}
}

func TestIsValidIpRange(t *testing.T) {

	// Prepare and run test cases
	tests := []struct {
		name string
		s    string
		want bool
	}{
		{"ipv4-localhost", "127.0.0.1", false},
		{"ipv4-1", "8.8.8.8", false},
		{"ipv4-2", "123.123.123.123", false},

		{"ipv6-localhost", "1::", false},
		{"ipv6", "fe80:3::1ff:fe23:4567:890a", false},
		{"ipv6-embraced", "[fe80:3::1ff:fe23:4567:890a]", false},

		{"ipv4-range-1", "192.168.0.1/32", true},
		{"ipv4-range-254", "192.168.0.1/24", true},
		{"ipv4-range-4294967294", "192.168.0.1/0", true},
		{"ipv4-range-2147483646", "192.168.0.1/1", true},
		{"ipv6-range-20282409603651670423947251286016", "1::/24", true},
		{"ipv6-range-20282409603651670423947251286016", "fe80:3::1ff:fe23:4567:890a/24", true},
		{"ipv6-range-20282409603651670423947251286016-embraced", "[fe80:3::1ff:fe23:4567:890a]/24", false},

		{"domain-tld", "domain.tld", false},
		{"domain-root", "domain", false},

		{"ipv4-with-port", "123.123.123.123:443", false},
		{"ipv6-with-port", "[2001:db8:85a3:8d3:1319:8a2e:370:7348]:443", false},
		{"domain-with-port", "domain.tld:443", false},

		{"grabage", "in valid", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsValidIpRange(tt.s); got != tt.want {
				t.Errorf("IsValidIpRange() = '%v', want = '%v'", got, tt.want)
			}
		})
	}
}

func TestIsValidTarget(t *testing.T) {

	// Prepare and run test cases
	tests := []struct {
		name string
		s    string
		want bool
	}{
		{"ipv4-localhost", "127.0.0.1", true},
		{"ipv4-1", "8.8.8.8", true},
		{"ipv4-2", "123.123.123.123", true},

		{"ipv6-localhost", "1::", true},
		{"ipv6", "fe80:3::1ff:fe23:4567:890a", true},
		{"ipv6-embraced", "[fe80:3::1ff:fe23:4567:890a]", false},

		{"ipv4-range-1", "192.168.0.1/32", false},
		{"ipv4-range-254", "192.168.0.1/24", false},
		{"ipv4-range-4294967294", "192.168.0.1/0", false},
		{"ipv4-range-2147483646", "192.168.0.1/1", false},
		{"ipv6-range-20282409603651670423947251286016", "1::/24", false},
		{"ipv6-range-20282409603651670423947251286016", "fe80:3::1ff:fe23:4567:890a/24", false},
		{"ipv6-range-20282409603651670423947251286016-embraced", "[fe80:3::1ff:fe23:4567:890a]/24", false},

		{"domain-tld", "domain.tld", true},
		{"domain-root", "domain", true},

		{"ipv4-with-port", "123.123.123.123:443", false},
		{"ipv6-with-port", "[2001:db8:85a3:8d3:1319:8a2e:370:7348]:443", false},
		{"domain-with-port", "domain.tld:443", false},

		{"grabage", "in valid", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsValidAddress(tt.s); got != tt.want {
				t.Errorf("IsValidAddress() = '%v', want = '%v'", got, tt.want)
			}
		})
	}
}
