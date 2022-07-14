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
	"crypto/tls"
	"fmt"
	"net"
	"time"
)

// GetSubjectAlternativeNames Connects to SSL endpoint and extracts subject name
// and subject alternative names from the SSL certificate. This function does not
// check whether the peer certificate is a CA.
func GetSubjectAlternativeNames(address string, port int, dialTimeout time.Duration) ([]string, error) {
	// Connect to endpoint
	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: dialTimeout},
		"tcp",
		fmt.Sprintf("%s:%d", address, port),
		InsecureTlsConfigFactory(), // Insecure, because this is not a user interface, we are trying to discover content...
	)
	if err != nil {
		return nil, err
	}

	// Grab certificate from the chain
	certChain := conn.ConnectionState().PeerCertificates

	// Return subject and subject alternative names
	if len(certChain) == 0 {
		return nil, fmt.Errorf("certificate chain is empty")
	} else {
		return certChain[0].DNSNames, nil
	}
}

// InsecureTlsConfigFactory returns an *INSECURE* SSL connection configuration allowing any supported SSL protocol,
// and skipping SSL verification routines. This configuration is intended to scan modules and may not be used for
// user interfaces!
func InsecureTlsConfigFactory() *tls.Config {

	// Prepare list of accepted cipher suites
	var ciphers []uint16
	for _, cipher := range tls.CipherSuites() {
		ciphers = append(ciphers, cipher.ID)
	}
	for _, cipher := range tls.InsecureCipherSuites() {
		ciphers = append(ciphers, cipher.ID)
	}

	// Return insecure TLS config
	return &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionSSL30, // If zero, TLS 1.0 is currently taken by the TLS package as the minimum.
		MaxVersion:         tls.VersionTLS12, // If zero, the maximum version supported by the TLS package is used
		CipherSuites:       ciphers,
	}
}
