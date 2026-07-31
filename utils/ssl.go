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
	conn, errConn := tls.DialWithDialer(
		&net.Dialer{Timeout: dialTimeout},
		"tcp",
		fmt.Sprintf("%s:%d", address, port),
		InsecureTlsConfigFactory(), // Insecure, because this is not a user interface, we are trying to discover content...
	)
	if errConn != nil {
		return nil, errConn
	}

	// Make sure connection gets closed on exit
	defer func() { _ = conn.Close() }()

	// Grab certificate from the chain
	certChain := conn.ConnectionState().PeerCertificates

	// Return subject and subject alternative names
	if len(certChain) == 0 {
		return nil, fmt.Errorf("certificate chain is empty")
	}
	return certChain[0].DNSNames, nil
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
		MinVersion:         tls.VersionSSL30, //lint:ignore SA1019 needed to advertise SSLv3 support during security scans
		MaxVersion:         tls.VersionTLS13,
		CipherSuites:       ciphers,
		Renegotiation:      tls.RenegotiateFreelyAsClient, // Required for legacy/OT devices that demand renegotiation
	}
}
