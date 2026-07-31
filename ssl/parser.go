/*
* GoScans, a collection of network scan modules for infrastructure discovery and information gathering.
*
* Copyright (c) Siemens AG, 2016-2026.
*
* This work is licensed under the terms of the MIT license. For a copy, see the LICENSE file in the top-level
* directory or visit <https://opensource.org/licenses/MIT>.
*
 */

package ssl

import (
	gosslyze "github.com/noneymous/GoSslyze"
	"github.com/siemens/GoScans/utils"
)

// parseSslyzeResult converts a raw SSLyze host result into the internal Data structure.
func parseSslyzeResult(logger utils.Logger, targetName string, hostResult *gosslyze.HostResult) *Data {

	// Check for nil pointer exceptions.
	if hostResult == nil {
		logger.Warningf("Provided SSLyze result is nil for target '%s'.", targetName)

		return &Data{
			Vhost:    targetName,
			Ciphers:  make(map[string]*Cipher),
			Chains:   make([]*Chain, 0),
			Settings: new(Settings),
			Issues:   new(Issues),
		}
	}

	// Check whether SSLyze has any results
	if len(hostResult.Targets) == 0 {
		logger.Debugf("Did not get any results for host '%s'.", targetName)
		return &Data{
			Vhost:    targetName,
			Ciphers:  make(map[string]*Cipher),
			Chains:   make([]*Chain, 0),
			Settings: new(Settings),
			Issues:   new(Issues),
		}
	}

	// Check whether amount of results matches expectation, there should only be one
	if len(hostResult.Targets) > 1 {
		logger.Warningf("Found multiple targets for host '%s' - only parsing first one.", targetName)
	}

	// Retrieve result
	result := hostResult.Targets[0]

	// Initialize the result data struct. Set the target again as sometimes SSLyze only returns the IP.
	sslData := &Data{
		Vhost:   targetName,
		Ciphers: make(map[string]*Cipher),
		Chains:  make([]*Chain, 0),
	}

	// Parse basic issues data
	var errInfo error
	sslData.Issues, errInfo = parseIssues(&result.ScanResult)
	if errInfo != nil {
		logger.Debugf("Could not parse basic info: %s", errInfo)
	}

	// Parse elliptic curves information
	var errEllip error
	sslData.Curves, errEllip = parseEllipticInfo(&result.ScanResult)
	if errEllip != nil {
		logger.Debugf("Could not parse elliptic curves information: %s", errEllip)
	}

	// Parse the certificates information
	var errCerts error
	sslData.Chains,
		sslData.Issues.AnyChainInvalid,
		sslData.Issues.AnyChainInvalidOrder,
		errCerts = parseCertificateChains(logger, &result.ScanResult, targetName)
	if errCerts != nil {
		logger.Debugf("Could not process certificate chain: %s", errCerts)
	}

	// Parse SSL settings information
	var errSettings error
	sslData.Settings, errSettings = parseSettings(&result.ScanResult)
	if errSettings != nil {
		logger.Debugf("Could not parse TLS settings: %s", errSettings)
	}

	// Parse the cipher suites information
	var errCiphers error
	sslData.Ciphers,
		sslData.Settings.LowestProtocol,
		errCiphers = parseCiphers(logger, targetName, &result.ScanResult)
	if errCiphers != nil {
		logger.Debugf("Could not process cipher suites: %s", errCiphers)
	}

	// Parse additional issue information that can be derived from previously parsed information
	errVuln := parseIssuesCiphers(sslData)
	if errVuln != nil {
		logger.Debugf("Could not set vulnerabilities: %s", errVuln)
	}

	// Parse and calculate minimum cipher strength
	errStrength := parseMinStrength(sslData)
	if errStrength != nil {
		logger.Debugf("Could not determine the minimum strength: %s", errStrength)
	}

	// Return SSL results
	return sslData
}
