/*
* GoScans, a collection of network scan modules for infrastructure discovery and information gathering.
*
* Copyright (c) Siemens AG, 2016-2021.
*
* This work is licensed under the terms of the MIT license. For a copy, see the LICENSE file in the top-level
* directory or visit <https://opensource.org/licenses/MIT>.
*
 */

package ssl

import (
	"fmt"
	"go-scans/utils"
	"gosslyze"
)

func parseSslyzeResult(logger utils.Logger, targetName string, hostResult *gosslyze.HostResult) *Data {

	// Check for nil pointer exceptions.
	if hostResult == nil {
		logger.Warningf("Provided SSLyze result is nil for target '%s'.", targetName)

		return &Data{
			Vhost:           targetName,
			Issues:          new(Issues),
			Ciphers:         make(map[string]*Cipher),
			CertDeployments: make([]*CertDeployment, 0),
		}
	}

	// Check whether SSLyze has any results
	if len(hostResult.Targets) == 0 {
		logger.Debugf("Did not get any results for host '%s'.", targetName)

		return &Data{
			Vhost:           targetName,
			Issues:          new(Issues),
			Ciphers:         make(map[string]*Cipher),
			CertDeployments: make([]*CertDeployment, 0),
		}
	}

	// We start a separate SSLyze scan for every target, therefore only one target should be returned.
	if len(hostResult.Targets) > 1 {
		logger.Warningf("Found multiple targets for host '%s' - only parsing first one.", targetName)
	}
	result := hostResult.Targets[0]

	// Initialize the Data struct. Set the target again as sometimes SSLyze only returns the IP.
	sslData := &Data{
		Vhost:           targetName,
		Ciphers:         make(map[string]*Cipher),
		CertDeployments: make([]*CertDeployment, 0),
	}

	// Parse the SSL/TLS basic data
	var errInfo error
	sslData.Issues, errInfo = parseIssues(&result.ScanResult)
	if errInfo != nil {
		logger.Warningf("Could not parse basic info: %s", errInfo)
	}

	// Parse information on the check against Mozilla's SSL recommended config
	var errComplianceCheck error
	sslData.ComplianceTestDetails, errInfo = parseComplianceCheck(hostResult)
	if errComplianceCheck != nil {
		logger.Warningf("Could not parse Mozilla's check information: %s", errComplianceCheck)
	}

	// Parse elliptic curves information
	var errEllip error
	sslData.EllipticCurves, errEllip = parseEllipticInfo(&result.ScanResult)
	if errEllip != nil {
		logger.Warningf("Could not parse elliptic curves information: %s", errEllip)
	}

	// Parse the Certificates
	var errCerts error
	sslData.CertDeployments,
		sslData.Issues.AnyChainInvalid,
		sslData.Issues.AnyChainInvalidOrder,
		errCerts = parseCertificateChains(logger, &result.ScanResult, targetName)
	if errCerts != nil {
		logger.Warningf("Could not process certificate chain: %s", errCerts)
	}

	// Parse the cipher suites
	var errCiphers error
	sslData.Ciphers,
		sslData.Issues.LowestProtocol,
		errCiphers = parseCiphers(logger, targetName, &result.ScanResult)
	if errCiphers != nil {
		logger.Warningf("Could not process cipher suites: %s", errCiphers)
	}

	// Set the additional information that can be derived from previously parsed information.
	errVuln := setCipherIssues(sslData)
	if errVuln != nil {
		logger.Warningf("Could not set vulnerabilities: %s", errVuln)
	}
	errStrength := setMinStrength(sslData)
	if errVuln != nil {
		logger.Warningf("Could not determine the minimum strength: %s", errStrength)
	}

	return sslData
}

// parseIssues creates and returns a issues struct with information on possible vulnerabilites.
func parseIssues(cr *gosslyze.CommandResults) (*Issues, error) {

	// Initialize the return structure.
	issues := &Issues{}

	// Check for nil pointer exceptions.
	if cr == nil {
		return issues, fmt.Errorf("provided SSLyze result is nil")
	}

	// General information
	if cr.EarlyData != nil {
		issues.EarlyDataSupported = cr.EarlyData.Result.IsSupported
	}

	// check whether session ID resumption was successful.
	if cr.Resumption != nil {
		if cr.Resumption.Result.AttemptedIdResumptions == cr.Resumption.Result.SuccessfulIdResumptions {
			issues.SessionResumptionWithId = true
		}

		// Check whether the server supports TLS ticket resumption.
		issues.SessionResumptionWithTickets = cr.Resumption.Result.TicketResumption == gosslyze.TicketResumptionSuccess
	}

	// Renegotiation information
	if cr.Renegotiation != nil {
		issues.InsecureRenegotiation = !cr.Renegotiation.Result.SupportsSecureRenegotiation
		issues.AcceptsClientRenegotiation = cr.Renegotiation.Result.VulnerableToClientRenegotiation
		issues.InsecureClientRenegotiation = issues.InsecureRenegotiation && issues.AcceptsClientRenegotiation
	}

	// Vulnerability information
	if cr.Compression != nil {
		issues.Compression = cr.Compression.Result.IsSupported
	}
	if cr.Heartbleed != nil {
		issues.Heartbleed = cr.Heartbleed.Result.IsVulnerable
	}
	if cr.OpensslCcs != nil {
		issues.CcsInjection = cr.OpensslCcs.Result.IsVulnerable
	}

	// Mozilla's Check information
	issues.IsCompliantToMozillaConfig = cr.IsCompliant

	return issues, nil
}

// parseEllipticInfo creates and returns an EllipticCurves struct with information on elliptic curves.
func parseEllipticInfo(cr *gosslyze.CommandResults) (*EllipticCurves, error) {

	// Initialize the return struct
	ellipticInfo := &EllipticCurves{}

	// Check for nil pointer
	if cr == nil {
		return ellipticInfo, fmt.Errorf("provided SSLyze result is nil")
	}

	// Accepted Elliptic Curves
	if cr.EllipticCurves.Result.SupportedCurves != nil {
		ellipticInfo.SupportedCurves = parseEllipticCurves(cr.EllipticCurves.Result.SupportedCurves)
	}

	// Rejected Elliptic Curves
	if cr.EllipticCurves.Result.RejectedCurves != nil {
		ellipticInfo.RejectedCurves = parseEllipticCurves(cr.EllipticCurves.Result.RejectedCurves)
	}

	// Check support for ECDH Key Exchange
	ellipticInfo.SupportECDHKeyExchange = cr.EllipticCurves.Result.SupportECDHKeyExchange

	return ellipticInfo, nil
}

func parseEllipticCurves(ec []gosslyze.Curve) []EllipticCurve {

	// Parse elliptic curves from GoSslyze
	var parsedCurves []EllipticCurve
	for _, curve := range ec {
		parsedCurves = append(parsedCurves, EllipticCurve{Name: curve.Name, OpenSSLnid: curve.OpenSSLnid})
	}
	return parsedCurves
}

// parseComplianceCheck parses details about Mozilla's check for SSL config
func parseComplianceCheck(result *gosslyze.HostResult) (string, error) {

	// Check for nil
	if result == nil {
		return "", fmt.Errorf("provided SSLyze result is nil")
	}

	// Return the check's results
	return result.ComplianceTestDetails, nil
}
