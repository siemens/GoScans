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
	"github.com/noneymous/GoSslyze"
	"go-scans/utils"
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
	sslData.Issues, errInfo = parseIssues(&result.CommandResults)
	if errInfo != nil {
		logger.Warningf("Could not parse basic info: %s", errInfo)
	}

	// Parse the Certificates
	var errCerts error
	sslData.CertDeployments,
		sslData.Issues.AnyChainInvalid,
		sslData.Issues.AnyChainInvalidOrder,
		errCerts = parseCertificateChains(logger, &result.CommandResults, targetName)
	if errCerts != nil {
		logger.Warningf("Could not process certificate chain: %s", errCerts)
	}

	// Parse the cipher suites
	var errCiphers error
	sslData.Ciphers,
		sslData.Issues.CipherPreference,
		sslData.Issues.LowestProtocol,
		errCiphers = parseCiphers(logger, targetName, &result.CommandResults)
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
		issues.EarlyDataSupported = cr.EarlyData.IsSupported
	}

	// check whether session ID resumption was successful.
	if cr.Resumption != nil {
		if cr.Resumption.AttemptedIdResumptions == cr.Resumption.SuccessfulIdResumptions {
			issues.SessionResumptionWithId = true
		}

		// Check whether the server supports TLS ticket resumption.
		issues.SessionResumptionWithTickets = cr.Resumption.TicketResumption == gosslyze.TicketResumptionSuccess
	}

	// Renegotiation information
	if cr.Renegotiation != nil {
		issues.InsecureRenegotiation = !cr.Renegotiation.SupportsSecureRenegotiation
		issues.AcceptsClientRenegotiation = cr.Renegotiation.AcceptsClientRenegotiation
		issues.InsecureClientRenegotiation = issues.InsecureRenegotiation && issues.AcceptsClientRenegotiation
	}

	// Vulnerability information
	if cr.Compression != nil {
		issues.Compression = cr.Compression.IsSupported
	}
	if cr.Heartbleed != nil {
		issues.Heartbleed = cr.Heartbleed.IsVulnerable
	}
	if cr.OpensslCcs != nil {
		issues.CcsInjection = cr.OpensslCcs.IsVulnerable
	}

	return issues, nil
}
