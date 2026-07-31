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
	"fmt"

	gosslyze "github.com/noneymous/GoSslyze"
)

// parseSettings parses the available info for SSL settings
func parseSettings(cr *gosslyze.CommandResults) (*Settings, error) {

	// Initialize the return structure.
	settings := &Settings{}

	// Check for nil pointer exceptions.
	if cr == nil {
		return settings, fmt.Errorf("provided SSLyze result is nil")
	}

	// Check for Downgrade Attacks Prevention
	if cr.Fallback != nil && cr.Fallback.Result != nil {
		settings.TlsFallbackScsv = cr.Fallback.Result.IsSupported
	}

	// Check for TLS extended master secret extension
	if cr.TlsEms != nil && cr.TlsEms.Result != nil {
		settings.Ems = cr.TlsEms.Result.SupportsEmsExtension
	}

	// Check for secure Renegotiation
	if cr.Renegotiation != nil && cr.Renegotiation.Result != nil {
		settings.SecureRenegotiation = cr.Renegotiation.Result.SupportsSecureRenegotiation
	}

	// Check whether session ID resumption was successful.
	if cr.Resumption != nil && cr.Resumption.Result != nil {
		if cr.Resumption.Result.AttemptedIdResumptions == cr.Resumption.Result.SuccessfulIdResumptions {
			settings.SessionResumptionWithId = true
		}

		// Check whether the server supports TLS ticket resumption.
		settings.SessionResumptionWithTickets = cr.Resumption.Result.TicketResumption == gosslyze.TicketResumptionSuccess
	}

	// Mozilla's Check information
	settings.IsCompliantToMozillaConfig = cr.IsCompliant

	// Return the checks results
	return settings, nil
}
