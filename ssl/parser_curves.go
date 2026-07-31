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

// parseEllipticInfo creates and returns a Curves struct with information on elliptic curves.
func parseEllipticInfo(cr *gosslyze.CommandResults) (*Curves, error) {

	// Initialize the return struct
	ellipticInfo := &Curves{}

	// Check for nil pointer
	if cr == nil {
		return ellipticInfo, fmt.Errorf("provided SSLyze result is nil")
	}

	if cr.EllipticCurves != nil && cr.EllipticCurves.Result != nil {
		// Accepted Elliptic Curves
		if cr.EllipticCurves.Result.SupportedCurves != nil {
			ellipticInfo.SupportedCurves = parseEllipticCurves(cr.EllipticCurves.Result.SupportedCurves)
		}

		// Rejected Elliptic Curves
		if cr.EllipticCurves.Result.RejectedCurves != nil {
			ellipticInfo.RejectedCurves = parseEllipticCurves(cr.EllipticCurves.Result.RejectedCurves)
		}

		// Check support for ECDH Key Exchange
		ellipticInfo.SupportEcdhKeyExchange = cr.EllipticCurves.Result.SupportEcdhKeyExchange
	}

	// Return elliptic curve data
	return ellipticInfo, nil
}

// parseEllipticCurves converts a slice of GoSslyze Curve structs into the internal EllipticCurve representation.
func parseEllipticCurves(ec []gosslyze.Curve) []EllipticCurve {

	// Parse elliptic curves from GoSslyze
	var parsedCurves []EllipticCurve
	for _, curve := range ec {
		parsedCurves = append(parsedCurves, EllipticCurve{Name: curve.Name, OpenSslNid: curve.OpenSslNid})
	}
	return parsedCurves
}
