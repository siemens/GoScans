/*
* GoScans, a collection of network scan modules for infrastructure discovery and information gathering.
*
* Copyright (c) Siemens AG, 2016-2026.
*
* This work is licensed under the terms of the MIT license. For a copy, see the LICENSE file in the top-level
* directory or visit <https://opensource.org/licenses/MIT>.
*
 */

package nuclei

import (
	"fmt"
	"strconv"
	"strings"

	nucleihttp "github.com/projectdiscovery/nuclei/v3/pkg/protocols/http"
	nucleijavascript "github.com/projectdiscovery/nuclei/v3/pkg/protocols/javascript"
	nucleinetwork "github.com/projectdiscovery/nuclei/v3/pkg/protocols/network"
	nucleissl "github.com/projectdiscovery/nuclei/v3/pkg/protocols/ssl"
	nucleiwebsocket "github.com/projectdiscovery/nuclei/v3/pkg/protocols/websocket"
	nucleitemplates "github.com/projectdiscovery/nuclei/v3/pkg/templates"
	"github.com/siemens/GoScans/utils"
)

// GetPortTemplates returns the IDs of templates relevant for a given port.
// Inclusion logic:
//   - If includeIds is empty:
//     Include templates that match the provided port OR have a dynamic port
//     AND whose ID is not in excludeIds
//   - If includeIds is not empty:
//     Include templates whose ID is in includeIds AND
//     have a port matching the provided port OR a dynamic port
func GetPortTemplates(
	logger utils.Logger,
	pathTemplates string,
	port int,
	includeIds []string,
	excludeIds []string,
) ([]string, error) {

	// Acquire the catalog shared by scanners using this template root
	catalog, errCatalog := acquireTemplateCatalog(pathTemplates)
	if errCatalog != nil {
		return nil, fmt.Errorf("could not acquire template catalog: %w", errCatalog)
	}

	// Apply the same selection contract used by Scanner execution
	ids, _, errSelection := selectPortTemplates(logger, catalog, port, includeIds, excludeIds)
	if errSelection != nil {
		return nil, fmt.Errorf("could not select port templates: %w", errSelection)
	}

	// Return the selected template identifiers
	return ids, nil
}

// selectPortTemplates returns matching identifiers and paths from an existing catalog reference
func selectPortTemplates(
	logger utils.Logger,
	catalog *templateCatalog,
	port int,
	includeIds []string,
	excludeIds []string,
) ([]string, []string, error) {

	// Select templates relevant for the requested service port
	sources, errSources := catalog.portSources(logger, port)
	if errSources != nil {
		return nil, nil, fmt.Errorf("could not load port template sources: %w", errSources)
	}

	// Apply caller specific identifier filters to the cached selection
	ids, paths := filterTemplateSources(sources, includeIds, excludeIds)

	// Return synchronized identifier and path slices
	return ids, paths, nil
}

// templateRelevantForPort applies the established GoScans port selection rules without compilation
func templateRelevantForPort(template *nucleitemplates.Template, port int) bool {

	// Exclude protocols that are reserved for host scans
	if len(template.RequestsDNS) > 0 || len(template.RequestsWHOIS) > 0 {
		return false
	}

	// Reject templates containing an HTTP request for another port
	for _, request := range template.RequestsHTTP {
		if !isHttpRequestAllowed(port, request) {
			return false
		}
	}

	// Reject templates containing a JavaScript request for another port
	for _, request := range template.RequestsJavascript {
		if !isJavascriptRequestAllowed(port, request) {
			return false
		}
	}

	// Reject templates containing a network request for another port
	for _, request := range template.RequestsNetwork {
		if !isNetworkRequestAllowed(port, request) {
			return false
		}
	}

	// Reject templates containing an SSL request for another port
	for _, request := range template.RequestsSSL {
		if !isSslRequestAllowed(port, request) {
			return false
		}
	}

	// Reject templates containing a WebSocket request for another port
	for _, request := range template.RequestsWebsocket {
		if !isWebsocketRequestAllowed(port, request) {
			return false
		}
	}

	// Accept templates containing at least one supported service request
	serviceRequestCount := len(template.RequestsHTTP) +
		len(template.RequestsNetwork) +
		len(template.RequestsSSL) +
		len(template.RequestsWebsocket) +
		len(template.RequestsJavascript)
	hasServiceRequests := serviceRequestCount > 0

	// Return whether the template contains a supported service request
	return hasServiceRequests
}

// --------------------------
// Per-protocol checks
// --------------------------

// isHttpRequestAllowed checks whether an HTTP request entry is valid for the user port.
// https://pkg.go.dev/github.com/projectdiscovery/nuclei/v3@v3.4.10/pkg/protocols/http#Request
// The rules are:
// - Accept entries that contain dynamic placeholders implying port injection ({{Port}}, {{BaseURL}}, etc.)
// - Accept entries that explicitly hardcode the requested port in a Host:Port pattern
func isHttpRequestAllowed(port int, req *nucleihttp.Request) bool {

	// User port string for comparisons
	userPortStr := strconv.Itoa(port)

	// Helper that validates a single string entry (Path or Raw)
	checkEntry := func(s string) bool {

		// Empty entries are invalid
		if s == "" {
			return false
		}

		// Case: {{Host}}:<port>
		if strings.Contains(s, "{{Host}}:") || strings.Contains(s, "{{Hostname}}:") || strings.Contains(s, "{{BaseURL}}:") {

			m := portRegex.FindStringSubmatch(s)
			if m != nil {
				// Explicit port found → must match exactly
				return m[1] == userPortStr
			}

			// Not matching ports -> reject
			return false
		}

		// Accept known service-oriented placeholders that imply port injection
		if strings.Contains(s, "{{BaseURL}}") ||
			strings.Contains(s, "{{RootURL}}") ||
			strings.Contains(s, "{{Hostname}}") ||
			strings.Contains(s, "{{Port}}") {
			return true
		}

		// Default reject
		return false
	}

	// Validate all Path entries; if any fails, the request is not allowed
	for _, p := range req.Path {
		if !checkEntry(p) {
			return false
		}
	}

	// Validate all Raw entries; if any fails, the request is not allowed
	for _, r := range req.Raw {
		if !checkEntry(r) {
			return false
		}
	}

	// All entries passed → HTTP request allowed
	return true
}

// isNetworkRequestAllowed checks whether a network request entry is valid for the user port.
// https://pkg.go.dev/github.com/projectdiscovery/nuclei/v3@v3.4.10/pkg/protocols/network#Request
// Rules:
// - If explicit Port field is present, it must be "{{Port}}" or equal to the UserPort.
// - Otherwise, check Address entries for either ":{{Port}}" or a hardcoded host:port matching UserPort.
func isNetworkRequestAllowed(port int, req *nucleinetwork.Request) bool {

	// User port string for comparisons
	userPortStr := strconv.Itoa(port)

	// Case 1: Explicit Port field
	if req.Port != "" {
		// Accept dynamic placeholder
		if req.Port == "{{Port}}" {
			return true
		}
		// Accept exact hardcoded port equal to the user port
		if req.Port == userPortStr {
			return true
		}
		return false
	}

	// Case 2: Check each Address in the slice
	for _, addr := range req.Address {
		// Dynamic port injection pattern -> allow.
		if strings.Contains(addr, ":{{Port}}") {
			return true
		}

		// Hardcoded host:port pattern -> compare it with user port
		m := portRegex.FindStringSubmatch(addr)
		if m != nil && m[1] == userPortStr {
			return true
		}
	}

	// Default reject
	return false
}

// isSslRequestAllowed checks whether an SSL request entry is valid for the user port.
// https://pkg.go.dev/github.com/projectdiscovery/nuclei/v3@v3.4.10/pkg/protocols/ssl#Request
// Acceptance rules:
// - Accept dynamic ":{{Port}}" patterns.
// - Accept explicit host:port with the exact user port.
func isSslRequestAllowed(port int, req *nucleissl.Request) bool {

	// If address contains the dynamic placeholder for Port, allow it.
	if strings.Contains(req.Address, ":{{Port}}") {
		return true
	}

	// If address is in host:port format, check if port matches the user port.
	m := portRegex.FindStringSubmatch(req.Address)
	if m != nil {
		// Explicit port found → must match exactly
		return m[1] == strconv.Itoa(port)
	}

	// Default reject
	return false
}

// isWebsocketRequestAllowed checks whether a WebSocket request entry is valid for the user port.
// https://pkg.go.dev/github.com/projectdiscovery/nuclei/v3@v3.4.10/pkg/protocols/websocket#Request
// Acceptance rules:
// - Accept ":{{Port}}" dynamic injection.
// - Accept hardcoded host:port equal to UserPort.
// - If no explicit port is present use standard ws/wss defaults (80/443).
func isWebsocketRequestAllowed(port int, req *nucleiwebsocket.Request) bool {

	// Extract the address to evaluate
	addr := req.Address

	// Allow dynamic port injection patterns
	if strings.Contains(addr, ":{{Port}}") {
		return true
	}

	m := portRegex.FindStringSubmatch(addr)
	if m != nil {
		// Explicit port found → must match exactly
		return m[1] == strconv.Itoa(port)
	}

	// No explicit port: allow standard ws/wss defaults when they match user port
	if strings.HasPrefix(addr, "ws://") && port == 80 {
		return true
	}
	if strings.HasPrefix(addr, "wss://") && port == 443 {
		return true
	}

	// Default reject
	return false
}

// isJavascriptRequestAllowed checks whether a JavaScript request entry is valid for the user port.
// https://pkg.go.dev/github.com/projectdiscovery/nuclei/v3@v3.4.10/pkg/protocols/javascript#Request
// Accepts when the "Port" arg exists and either uses "{{Port}}" or hardcodes the matching user port.
func isJavascriptRequestAllowed(port int, req *nucleijavascript.Request) bool {

	// Look up the "Port" argument in the request's Args map
	portVal, ok := req.Args["Port"]
	if !ok {
		// No port argument provided → reject
		return false
	}

	// Convert the value to string
	portStr := fmt.Sprint(portVal)

	// Allow the dynamic placeholder
	if portStr == "{{Port}}" {
		return true
	}

	// If the port argument is numeric, compare to the UserPort
	p, errP := strconv.Atoi(portStr)
	if errP == nil {
		return p == port
	}

	// Default reject
	return false
}
