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

const (
	// Waiting states
	StatusWaiting = "Waiting" // Default value of sql attribute on create, if not defined otherwise

	// Active states
	StatusRunning = "Running" // Scan is in progress

	// Success states
	StatusCompleted    = "Completed"               // Scan ran through without significant issues
	StatusDeadline     = "Completed With Deadline" // Deadline (scan timeout) reached
	StatusNotReachable = "Not Reachable"           // Connection/Socket error, target might not be online anymore
	StatusSkipped      = "Skipped"                 // Target might be on blacklist and not scanned

	// Error states
	StatusFailed     = "Failed"      // Scan crashed or vanished (e.g. agent restart, agent keyboard interrupt)
	StatusProxyError = "Proxy Error" // Proxy error might be suspicious, if a proxy is configured (web enum/crawler)
)
