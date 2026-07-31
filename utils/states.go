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

// StatusWaiting is the default SQL state when no explicit scan state is supplied
const StatusWaiting = "Waiting"

// StatusRunning indicates that a scan is in progress
const StatusRunning = "Running"

// Success states
const StatusCompleted = "Completed"              // Scan ran through without significant issues
const StatusDeadline = "Completed With Deadline" // Deadline (scan timeout) reached
const StatusNotReachable = "Not Reachable"       // Connection or socket error. The target might not be online anymore
const StatusSkipped = "Skipped"                  // Target might be on the blacklist and not scanned

// Error states
const StatusFailed = "Failed"          // Scan crashed or vanished, for example due to an agent restart or interrupt
const StatusProxyError = "Proxy Error" // Proxy errors might be suspicious when a proxy is configured
