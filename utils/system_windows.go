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
	"syscall"
)

// Check whether the current process is running with admin privileges on Windows
func IsElevated() bool {

	// Open current process token
	hToken, err := syscall.OpenCurrentProcessToken()
	if err != nil {
		return false
	}

	// Prepare some result variables
	n := uint32(4)
	b := make([]byte, n)

	// Get token information
	e := syscall.GetTokenInformation(hToken, syscall.TokenElevation, &b[0], uint32(len(b)), &n)
	if e != nil {
		return false
	}

	// Validate escalation bit
	if *(&b[0]) == 1 {
		return true
	}

	// Return false by default
	return false
}
