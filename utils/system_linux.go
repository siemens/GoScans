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
	"os"
)

// Check whether the current process is running with admin privileges on Linux
func IsElevated() bool {

	// Check env variables for sudo user are set
	if len(os.Getenv("SUDO_UID")) > 0 {

		// Check if process is running as root
		if os.Geteuid() == 0 {
			return true
		}

		// Return false by default
		return false
	}

	// Return false by default
	return false
}
