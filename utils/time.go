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
	"time"
)

// DeadlineReached checks whether a given deadline has been reached. Returns false if deadline is zero-time.
func DeadlineReached(deadline time.Time) bool {
	if deadline.IsZero() {
		return false
	} else if time.Now().After(deadline) {
		return true
	} else {
		return false
	}
}
