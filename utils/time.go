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

import (
	"context"
)

// ContextExpired checks whether a given deadline has been reached. Returns false if deadline is zero-time.
func ContextExpired(ctx context.Context) bool {
	if ctx == nil { // No context can't expire
		return false
	}
	if ctx.Err() != nil {
		return true
	}
	return false
}
