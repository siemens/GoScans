/*
* GoScans, a collection of network scan modules for infrastructure discovery and information gathering.
*
* Copyright (c) Siemens AG, 2016-2026.
*
* This work is licensed under the terms of the MIT license. For a copy, see the LICENSE file in the top-level
* directory or visit <https://opensource.org/licenses/MIT>.
*
 */

// Package netapi provides platform-specific network API wrappers for host discovery.
package netapi

import (
	"github.com/siemens/GoScans/utils"
)

// GetGroupInfo is a Linux stub that always returns an empty list, as NetAPI is Windows-only.
func GetGroupInfo(logger utils.Logger, target, sidString string) ([]string, error) {
	return []string{}, nil
}
