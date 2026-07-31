/*
* GoScans, a collection of network scan modules for infrastructure discovery and information gathering.
*
* Copyright (c) Siemens AG, 2016-2026.
*
* This work is licensed under the terms of the MIT license. For a copy, see the LICENSE file in the top-level
* directory or visit <https://opensource.org/licenses/MIT>.
*
 */

package ad

import (
	"github.com/siemens/GoScans/utils"
)

// AdodbQuery queries the given Active Directory service with implicit Windows authentication and returns a
// pointer to a populated Ad struct.
// ATTENTION: Make sure searchCn / ldapAddress are sanitized if taken from user input, to avoid SQL injection attacks!
func AdodbQuery(logger utils.Logger, searchCn string, searchDomain string) *Ad {

	// Prepare return data
	return &Ad{}
}
