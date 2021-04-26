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

func ValidOrEmptyCredentials(domain string, user string, password string) bool {
	if domain == "" && user == "" && password == "" {
		return true
	} else {
		if user == "" || password == "" {
			return false
		}
	}
	return true
}
