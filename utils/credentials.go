/*
* GoScans, a collection of network scan modules for infrastructure discovery and information gathering.
*
* Copyright (c) Siemens AG, 2016-2026.
*
* This work is licensed under the terms of the MIT license. For a copy, see the LICENSE file in the top-level
* directory or visit <https://opensource.org/licenses/MIT>.
*
 */

// Package utils provides common helper utilities shared across GoScans scan modules.
package utils

// ValidOrEmptyCredentials checks whether credentials are either all empty or at least user and password are set.
func ValidOrEmptyCredentials(domain string, user string, password string) bool {
	if domain == "" && user == "" && password == "" {
		return true
	}
	if user == "" || password == "" {
		return false
	}
	return true
}
