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
	"bytes"
	"crypto/sha1"
	"fmt"
)

// Returns the sha1 of a byte sequence
func HashSha1(data []byte, separator string) string {

	// Calculate SHA1
	hash := sha1.Sum(data)

	// Convert representation
	hexified := make([][]byte, len(hash))
	for i, data := range hash {
		hexified[i] = []byte(fmt.Sprintf("%02X", data))
	}

	// Return separator-formatted hash
	return fmt.Sprintf("%s", string(bytes.Join(hexified, []byte(separator))))
}
