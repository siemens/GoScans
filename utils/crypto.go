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
	"bytes"
	"crypto/sha1"
	"fmt"
)

// HashSha1 returns the SHA-1 hash of a byte sequence as a hex-encoded string.
func HashSha1(data []byte, separator string) string {

	// Calculate SHA1
	hash := sha1.Sum(data)

	// Convert representation
	hexified := make([][]byte, len(hash))
	for i, byteVal := range hash {
		hexified[i] = []byte(fmt.Sprintf("%02X", byteVal))
	}

	// Return separator-formatted hash
	return string(bytes.Join(hexified, []byte(separator)))
}
