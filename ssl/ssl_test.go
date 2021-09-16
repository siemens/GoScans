/*
* GoScans, a collection of network scan modules for infrastructure discovery and information gathering.
*
* Copyright (c) Siemens AG, 2016-2021.
*
* This work is licensed under the terms of the MIT license. For a copy, see the LICENSE file in the top-level
* directory or visit <https://opensource.org/licenses/MIT>.
*
 */

package ssl

import (
	"go-scans/utils"
	"testing"
)

func TestScanner_LoadCiphers(t *testing.T) {

	// Prepare test variables
	testLogger := utils.NewTestLogger()

	// Test load
	LoadCiphers(testLogger)
}

func TestScanner_DuplicateCiphers(t *testing.T) {

	// Prepare test variables
	testLogger := utils.NewTestLogger()

	LoadCiphers(testLogger)

	for name, ciphers := range cipherMapping {
		if len(ciphers) != 1 {
			if len(ciphers) != 2 {
				t.Errorf("Normally there's a maximum of 2 ciphers with the same OpenSSL name. We have '%d'.", len(ciphers))
				continue
			}

			if (ciphers[0].Id == "0x010080" && ciphers[1].Id == "0x04") || //  RC4-MD5
				(ciphers[0].Id == "0x04" && ciphers[1].Id == "0x010080") || // RC4-MD5
				(ciphers[0].Id == "0x040080" && ciphers[1].Id == "0x06") || // EXP-RC2-CBC-MD5
				(ciphers[0].Id == "0x06" && ciphers[1].Id == "0x040080") || // EXP-RC2-CBC-MD5
				(ciphers[0].Id == "0x020080" && ciphers[1].Id == "0x03") || // EXP-RC4-MD5
				(ciphers[0].Id == "0x03" && ciphers[1].Id == "0x020080") { //  EXP-RC4-MD5
				continue
			}

			// Unknown duplicates.
			t.Errorf("Unknown duplicates: %s", name)
		}
	}
}
