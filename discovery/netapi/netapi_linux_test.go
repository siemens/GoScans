//go:build linux

/*
* GoScans, a collection of network scan modules for infrastructure discovery and information gathering.
*
* Copyright (c) Siemens AG, 2016-2026.
*
* This work is licensed under the terms of the MIT license. For a copy, see the LICENSE file in the top-level
* directory or visit <https://opensource.org/licenses/MIT>.
*
 */

package netapi

import (
	"testing"

	"github.com/siemens/GoScans/utils"
)

// TestGetGroupInfo_Linux verifies that the Linux stub of GetGroupInfo always returns an empty slice without error.
func TestGetGroupInfo_Linux(t *testing.T) {

	// Prepare unit test data
	testLogger := utils.NewTestLogger()

	// Verify stub returns empty result without error
	result, errResult := GetGroupInfo(testLogger, "192.0.2.1", "S-1-5-32-544")
	if errResult != nil {
		t.Errorf("GetGroupInfo() error = '%v', want = 'nil'", errResult)
	}
	if len(result) != 0 {
		t.Errorf("GetGroupInfo() result len = '%v', want = '0'", len(result))
	}
}
