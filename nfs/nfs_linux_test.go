/*
* GoScans, a collection of network scan modules for infrastructure discovery and information gathering.
*
* Copyright (c) Siemens AG, 2016-2026.
*
* This work is licensed under the terms of the MIT license. For a copy, see the LICENSE file in the top-level
* directory or visit <https://opensource.org/licenses/MIT>.
*
 */

package nfs

import (
	"os"
	"strings"
	"testing"
)

// TestDeleteMountPoint_EmptyDir_RemovesDir verifies that deleteMountPoint successfully removes an existing empty directory.
func TestDeleteMountPoint_EmptyDir_RemovesDir(t *testing.T) {

	// Prepare unit test data
	dir, errDir := os.MkdirTemp(".", "test-mount-point-*")
	if errDir != nil {
		t.Errorf("MkdirTemp() error = '%v'", errDir)
		return
	}

	// Verify the directory is removed without error
	errDelete := deleteMountPoint(dir)
	if errDelete != nil {
		t.Errorf("deleteMountPoint() error = '%v', want = 'nil'", errDelete)
		// Clean up in case of failure so the test dir is not left behind
		_ = os.Remove(dir)
		return
	}

	// Verify the directory no longer exists on disk
	_, errStat := os.Stat(dir)
	if !os.IsNotExist(errStat) {
		t.Errorf("deleteMountPoint() dir still exists after deletion, stat error = '%v'", errStat)
		_ = os.Remove(dir)
	}
}

// TestDeleteMountPoint_NonExistentDir_ReturnsError verifies that deleteMountPoint returns an error when the path does not exist.
func TestDeleteMountPoint_NonExistentDir_ReturnsError(t *testing.T) {

	// Prepare unit test data
	nonExistent := "./does-not-exist-12345-xyz"

	// Verify an error is returned for a missing path
	errDelete := deleteMountPoint(nonExistent)
	if errDelete == nil {
		t.Errorf("deleteMountPoint() error = 'nil', want = 'non-nil' for non-existent path '%v'", nonExistent)
	}
}

// TestExecWithUserInput_ValidCommand_ReturnsOutput verifies that execWithUserInput runs a command and returns its combined output.
func TestExecWithUserInput_ValidCommand_ReturnsOutput(t *testing.T) {

	// Prepare and run test cases
	tests := []struct {
		name          string
		cmd           string
		wantSubstring string
	}{
		{
			name:          "echo-command-returns-text",
			cmd:           "echo hello-world",
			wantSubstring: "hello-world",
		},
		{
			name:          "true-command-returns-no-error",
			cmd:           "true",
			wantSubstring: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			// Verify command executes successfully and output contains expected substring
			out, errOut := execWithUserInput(tt.cmd, []string{})
			if errOut != nil {
				t.Errorf("execWithUserInput() error = '%v', want = 'nil'", errOut)
				return
			}
			if tt.wantSubstring != "" && !strings.Contains(out, tt.wantSubstring) {
				t.Errorf("execWithUserInput() output = '%v', want to contain = '%v'", out, tt.wantSubstring)
			}
		})
	}
}

// TestExecWithUserInput_InvalidCommand_ReturnsError verifies that execWithUserInput returns an error when the command fails.
func TestExecWithUserInput_InvalidCommand_ReturnsError(t *testing.T) {

	// Prepare and run test cases
	tests := []struct {
		name string
		cmd  string
	}{
		{
			name: "failing-exit-code",
			cmd:  "false",
		},
		{
			name: "nonexistent-command",
			cmd:  "command-that-does-not-exist-xyz-12345",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			// Verify error is returned for a failing command
			_, errExecWithUserInput := execWithUserInput(tt.cmd, []string{})
			if errExecWithUserInput == nil {
				t.Errorf("execWithUserInput() error = 'nil', want = 'non-nil' for cmd '%v'", tt.cmd)
			}
		})
	}
}
