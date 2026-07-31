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
	"syscall"
	"testing"
)

// TestUtf16PtrToString verifies that utf16PtrToString correctly converts a UTF-16 pointer back to a Go string, including edge cases like empty and long strings.
func TestUtf16PtrToString(t *testing.T) {

	// Prepare and run test cases
	type args struct {
		str string
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "empty",
			args: args{str: ""},
		},
		{
			name: "single-character-1",
			args: args{str: "1"},
		},
		{
			name: "single-character-2",
			args: args{str: "2"},
		},
		{
			name: "normal-string-1",
			args: args{str: "This is a normal test string."},
		},
		{
			name: "normal-string-2",
			args: args{str: "This is a normal test string with some escaped characters \t \n \v \\ \a \b \f \r \"."},
		},
		{
			name: "long-string",
			args: args{str: "This is a very long text, exceeding the capacity (512) of the internal uint16 slice. Lorem ipsum dolor sit amet, consetetur sadipscing elitr, sed diam nonumy eirmod tempor invidunt ut labore et dolore magna aliquyam erat, sed diam voluptua. At vero eos et accusam et justo duo dolores et ea rebum. Stet clita kasd gubergren, no sea takimata sanctus est Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet, consetetur sadipscing elitr, sed diam nonumy eirmod tempor invidunt ut labore et dolore magna aliquyam erat, sed diam voluptua. At vero eos et accusam et justo duo dolores et ea rebum. Stet clita kasd gubergren, no sea takimata sanctus est Lorem ipsum dolor sit amet. Lorem ip"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Simply convert back and forth
			strPtr, errStrPtr := syscall.UTF16PtrFromString(tt.args.str)
			if errStrPtr != nil {
				// It's an error, but it is not in the function that we actually want to test. Therefore only log and
				// skip it.
				t.Skipf("Could not convert the string '%s' to an '*uint16' - skipping: %s", tt.args.str, errStrPtr)
			}

			str := utf16PtrToString(strPtr)

			if str != tt.args.str {
				t.Errorf("utf16PtrToString() = '%v', want = '%v'", str, tt.args.str)
			}
		})
	}
}
