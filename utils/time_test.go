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
	"testing"
	"time"
)

func TestDeadlineReached(t *testing.T) {
	tests := []struct {
		name     string
		deadline time.Time
		want     bool
	}{
		{"reached-1", time.Now().Add(-time.Second), true},
		{"reached-2", time.Now().Add(-time.Hour), true},
		{"not-reached-1", time.Now().Add(time.Second), false},
		{"not-reached-2", time.Now().Add(time.Hour), false},
		{"not-reached-zerotime", time.Time{}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := DeadlineReached(tt.deadline); got != tt.want {
				t.Errorf("DeadlineReached() = '%v', want = '%v'", got, tt.want)
			}
		})
	}
}
