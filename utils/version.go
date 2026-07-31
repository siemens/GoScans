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
	"fmt"
	"strconv"
	"strings"
)

// Version holds the major, minor, and patch components of a semantic version number.
type Version struct {
	Major int
	Minor int
	Patch int
}

// NewVersion generates a Version struct from a dot-separated version string such as "5.0.5".
func NewVersion(version string) (Version, error) {
	versionSlice := strings.Split(version, ".")
	versionSliceInt := make([]int, 3)
	for i, segment := range versionSlice {
		var errAtoi error
		versionSliceInt[i], errAtoi = strconv.Atoi(segment)
		if errAtoi != nil {
			return Version{}, fmt.Errorf("could not parse version string '%s'", version)
		}
	}
	return Version{
		Major: versionSliceInt[0],
		Minor: versionSliceInt[1],
		Patch: versionSliceInt[2],
	}, nil
}

// String returns the version in "major.minor.patch" dot-separated format.
func (v *Version) String() string {
	return fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Patch)
}

// IsGreaterThan reports whether the receiver version is strictly greater than otherVersion.
func (v *Version) IsGreaterThan(otherVersion Version) bool {
	if v.Major > otherVersion.Major {
		return true
	}
	if v.Major == otherVersion.Major && v.Minor > otherVersion.Minor {
		return true
	}
	if v.Major == otherVersion.Major && v.Minor == otherVersion.Minor && v.Patch > otherVersion.Patch {
		return true
	}
	return false
}

// IsGreaterEqualThan reports whether the receiver version is greater than or equal to otherVersion.
func (v *Version) IsGreaterEqualThan(otherVersion Version) bool {
	if v.IsGreaterThan(otherVersion) {
		return true
	}
	if v.Major == otherVersion.Major && v.Minor == otherVersion.Minor && v.Patch == otherVersion.Patch {
		return true
	}
	return false
}
