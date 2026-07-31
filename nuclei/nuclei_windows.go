/*
* GoScans, a collection of network scan modules for infrastructure discovery and information gathering.
*
* Copyright (c) Siemens AG, 2016-2026.
*
* This work is licensed under the terms of the MIT license. For a copy, see the LICENSE file in the top-level
* directory or visit <https://opensource.org/licenses/MIT>.
*
 */

package nuclei

import (
	"github.com/siemens/GoScans/utils"
)

// chownDirTree sets the ownership of all files and folders in templates directory
// to match the owner of the currently executing binary
func chownDirTree(logger utils.Logger, pathTemplates string) error {
	return nil
}
