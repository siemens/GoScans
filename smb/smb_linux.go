/*
* GoScans, a collection of network scan modules for infrastructure discovery and information gathering.
*
* Copyright (c) Siemens AG, 2016-2021.
*
* This work is licensed under the terms of the MIT license. For a copy, see the LICENSE file in the top-level
* directory or visit <https://opensource.org/licenses/MIT>.
*
 */

package smb

import "github.com/siemens/GoScans/filecrawler"

// crawl enumerates shares and crawls each of them one by one
func (s *Scanner) crawl() *filecrawler.Result {

	// This code should not be contained in Windows builds!
	panic("SMB not implemented for Linux")
}
