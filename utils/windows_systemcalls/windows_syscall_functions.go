/*
* GoScans, a collection of network scan modules for infrastructure discovery and information gathering.
*
* Copyright (c) Siemens AG, 2016-2021.
*
* This work is licensed under the terms of the MIT license. For a copy, see the LICENSE file in the top-level
* directory or visit <https://opensource.org/licenses/MIT>.
*
 */

package windows_systemcalls

/*
This file defines all windows api functions we want to use. If a new function should be added, then add the function
signature and run the go generate command to generate the function body.
*/

//go:generate go run golang.org/x/sys/windows/mkwinsyscall -output zwindows_syscall_functions.go windows_syscall_functions.go

//sys  NetShareEnum(serverName *uint16, level uint32, buf **byte, prefMaxLen uint32, entriesRead *uint32, totalEntries *uint32, resumeHandle *uint32) (neterr error) = netapi32.NetShareEnum
//sys  NetShareGetInfo(serverName *uint16, netName *uint16, level uint32, buf **byte) (neterr error) = netapi32.NetShareGetInfo
//sys  WNetAddConnection2(netResource *Netresource, password *uint16, username *uint16, flags uint32) (neterr error) = mpr.WNetAddConnection2W
// sys  WNetCancelConnection2(name *uint16, flags uint32, force bool) (neterr error) = mpr.WNetCancelConnection2W
// sys  NetDfsGetInfo(DfsEntryPath *uint16, ServerName *uint16, ShareName *uint16, Level uint32, Buffer **byte) (neterr error) = netapi32.NetDfsGetInfo
