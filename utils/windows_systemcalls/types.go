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

import "github.com/go-ole/go-ole"

const GPS_DEFAULT = 0

type (
	DWORD  uint32  // go, medium, github w32, outside windows: uint32
	LPWSTR *uint16 // Struct go *uint16 StartupInfo(w)
	LMSTR  *uint16 // Func: *uint16 NetshareAdd, Struct: go *uint16 (share_info_2) strings have to be converted to pointer and pointer have to be converted back to strings
	ULONG  uint32
)

type Netresource struct {
	Scope       DWORD
	Type        DWORD
	DisplayType DWORD
	Usage       DWORD
	LocalName   LPWSTR
	RemoteName  LPWSTR
	Comment     LPWSTR
	Provider    LPWSTR
}

type SHARE_INFO_1 struct {
	Netname LMSTR
	Type    DWORD
	Remark  LMSTR
}

type SHARE_INFO_1005 struct {
	Flags DWORD
}

type DFS_STORAGE_INFO struct {
	State      ULONG
	ServerName LPWSTR
	ShareName  LPWSTR
}

type DFS_INFO_3 struct {
	EntryPath        LPWSTR
	Comment          LPWSTR
	State            DWORD
	NumberOfStorages DWORD
	DfsStorageInfo   *DFS_STORAGE_INFO
}

type SHARE_INFO_2 struct {
	Netname     *uint16
	Type        uint32
	Remark      *uint16
	Permissions uint32
	MaxUses     uint32
	CurrentUses uint32
	Path        *uint16
	Passwd      *uint16
}

type PROPERTYKEY struct {
	ole.GUID
	PID uint32
}

type IBindCtx struct {
	ole.IUnknown
}
