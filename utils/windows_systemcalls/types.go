//go:build windows

/*
* GoScans, a collection of network scan modules for infrastructure discovery and information gathering.
*
* Copyright (c) Siemens AG, 2016-2026.
*
* This work is licensed under the terms of the MIT license. For a copy, see the LICENSE file in the top-level
* directory or visit <https://opensource.org/licenses/MIT>.
*
 */

// Package windows_systemcalls provides Windows-specific system-call wrappers and type definitions
// used by GoScans modules (SMB, shell32 property store, NetAPI32, MPR).
package windows_systemcalls

import "github.com/go-ole/go-ole"

// GPS_DEFAULT is the default flag for SHGetPropertyStoreFromParsingName (no special options).
const GPS_DEFAULT = 0

type DWORD uint32   // Windows double word represented as uint32
type LPWSTR *uint16 // Pointer to a UTF-16 Windows string
type LMSTR *uint16  // Pointer to a UTF-16 LAN Manager string
type ULONG uint32   // Windows unsigned long represented as uint32

// Netresource maps to the Windows NETRESOURCE struct used by WNet API calls.
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

// SHARE_INFO_1 maps to the Windows SHARE_INFO_1 struct returned by NetShareEnum at level 1.
type SHARE_INFO_1 struct {
	Netname LMSTR
	Type    DWORD
	Remark  LMSTR
}

// SHARE_INFO_1005 maps to the Windows SHARE_INFO_1005 struct containing share flags.
type SHARE_INFO_1005 struct {
	Flags DWORD
}

// DFS_STORAGE_INFO maps to the Windows DFS_STORAGE_INFO struct describing a DFS storage target.
type DFS_STORAGE_INFO struct {
	State      ULONG
	ServerName LPWSTR
	ShareName  LPWSTR
}

// DFS_INFO_3 maps to the Windows DFS_INFO_3 struct returned by NetDfsGetInfo at level 3.
type DFS_INFO_3 struct {
	EntryPath        LPWSTR
	Comment          LPWSTR
	State            DWORD
	NumberOfStorages DWORD
	DfsStorageInfo   *DFS_STORAGE_INFO
}

// SHARE_INFO_2 maps to the Windows SHARE_INFO_2 struct returned by NetShareEnum at level 2.
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

// PROPERTYKEY maps to the Windows PROPERTYKEY struct identifying a shell property.
type PROPERTYKEY struct {
	ole.GUID
	PID uint32
}

// IBindCtx is a COM wrapper for the Windows IBindCtx interface used during property store retrieval.
type IBindCtx struct {
	ole.IUnknown
}
