/*
* GoScans, a collection of network scan modules for infrastructure discovery and information gathering.
*
* Copyright (c) Siemens AG, 2016-2026.
*
* This work is licensed under the terms of the MIT license. For a copy, see the LICENSE file in the top-level
* directory or visit <https://opensource.org/licenses/MIT>.
*
 */

package windows_systemcalls

import (
	"reflect"
	"syscall"
	"unsafe"

	"github.com/go-ole/go-ole"
	"golang.org/x/sys/windows"
)

var modShell32 = windows.NewLazySystemDLL("shell32.dll")                                            // Lazy-loaded handle to the Windows shell32 DLL
var procSHGetPropertyStoreFromParsingName = modShell32.NewProc("SHGetPropertyStoreFromParsingName") // Procedure for retrieving a property store for a file-system path

// SHGetPropertyStoreFromParsingName retrieves a property store for the file-system item identified by pszPath.
func SHGetPropertyStoreFromParsingName(pszPath *uint16, pbc *IBindCtx, flags uint32, riid *ole.GUID, obj interface{}) (errErrno error) {
	objValue := reflect.ValueOf(obj).Elem()
	r0, _, _ := syscall.SyscallN(
		procSHGetPropertyStoreFromParsingName.Addr(),
		uintptr(unsafe.Pointer(pszPath)),
		uintptr(unsafe.Pointer(pbc)),
		uintptr(flags),
		uintptr(unsafe.Pointer(riid)),
		objValue.Addr().Pointer())

	if r0 != 0 {
		errErrno = syscall.Errno(r0)
	}

	return
}

// psGetCount retrieves the number of properties in the property store.
func psGetCount(ps *IPropertyStore, count *uint32) (errNewError error) {
	hr, _, _ := syscall.SyscallN(
		ps.VTable().GetCount,
		uintptr(unsafe.Pointer(ps)),
		uintptr(unsafe.Pointer(count)))
	if hr != 0 {
		errNewError = ole.NewError(hr)
	}
	return
}

// psGetAt retrieves the property key at the given index in the property store.
func psGetAt(ps *IPropertyStore, iProp uint32, pkey *PROPERTYKEY) (errNewError error) {
	hr, _, _ := syscall.SyscallN(
		ps.VTable().GetAt,
		uintptr(unsafe.Pointer(ps)),
		uintptr(iProp),
		uintptr(unsafe.Pointer(pkey)))
	if hr != 0 {
		errNewError = ole.NewError(hr)
	}
	return
}

// psGetValue retrieves the value associated with the given property key.
func psGetValue(ps *IPropertyStore, key *PROPERTYKEY, pv *PROPVARIANT) (errNewError error) {
	hr, _, _ := syscall.SyscallN(
		ps.VTable().GetValue,
		uintptr(unsafe.Pointer(ps)),
		uintptr(unsafe.Pointer(key)),
		uintptr(unsafe.Pointer(pv)))
	if hr != 0 {
		errNewError = ole.NewError(hr)
	}
	return
}

// psSetValue is not implemented and always returns E_NOTIMPL.
func psSetValue() (err error) {
	return ole.NewError(ole.E_NOTIMPL)
}

// psCommit is not implemented and always returns E_NOTIMPL.
func psCommit() (err error) {
	return ole.NewError(ole.E_NOTIMPL)
}
