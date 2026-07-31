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
	"unsafe"

	"github.com/go-ole/go-ole"
)

// IPropertyStoreGuid is the COM interface GUID for IPropertyStore.
var IPropertyStoreGuid = ole.NewGUID("886d8eeb-8cf2-4446-8d02-cdba1dbdcf99")

// IPropertyStore is a COM wrapper for the Windows IPropertyStore interface.
type IPropertyStore struct {
	ole.IUnknown
}

// IPropertyStoreVtbl holds the virtual method table layout for IPropertyStore.
type IPropertyStoreVtbl struct {
	ole.IUnknownVtbl
	GetCount uintptr
	GetAt    uintptr
	GetValue uintptr
	SetValue uintptr
	Commit   uintptr
}

// VTable returns the IPropertyStore virtual method table.
func (v *IPropertyStore) VTable() *IPropertyStoreVtbl {
	return (*IPropertyStoreVtbl)(unsafe.Pointer(v.RawVTable))
}

// GetCount retrieves the number of properties in the property store.
func (v *IPropertyStore) GetCount(count *uint32) (errPsGetCount error) {
	errPsGetCount = psGetCount(v, count)
	return
}

// GetAt retrieves the property key at the given index.
func (v *IPropertyStore) GetAt(iProp uint32, pkey *PROPERTYKEY) error {
	return psGetAt(v, iProp, pkey)
}

// GetValue retrieves the value of the property identified by key.
func (v *IPropertyStore) GetValue(key *PROPERTYKEY, pv *PROPVARIANT) (errPsGetValue error) {
	errPsGetValue = psGetValue(v, key, pv)
	return
}

// SetValue is not implemented and always returns E_NOTIMPL.
func (v *IPropertyStore) SetValue() (errPsSetValue error) {
	errPsSetValue = psSetValue()
	return
}

// Commit is not implemented and always returns E_NOTIMPL.
func (v *IPropertyStore) Commit() (errPsCommit error) {
	errPsCommit = psCommit()
	return
}
