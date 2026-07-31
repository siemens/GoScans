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
	"fmt"
	"unsafe"

	"github.com/go-ole/go-ole"
)

// PROPVARIANT wraps the OLE VARIANT to add shell property conversion support.
type PROPVARIANT struct {
	ole.VARIANT
}

// ValueExt converts the value of the propvariant to a Go value. The conversion is not exhaustive and can be extended.
func (pv *PROPVARIANT) ValueExt() (interface{}, error) {

	// Check if value conversion was already covered
	value := pv.Value()
	if value != nil {
		return value, nil
	}

	// Further type handling
	switch pv.VT {
	case ole.VT_LPWSTR:
		return ole.UTF16PtrToString(*(**uint16)(unsafe.Pointer(&pv.Val))), nil
	case ole.VT_EMPTY:
		return nil, nil
	default:
		return nil, fmt.Errorf("type %s conversion not supported", pv.VT)
	}
}
