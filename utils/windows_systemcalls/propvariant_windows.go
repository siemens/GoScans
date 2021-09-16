package windows_systemcalls

import (
	"fmt"
	"github.com/go-ole/go-ole"
	"unsafe"
)

type PROPVARIANT struct {
	ole.VARIANT
}

// This function converts the value of the propvariant to a golang value, this function is not complete but can be
// extended further
func (pv *PROPVARIANT) ValueExt() (interface{}, error) {
	var value interface{}

	// Check if value conversion was already covered
	value = pv.Value()
	if value != nil {
		return value, nil
	}

	// further type handling
	switch pv.VT {
	case ole.VT_LPWSTR:
		return ole.UTF16PtrToString(*(**uint16)(unsafe.Pointer(&pv.Val))), nil
	case ole.VT_EMPTY:
		return nil, nil
	default:
		return nil, fmt.Errorf("type %s conversion not suporrted", pv.VT)
	}
}
