package windows_systemcalls

import (
	"github.com/go-ole/go-ole"
	"golang.org/x/sys/windows"
	"reflect"
	"syscall"
	"unsafe"
)

var (
	modShell32                            = windows.NewLazySystemDLL("shell32.dll")
	procSHGetPropertyStoreFromParsingName = modShell32.NewProc("SHGetPropertyStoreFromParsingName")
)

func SHGetPropertyStoreFromParsingName(pszPath *uint16, pbc *IBindCtx, flags uint32, riid *ole.GUID, obj interface{}) (err error) {
	objValue := reflect.ValueOf(obj).Elem()
	r0, _, _ := syscall.Syscall6(
		procSHGetPropertyStoreFromParsingName.Addr(),
		5,
		uintptr(unsafe.Pointer(pszPath)),
		uintptr(unsafe.Pointer(pbc)),
		uintptr(flags),
		uintptr(unsafe.Pointer(riid)),
		objValue.Addr().Pointer(),
		0)

	if r0 != 0 {
		err = syscall.Errno(r0)
	}

	return
}

func psGetCount(ps *IPropertyStore, count *uint32) (err error) {
	hr, _, _ := syscall.Syscall(
		ps.VTable().GetCount,
		2,
		uintptr(unsafe.Pointer(ps)),
		uintptr(unsafe.Pointer(count)),
		0)
	if hr != 0 {
		err = ole.NewError(hr)
	}
	return
}

func psGetAt(ps *IPropertyStore, iProp uint32, pkey *PROPERTYKEY) (err error) {
	hr, _, _ := syscall.Syscall(
		ps.VTable().GetAt,
		3,
		uintptr(unsafe.Pointer(ps)),
		uintptr(iProp),
		uintptr(unsafe.Pointer(pkey)))
	if hr != 0 {
		err = ole.NewError(hr)
	}
	return
}

func psGetValue(ps *IPropertyStore, key *PROPERTYKEY, pv *PROPVARIANT) (err error) {
	hr, _, _ := syscall.Syscall(
		ps.VTable().GetValue,
		3,
		uintptr(unsafe.Pointer(ps)),
		uintptr(unsafe.Pointer(key)),
		uintptr(unsafe.Pointer(pv)))
	if hr != 0 {
		err = ole.NewError(hr)
	}
	return
}

func psSetValue() (err error) {
	return ole.NewError(ole.E_NOTIMPL)
}

func psCommit() (err error) {
	return ole.NewError(ole.E_NOTIMPL)
}
