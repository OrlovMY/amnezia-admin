//go:build windows

// Слой machine-bind для .avlt через DPAPI (CryptProtectData/CryptUnprotectData).
package core

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

func init() {
	dpapiProtect = dpapiProtectWindows
	dpapiUnprotect = dpapiUnprotectWindows
}

func dpapiProtectWindows(secret []byte) ([]byte, error) {
	if len(secret) == 0 {
		return nil, fmt.Errorf("пустой секрет")
	}
	in := windows.DataBlob{
		Size: uint32(len(secret)),
		Data: &secret[0],
	}
	var out windows.DataBlob
	if err := windows.CryptProtectData(&in, nil, nil, 0, nil, 0, &out); err != nil {
		return nil, fmt.Errorf("CryptProtectData: %w", err)
	}
	defer windows.LocalFree(windows.Handle(uintptr(unsafe.Pointer(out.Data))))
	return copyDataBlob(out), nil
}

func dpapiUnprotectWindows(blob []byte) ([]byte, error) {
	if len(blob) == 0 {
		return nil, fmt.Errorf("пустой блоб")
	}
	in := windows.DataBlob{
		Size: uint32(len(blob)),
		Data: &blob[0],
	}
	var out windows.DataBlob
	if err := windows.CryptUnprotectData(&in, nil, nil, 0, nil, 0, &out); err != nil {
		return nil, fmt.Errorf("CryptUnprotectData: %w", err)
	}
	defer windows.LocalFree(windows.Handle(uintptr(unsafe.Pointer(out.Data))))
	return copyDataBlob(out), nil
}

func copyDataBlob(b windows.DataBlob) []byte {
	if b.Size == 0 || b.Data == nil {
		return nil
	}
	out := make([]byte, b.Size)
	src := unsafe.Slice(b.Data, b.Size)
	copy(out, src)
	return out
}
