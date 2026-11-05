//go:build !windows

package core

// KeepAwakeSupported — на этой ОС программа сон не запрещает.
const KeepAwakeSupported = false

// KeepAwake — на этой ОС ничего не делает (ok=false): человеку говорится
// прямо, что сон не запрещён.
func KeepAwake() (stop func(), ok bool) { return func() {}, false }
