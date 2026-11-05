package core

import (
	"runtime"
	"syscall"
)

// KeepAwakeSupported — на Windows запрет сна ставится.
const KeepAwakeSupported = true

const (
	esContinuous     = 0x80000000
	esSystemRequired = 0x00000001
)

var procSetThreadExecutionState = syscall.NewLazyDLL("kernel32.dll").NewProc("SetThreadExecutionState")

// KeepAwake — запретить сон ПК, пока не вызван stop (аудит AU GUI-TO-HOST
// M1б). SetThreadExecutionState действует на поток: держим его в отдельной
// горутине, привязанной к потоку ОС. ok=false — запрет не поставлен.
func KeepAwake() (stop func(), ok bool) {
	res := make(chan bool, 1)
	done := make(chan struct{})
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		r, _, _ := procSetThreadExecutionState.Call(uintptr(esContinuous | esSystemRequired))
		res <- r != 0
		<-done
		procSetThreadExecutionState.Call(uintptr(esContinuous))
	}()
	ok = <-res
	var once bool
	return func() {
		if !once {
			once = true
			close(done)
		}
	}, ok
}
