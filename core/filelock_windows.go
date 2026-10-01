//go:build windows

package core

import (
	"errors"
	"os"

	"golang.org/x/sys/windows"
)

// tryLockFile — неблокирующая исключительная блокировка LockFileEx на
// первый байт f. busy=true — замок держит другой процесс (или другой
// дескриптор).
func tryLockFile(f *os.File) (busy bool, err error) {
	ol := new(windows.Overlapped)
	err = windows.LockFileEx(windows.Handle(f.Fd()),
		windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, ol)
	if errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
		return true, nil
	}
	return false, err
}

// unlockFile снимает замок (закрытие дескриптора сняло бы его тоже).
func unlockFile(f *os.File) error {
	return windows.UnlockFileEx(windows.Handle(f.Fd()), 0, 1, 0, new(windows.Overlapped))
}
