//go:build !windows

package core

import (
	"errors"
	"os"
	"syscall"
)

// tryLockFile — неблокирующая исключительная блокировка flock(2) на f.
// busy=true — замок держит другой процесс (или другой дескриптор).
func tryLockFile(f *os.File) (busy bool, err error) {
	err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
	if errors.Is(err, syscall.EWOULDBLOCK) {
		return true, nil
	}
	return false, err
}

// unlockFile снимает замок (закрытие файла сняло бы его тоже).
func unlockFile(f *os.File) error {
	return syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
}
