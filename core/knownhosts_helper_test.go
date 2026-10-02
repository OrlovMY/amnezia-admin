package core

import "golang.org/x/crypto/ssh"

// appendKnownHost — только для тестов: подготовить known_hosts заранее.
// В программе такой обёртки нет (SEC-01): запись идёт через recordKnownHost
// с повторной проверкой под замком.
func appendKnownHost(path, addr string, key ssh.PublicKey) error {
	return withKnownHostsLock(path, func() error { return appendKnownHostLocked(path, addr, key) })
}
