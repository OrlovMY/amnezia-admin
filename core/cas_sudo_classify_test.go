package core

import (
	"testing"

	"amnezia-admin/internal/fakesrv"
)

// TestSudoRefusedClosedList — какие ответы при повторе под sudo считаются
// отказом самого sudo («ничего не записано»), а какие — нет. Тексты sudo —
// дословно: классический sudo 1.9 и sudo-rs 0.2 (Ubuntu 25.10+; снят в WSL,
// журнал отчёта). Код 1 со сторонним текстом — не отказ sudo, а
// «неизвестно».
func TestSudoRefusedClosedList(t *testing.T) {
	for _, tc := range []struct {
		code   int
		stderr string
		want   bool
	}{
		{1, "sudo: a password is required", true},
		{1, "sudo: a terminal is required to read the password; either use the -S option to read from standard input or configure an askpass helper", true},
		{1, "Sorry, user admin is not allowed to execute '/usr/bin/docker exec -i amnezia-awg' as root on vps.", true},
		{1, "admin is not in the sudoers file.", true},
		{1, "sudo: I'm sorry a3b-none. I'm afraid I can't do that", true}, // sudo-rs
		{1, "", false},
		{1, "changed: wg0.conf", false},
		{1, "Error response from daemon: No such container: amnezia-awg", false},
		{1, "sudo: требуется пароль", false}, // перевод — не в списке: «неизвестно», в осторожную сторону
		{3, "sudo: a password is required", false},
	} {
		err := &fakesrv.ExitError{Cmd: "x", Status: tc.code, Stderr: tc.stderr}
		if got := casSudoRefused(err); got != tc.want {
			t.Errorf("код %d, %q: отказ sudo = %v, ждали %v", tc.code, tc.stderr, got, tc.want)
		}
	}
	if casSudoRefused(nil) {
		t.Error("nil — не отказ sudo")
	}
}
