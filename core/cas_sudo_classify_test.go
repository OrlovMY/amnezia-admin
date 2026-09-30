package core

import (
	"errors"
	"strings"
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
		// SEC-01 R1: метка скрипта «not moved:» — скрипт работал, sudo пустил
		{1, "sudo: a password is required\nnot moved: clientsTable: Permission denied", false},
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

// TestSudoPassedScriptFailedIsUnknown — AU-LOGIC M-1, доезд: sudo ПРОПУСТИЛ,
// а настоящий скрипт упал кодом 1 (rename: mv на clientsTable отказал) —
// итог «неизвестно, записано ли», а не «sudo отказал». Код 1 у повтора
// под sudo общий; отказом sudo он становится только по тексту sudo.
func TestSudoPassedScriptFailedIsUnknown(t *testing.T) {
	srv := fakesrv.New()
	srv.FailMvTo = "clientsTable"
	sess := NewSessionWithRunner(sockDeniedRunner{srv}, testCreds())
	c := awgContainer()
	clients, err := sess.LoadClients(c)
	if err != nil {
		t.Fatal(err)
	}
	err = sess.RenameUser(c, clients[0].ClientID, "Renamed")
	if err == nil {
		t.Fatal("переименование прошло, хотя mv отказал")
	}
	if errors.Is(err, ErrSudoDenied) {
		t.Errorf("sudo пропустил, скрипт упал — а итог «sudo отказал»: %v", err)
	}
	if !errors.Is(err, ErrWriteUnknown) {
		t.Errorf("ждали ErrWriteUnknown: %v", err)
	}
	sudoRuns := 0
	for _, cmd := range srv.Commands() {
		if strings.Contains(cmd, fakesrv.CASSudoInfix) {
			sudoRuns++
		}
	}
	if sudoRuns != 1 {
		t.Errorf("записей под sudo дошло до сервера %d, ждали ровно 1 — сценарий не тот", sudoRuns)
	}
}

// TestSudoInfixMatchesCore — копия формы повтора в fakesrv совпадает с
// командой ядра (иначе второй признак F1 в fakesrv онемеет, AU-LOGIC M-2).
func TestSudoInfixMatchesCore(t *testing.T) {
	cmd, err := CASWriteCommandSudo(CASLabelApply, "amnezia-awg", "/opt/amnezia/awg", strings.Repeat("a", 64), CASAbsent)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(cmd, " "+fakesrv.CASSudoInfix+" ") {
		t.Errorf("команда повтора %.90q не содержит fakesrv.CASSudoInfix %q", cmd, fakesrv.CASSudoInfix)
	}
}
