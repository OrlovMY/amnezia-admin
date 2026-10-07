package main

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestCLIRestoreTargetUsersAsk — терминал: отдельный вопрос; не то слово —
// отмена без записи; «записать» — запись.
func TestCLIRestoreTargetUsersAsk(t *testing.T) {
	keyA, khA, srcExec := setupFakeSSHForRunWithExec(t)
	srcExec.SetFile("/opt/amnezia/awg/wireguard_psk.key", []byte("OLD-PSK\n"))
	p := filepath.Join(t.TempDir(), "c.aabk")
	if code, _, e := cliRun(t, khA, "", "backup", "-key", keyA, "-o", p, "-no-password"); code != 0 {
		t.Fatalf("backup: %d %s", code, e)
	}
	keyB, khB, tgt := setupFakeSSHForRunWithExec(t)
	tgt.SetFile("/opt/amnezia/awg/wireguard_psk.key", []byte("NEW-PSK\n"))
	sess := cliSession(t, keyB, khB)
	var o, e bytes.Buffer
	code := runRestore(context.Background(), strings.NewReader("y\ny\n"), &o, &e, true, sess, p, "", true, false, false, false, false, time.Now())
	if code != 2 || flocks(tgt) != 0 || !strings.Contains(o.String(), "Всё равно записать?") {
		t.Fatalf("терминал, ответ «y»: код %d записей %d\n%s", code, flocks(tgt), o.String())
	}
	o.Reset()
	code = runRestore(context.Background(), strings.NewReader("y\nЗаписать\n"), &o, &e, true, sess, p, "", true, false, false, false, false, time.Now())
	if code != 0 || flocks(tgt) == 0 || !strings.Contains(o.String(), "amnezia-awg: восстановлен") {
		t.Fatalf("терминал, «записать»: код %d записей %d\n%s\n%s", code, flocks(tgt), o.String(), e.String())
	}
}

// TestCLIRestoreCoreGate — AU-LOGIC З2: проверка CLI обойдена — ядро без
// полученного подтверждения само не пишет.
func TestCLIRestoreCoreGate(t *testing.T) {
	keyA, khA, srcExec := setupFakeSSHForRunWithExec(t)
	srcExec.SetFile("/opt/amnezia/awg/wireguard_psk.key", []byte("OLD-PSK\n"))
	p := filepath.Join(t.TempDir(), "c.aabk")
	if code, _, e := cliRun(t, khA, "", "backup", "-key", keyA, "-o", p, "-no-password"); code != 0 {
		t.Fatalf("backup: %d %s", code, e)
	}
	keyB, khB, tgt := setupFakeSSHForRunWithExec(t)
	tgt.SetFile("/opt/amnezia/awg/wireguard_psk.key", []byte("NEW-PSK\n"))
	bypassTargetGate = true
	t.Cleanup(func() { bypassTargetGate = false })
	code, out, e := cliRun(t, khB, "", "restore", "-key", keyB, "-file", p, "-apply", "-yes")
	if code == 0 || flocks(tgt) != 0 || !strings.Contains(e, "без отдельного подтверждения запрещена") {
		t.Fatalf("код %d записей %d\n%s\n%s", code, flocks(tgt), out, e)
	}
}

// TestCLIRestoreTargetUsersYesTTY — QA Minor PR #43: терминал, -yes без
// -replace-users, на цели есть пользователи — отказ своим текстом CLI и
// кодом 2 до ядра (а не ошибкой ядра), без вопроса и без записи.
func TestCLIRestoreTargetUsersYesTTY(t *testing.T) {
	keyA, khA, srcExec := setupFakeSSHForRunWithExec(t)
	srcExec.SetFile("/opt/amnezia/awg/wireguard_psk.key", []byte("OLD-PSK\n"))
	p := filepath.Join(t.TempDir(), "c.aabk")
	if code, _, e := cliRun(t, khA, "", "backup", "-key", keyA, "-o", p, "-no-password"); code != 0 {
		t.Fatalf("backup: %d %s", code, e)
	}
	keyB, khB, tgt := setupFakeSSHForRunWithExec(t)
	tgt.SetFile("/opt/amnezia/awg/wireguard_psk.key", []byte("NEW-PSK\n"))
	sess := cliSession(t, keyB, khB)
	var o, e bytes.Buffer
	code := runRestore(context.Background(), strings.NewReader("Записать\n"), &o, &e, true, sess, p, "", true, false, false, false, true, time.Now())
	if code != 2 || flocks(tgt) != 0 || !strings.Contains(o.String(), replaceUsersRefuse) || strings.Contains(o.String(), "Всё равно записать?") {
		t.Fatalf("терминал, -yes без -replace-users: код %d записей %d\n%s\n%s", code, flocks(tgt), o.String(), e.String())
	}
}
