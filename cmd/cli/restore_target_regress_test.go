package main

import (
	"path/filepath"
	"strings"
	"testing"
)

// TestCLIRestoreTargetUsersRefused — регресс (задача владельца 07.10): на
// новом сервере есть пользователи (Alice, Bob fakesrv); -apply -yes без
// -replace-users — отказ, код 2, ни одной записи; в выводе — число и
// имена. Только старые флаги — на 25e2377 падает поведением (там запись).
func TestCLIRestoreTargetUsersRefused(t *testing.T) {
	keyA, khA, srcExec := setupFakeSSHForRunWithExec(t)
	srcExec.SetFile("/opt/amnezia/awg/wireguard_psk.key", []byte("OLD-PSK\n"))
	p := filepath.Join(t.TempDir(), "c.aabk")
	if code, _, e := cliRun(t, khA, "", "backup", "-key", keyA, "-o", p, "-no-password"); code != 0 {
		t.Fatalf("backup: %d %s", code, e)
	}
	keyB, khB, tgt := setupFakeSSHForRunWithExec(t)
	tgt.SetFile("/opt/amnezia/awg/wireguard_psk.key", []byte("NEW-PSK\n"))

	code, out, _ := cliRun(t, khB, "", "restore", "-key", keyB, "-file", p, "-apply", "-yes")
	if code != 2 || flocks(tgt) != 0 {
		t.Fatalf("без -replace-users: код %d, записей %d\n%s", code, flocks(tgt), out)
	}
	for _, part := range []string{"уже есть пользователи — 2", "Alice, Bob", "КОНФЛИКТ: имя «Alice»", "-replace-users"} {
		if !strings.Contains(out, part) {
			t.Errorf("в выводе нет «%s»:\n%s", part, out)
		}
	}
	if w, rm := strings.Index(out, "ВНИМАНИЕ"), strings.Index(out, "Копия: формат"); w < 0 || w > rm {
		t.Errorf("предупреждение не первым разделом:\n%s", out)
	}

}
