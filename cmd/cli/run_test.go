// Файл run_test.go — сквозные тесты полного run() (флаги → ConnectWithHostKey
// → LoadClients/... → confirmSubcommand/runDryRun) против настоящего
// fakesrv.ListenSSH (PR-4, ревью части Б, круг 1, BE-01 Low): до этого пути
// PR-5 (del без -yes без TTY) и PR-2 (-dry-run) проверялись только вызовом
// confirmOrExit/confirmSubcommand/runDryRun напрямую (confirm_test.go,
// main_test.go) — сама сборка run() (разбор флагов, ConnectWithHostKey,
// диспетчеризация по cmd) для этих двух семейств живым сервером не
// проверялась вовсе.
package main

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"

	"amnezia-admin/internal/fakesrv"
)

// setupFakeSSHForRun поднимает fakesrv.ListenSSH и "прогревает" known_hosts
// одним успешным list -hostkey — тесты этого файла проверяют не саму
// проверку ключа хоста (это TestNonTTYUnknownHostNeedsHostkey,
// hostkey_test.go), а то, что run() правильно доводит вызов до
// confirmSubcommand/runDryRun.
func setupFakeSSHForRun(t *testing.T) (key, knownHostsPath string) {
	t.Helper()
	const user, password = "root", "fakepw-run-e2e-test"
	hostKey, err := fakesrv.NewHostKey()
	if err != nil {
		t.Fatalf("NewHostKey: %v", err)
	}
	srv, err := fakesrv.ListenSSH("127.0.0.1:0", user, password, hostKey, fakesrv.New())
	if err != nil {
		t.Fatalf("ListenSSH: %v", err)
	}
	t.Cleanup(func() { srv.Close() })

	key = buildTestVpnKey(t, srv.Addr(), user, password)
	knownHostsPath = filepath.Join(t.TempDir(), "known_hosts")

	var out, errOut bytes.Buffer
	if code := run([]string{"list", "-key", key, "-hostkey", srv.Fingerprint()}, strings.NewReader(""), &out, &errOut, knownHostsPath); code != 0 {
		t.Fatalf("прогрев known_hosts (list -hostkey): code=%d stderr=%s", code, errOut.String())
	}
	return key, knownHostsPath
}

// TestRunDelWithoutYesNoTTYRefuses — PR-5, путь через ПОЛНЫЙ run(): del без
// -yes и без TTY обязан отказать (код 2) и НЕ удалить пользователя — сервер
// настоящий (fakesrv.ListenSSH), а не подмена confirmOrExit напрямую (как
// TestNonTTYWithoutYesExit2, confirm_test.go).
func TestRunDelWithoutYesNoTTYRefuses(t *testing.T) {
	key, knownHostsPath := setupFakeSSHForRun(t)

	var out, errOut bytes.Buffer
	code := run([]string{"del", "-key", key, "-name", "Alice"}, strings.NewReader(""), &out, &errOut, knownHostsPath)
	if code != 2 {
		t.Fatalf("code = %d, хочу 2; stderr:\n%s", code, errOut.String())
	}
	if !strings.Contains(errOut.String(), "-yes") {
		t.Errorf("stderr не содержит подсказку про -yes: %q", errOut.String())
	}

	// Alice всё ещё в списке — del не должен был выполниться.
	out.Reset()
	errOut.Reset()
	if code := run([]string{"list", "-key", key}, strings.NewReader(""), &out, &errOut, knownHostsPath); code != 0 {
		t.Fatalf("list после отказа del: code=%d stderr=%s", code, errOut.String())
	}
	if !strings.Contains(out.String(), "Alice") {
		t.Errorf("Alice пропала из списка, хотя del без -yes должен был отказать: %q", out.String())
	}
}

// TestRunDryRunAddViaEntry — PR-2, путь через ПОЛНЫЙ run(): -dry-run для add
// печатает diff и ничего не пишет на сервер — против настоящего fakesrv, а
// не runDryRun() напрямую (как TestRunDryRunAllActionsWriteNothing,
// main_test.go).
func TestRunDryRunAddViaEntry(t *testing.T) {
	key, knownHostsPath := setupFakeSSHForRun(t)

	var out, errOut bytes.Buffer
	code := run([]string{"add", "-dry-run", "-key", key, "-name", "Канарейка"}, strings.NewReader(""), &out, &errOut, knownHostsPath)
	if code != 0 {
		t.Fatalf("code = %d, хочу 0; stderr:\n%s", code, errOut.String())
	}
	if !strings.Contains(out.String(), "Ничего не записано (dry-run).") {
		t.Errorf("вывод не содержит финальную строку dry-run: %q", out.String())
	}

	// Канарейка не создана — dry-run ничего не пишет на сервер.
	out.Reset()
	errOut.Reset()
	if code := run([]string{"list", "-key", key}, strings.NewReader(""), &out, &errOut, knownHostsPath); code != 0 {
		t.Fatalf("list после dry-run: code=%d stderr=%s", code, errOut.String())
	}
	if strings.Contains(out.String(), "Канарейка") {
		t.Errorf("Канарейка появилась в списке — -dry-run не должен был ничего писать: %q", out.String())
	}
}
