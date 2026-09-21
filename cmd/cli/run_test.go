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
	"encoding/json"
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
	key, knownHostsPath, _ = setupFakeSSHForRunWithExec(t)
	return key, knownHostsPath
}

// setupFakeSSHForRunWithExec — то же, но отдаёт и фейковую ФС сервера:
// сквозным тестам нужно подготовить состояние (например, клиента с именем
// из одних цифр), которого нет в дефолтном fakesrv.New().
func setupFakeSSHForRunWithExec(t *testing.T) (key, knownHostsPath string, exec *fakesrv.Server) {
	t.Helper()
	const user, password = "root", "fakepw-run-e2e-test"
	hostKey, err := fakesrv.NewHostKey()
	if err != nil {
		t.Fatalf("NewHostKey: %v", err)
	}
	exec = fakesrv.New()
	srv, err := fakesrv.ListenSSH("127.0.0.1:0", user, password, hostKey, exec)
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
	return key, knownHostsPath, exec
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

// renameFirstClientTo переименовывает первого клиента в фейковой
// clientsTable, чтобы сквозной тест мог получить клиента с нужным именем
// (в дефолтном fakesrv.New() это Alice и Bob).
func renameFirstClientTo(t *testing.T, exec *fakesrv.Server, newName string) {
	t.Helper()
	const path = "/opt/amnezia/awg/clientsTable"
	raw, ok := exec.File(path)
	if !ok {
		t.Fatal("подготовка: clientsTable нет в фейковой ФС")
	}
	var list []map[string]any
	if err := json.Unmarshal(raw, &list); err != nil {
		t.Fatalf("подготовка: разбор clientsTable: %v", err)
	}
	if len(list) == 0 {
		t.Fatal("подготовка: clientsTable пуста")
	}
	ud, ok := list[0]["userData"].(map[string]any)
	if !ok {
		t.Fatalf("подготовка: нет userData в записи: %+v", list[0])
	}
	ud["clientName"] = newName
	out, err := json.MarshalIndent(list, "", "    ")
	if err != nil {
		t.Fatalf("подготовка: сборка clientsTable: %v", err)
	}
	exec.SetFile(path, out)
}

// TestRunDelNumericNameAnnouncesBeforeDeleting — СКВОЗНОЙ доезд для
// флагового пути (ревью QA-01, подмена N18, круг 3).
//
// ЗАЧЕМ ИМЕННО СКВОЗНОЙ. До человека доезжает не текст, а вызов.
// TestResolveByFlagReachesHuman проверяет обёртку resolveByFlag, а
// internal/resolveguard считает синтаксические вызовы — ни то, ни другое не
// видит, КУДА пишет боевая ветка. Подмена «боевое место пишет Note в
// io.Discard вместо stdout» компилируется, оставляет оба прежних теста
// зелёными, и `amnezia-admin del -name 12` снова удаляет МОЛЧА. Здесь
// проверяется настоящий run() против настоящего fakesrv.ListenSSH: что
// предупреждение попало в stdout и что оно стоит ПЕРЕД карточкой
// необратимого действия — после действия оно бесполезно.
func TestRunDelNumericNameAnnouncesBeforeDeleting(t *testing.T) {
	key, knownHostsPath, exec := setupFakeSSHForRunWithExec(t)
	renameFirstClientTo(t, exec, "12")

	var out, errOut bytes.Buffer
	code := run([]string{"del", "-key", key, "-name", "12", "-yes"}, strings.NewReader(""), &out, &errOut, knownHostsPath)
	if code != 0 {
		t.Fatalf("code = %d, хочу 0 (имя главнее номера — команда обязана выполниться); stderr:\n%s", code, errOut.String())
	}
	got := out.String()

	// 1. Предупреждение доехало до stdout боевой команды.
	notePos := strings.Index(got, "Это ИМЯ, а не номер")
	if notePos < 0 {
		t.Fatalf("del -name 12 удалил МОЛЧА: в stdout нет предупреждения, кого поняли.\nstdout:\n%s", got)
	}
	if !strings.Contains(got, "продолжаю с ним") {
		t.Errorf("предупреждение не говорит, что действие продолжается: %q", got[notePos:])
	}

	// 2. Оно стоит ПЕРЕД карточкой необратимого действия.
	cardPos := strings.Index(got, "Действие: удалить")
	if cardPos < 0 {
		t.Fatalf("в stdout нет карточки действия — тест якорится не на то:\n%s", got)
	}
	if notePos > cardPos {
		t.Errorf("предупреждение напечатано ПОСЛЕ карточки действия (%d > %d) — человек узнаёт, кого поняли, слишком поздно:\n%s", notePos, cardPos, got)
	}

	// 3. Удалён именно тот, кого объявили.
	out.Reset()
	errOut.Reset()
	if code := run([]string{"list", "-key", key}, strings.NewReader(""), &out, &errOut, knownHostsPath); code != 0 {
		t.Fatalf("list после del: code=%d stderr=%s", code, errOut.String())
	}
	if strings.Contains(out.String(), "Bob") == false {
		t.Errorf("удалён не тот клиент — Bob пропал:\n%s", out.String())
	}
}

// TestRunRenameNumericNameAnnouncesBeforeRenaming — тот же доезд для
// rename: у него карточки подтверждения НЕТ ВОВСЕ, поэтому предупреждение
// resolveByFlag — единственное, что человек видит до необратимого действия.
func TestRunRenameNumericNameAnnouncesBeforeRenaming(t *testing.T) {
	key, knownHostsPath, exec := setupFakeSSHForRunWithExec(t)
	renameFirstClientTo(t, exec, "12")

	var out, errOut bytes.Buffer
	code := run([]string{"rename", "-key", key, "-name", "12", "-newname", "Вася", "-yes"}, strings.NewReader(""), &out, &errOut, knownHostsPath)
	if code != 0 {
		t.Fatalf("code = %d, хочу 0; stderr:\n%s", code, errOut.String())
	}
	got := out.String()

	notePos := strings.Index(got, "Это ИМЯ, а не номер")
	if notePos < 0 {
		t.Fatalf("rename -name 12 переименовал МОЛЧА — а карточки у rename нет вовсе.\nstdout:\n%s", got)
	}
	donePos := strings.Index(got, "переименован")
	if donePos < 0 {
		t.Fatalf("в stdout нет строки об успехе — тест якорится не на то:\n%s", got)
	}
	if notePos > donePos {
		t.Errorf("предупреждение напечатано ПОСЛЕ сообщения о выполнении (%d > %d):\n%s", notePos, donePos, got)
	}
}
