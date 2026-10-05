package main

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"amnezia-admin/core"
)

const cliTestPassword = "пароль-копии-для-теста"

func writePwFile(t *testing.T, pw string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "pw.txt")
	if err := os.WriteFile(p, []byte(pw+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// лёгкие параметры Argon2 для тестов CLI (прод — 512 МиБ на каждый вызов)
func lightArgon(t *testing.T) {
	old := core.ProdArgonParams
	core.ProdArgonParams = core.ArgonParams{MemoryKiB: 64, Time: 1, Threads: 1}
	t.Cleanup(func() { core.ProdArgonParams = old })
}

// TestCLIBackupPasswordChoice — без терминала и без выбора — код 2 и файл не
// записан; оба флага — ошибка; пароль короче 12 — отказ; с паролем —
// предупреждение «забудете пароль» до записи, файл зашифрован, пароля в
// выводе нет. Подмена «нет выбора → без пароля» роняет тест.
func TestCLIBackupPasswordChoice(t *testing.T) {
	lightArgon(t)
	key, kh, _ := setupFakeSSHForRunWithExec(t)
	dir := t.TempDir()
	p := filepath.Join(dir, "c.aabk")
	code, _, errOut := cliRun(t, kh, "", "backup", "-key", key, "-o", p)
	if code != 2 || !strings.Contains(errOut, "-password-file") {
		t.Fatalf("без выбора: код %d %s", code, errOut)
	}
	if _, err := os.Stat(p); err == nil {
		t.Fatal("без выбора файл записан")
	}
	if code, _, _ := cliRun(t, kh, "", "backup", "-key", key, "-o", p, "-no-password", "-password-file", writePwFile(t, cliTestPassword)); code != 1 {
		t.Errorf("оба флага: код %d", code)
	}
	if code, _, e := cliRun(t, kh, "", "backup", "-key", key, "-o", p, "-password-file", writePwFile(t, "короткий")); code != 1 || !strings.Contains(e, "короче 12") {
		t.Errorf("короткий пароль: %d %s", code, e)
	}
	code, out, e := cliRun(t, kh, "", "backup", "-key", key, "-o", p, "-password-file", writePwFile(t, cliTestPassword))
	if code != 0 {
		t.Fatalf("с паролем: %d %s", code, e)
	}
	wi, ri := strings.Index(out, "Забудете пароль"), strings.Index(out, "Копия записана: ")
	if wi < 0 || ri < 0 || wi > ri || strings.Contains(out, "НЕ ЗАШИФРОВАН") {
		t.Errorf("предупреждение с паролем:\n%s", out)
	}
	if strings.Contains(out+e, cliTestPassword) {
		t.Error("пароль в выводе")
	}
	if l, _ := core.BackupLayerOf(p); l != core.PasswordLayerName {
		t.Errorf("слой файла %q", l)
	}
}

// TestCLIEncryptedRead — backup-info/restore спрашивают пароль только у
// зашифрованной копии: без терминала и без файла пароля — код 2; неверный
// пароль — «неверный пароль или файл повреждён»; верный — читается и
// переносится.
func TestCLIEncryptedRead(t *testing.T) {
	lightArgon(t)
	keyA, khA, _ := setupFakeSSHForRunWithExec(t)
	p := filepath.Join(t.TempDir(), "c.aabk")
	good := writePwFile(t, cliTestPassword)
	if code, _, e := cliRun(t, khA, "", "backup", "-key", keyA, "-o", p, "-password-file", good); code != 0 {
		t.Fatalf("backup: %d %s", code, e)
	}
	if code, _, e := cliRun(t, "", "", "backup-info", p); code != 2 || !strings.Contains(e, "-password-file") {
		t.Errorf("backup-info без пароля: %d %s", code, e)
	}
	code, _, e := cliRun(t, "", "", "backup-info", "-password-file", writePwFile(t, "неверный-пароль-копии"), p)
	if code != 1 || !strings.Contains(e, "неверный пароль или файл повреждён") {
		t.Errorf("неверный пароль: %d %s", code, e)
	}
	if code, out, e := cliRun(t, "", "", "backup-info", "-password-file", good, p); code != 0 || !strings.Contains(out, "amnezia-awg") {
		t.Errorf("верный пароль: %d %s", code, e)
	}
	keyB, khB, _ := setupFakeSSHForRunWithExec(t)
	if code, _, _ := cliRun(t, khB, "", "restore", "-key", keyB, "-file", p); code != 2 {
		t.Errorf("restore зашифрованной без пароля: код %d", code)
	}
	if code, out, e := cliRun(t, khB, "", "restore", "-key", keyB, "-file", p, "-password-file", good); code != 0 || !strings.Contains(out, "предпросмотр") {
		t.Errorf("restore с паролем: %d %s\n%s", code, e, out)
	}
	// незашифрованная копия пароль не спрашивает
	p2 := filepath.Join(t.TempDir(), "plain.aabk")
	cliRun(t, khA, "", "backup", "-key", keyA, "-o", p2, "-no-password")
	if code, _, e := cliRun(t, "", "", "backup-info", p2); code != 0 {
		t.Errorf("незашифрованная: %d %s", code, e)
	}
}

// TestCLIPasswordTTY — с терминалом: вопрос «зашифровать?», пароль дважды
// без эха (шов readPasswordTTY); несовпадение — отказ.
func TestCLIPasswordTTY(t *testing.T) {
	lightArgon(t)
	answers := []string{}
	old := readPasswordTTY
	t.Cleanup(func() { readPasswordTTY = old })
	readPasswordTTY = func(w io.Writer, prompt string) ([]byte, error) {
		a := answers[0]
		answers = answers[1:]
		return []byte(a), nil
	}
	var out, errOut bytes.Buffer
	answers = []string{cliTestPassword, cliTestPassword}
	l, warn, code := backupLayerChoice(strings.NewReader("y\n"), &out, &errOut, true, "", false)
	if code != 0 || l.Name() != core.PasswordLayerName || warn != core.BackupPasswordWarning {
		t.Fatalf("с паролем: %d %v %s", code, l, errOut.String())
	}
	answers = []string{cliTestPassword, "другой-пароль-копии"}
	if _, _, code := backupLayerChoice(strings.NewReader("y\n"), &out, &errOut, true, "", false); code != 1 {
		t.Errorf("несовпадение: код %d", code)
	}
	if l, _, code := backupLayerChoice(strings.NewReader("n\n"), &out, &errOut, true, "", false); code != 0 || l.Name() != "none" {
		t.Errorf("без пароля: %d", code)
	}
	if _, _, code := backupLayerChoice(strings.NewReader("\n"), &out, &errOut, true, "", false); code != 2 {
		t.Errorf("пустой ответ — не отмена: %d", code)
	}
}
