package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"amnezia-admin/core"
)

// TestShowConfigCommand — ДОЕЗД `show-config` через run() по SSH к fakesrv:
// add сохраняет .conf (как всегда в CLI), show-config находит его по ключу и
// сверяет с сервером; содержимое — только по -print. Затем РАЗЛИЧЕНИЕ:
// файла нет — «не сохранялся» с подсказкой rekey; каталог — файл —
// «не удалось прочитать», без подсказки.
func TestShowConfigCommand(t *testing.T) {
	base := t.TempDir()
	t.Setenv("LOCALAPPDATA", base)
	t.Setenv("XDG_CONFIG_HOME", base)
	t.Setenv("HOME", base) // macOS: UserConfigsDir от HOME
	dir, err := core.UserConfigsDir()
	if err != nil {
		t.Fatal(err)
	}
	key, kh, _ := setupFakeSSHForRunWithExec(t)
	runCLI := func(args ...string) (int, string, string) {
		var o, e bytes.Buffer
		code := run(append(args, "-key", key), strings.NewReader(""), &o, &e, kh)
		return code, o.String(), e.String()
	}
	if code, _, e := runCLI("add", "-name", "Carol"); code != 0 {
		t.Fatalf("add: %d %s", code, e)
	}
	// имени файла не доверяем: переименуем
	if err := os.Rename(filepath.Join(dir, "Carol.conf"), filepath.Join(dir, "другое.conf")); err != nil {
		t.Fatal(err)
	}
	code, out, e := runCLI("show-config", "-name", "Carol")
	if code != 0 {
		t.Fatalf("show-config: %d %s", code, e)
	}
	for _, want := range []string{"Конфиг из файла: " + filepath.Join(dir, "другое.conf"), "PresharedKey совпадает с сервером.", "Адрес клиента (Address) совпадает с сервером."} {
		if !strings.Contains(out, want) {
			t.Errorf("нет %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "PrivateKey") {
		t.Error("без -print напечатан приватный ключ")
	}
	if _, out, _ = runCLI("show-config", "-name", "Carol", "-print"); !strings.Contains(out, "PrivateKey = ") {
		t.Error("-print не напечатал содержимое")
	}

	os.Remove(filepath.Join(dir, "другое.conf"))
	code, out, e = runCLI("show-config", "-name", "Carol")
	if code != 1 || !strings.Contains(out, "Конфигурация этого клиента не найдена в папках, где программа её ищет:") || !strings.Contains(out, "rekey -name \"Carol\"") {
		t.Errorf("«не найден»: %d\n%s\n%s", code, out, e)
	}
	for _, d := range append([]string{dir}, legacyPaths()...) {
		if !strings.Contains(out, d) {
			t.Errorf("в выводе «не найден» нет каталога поиска %q:\n%s", d, out)
		}
	}

	os.RemoveAll(dir)
	os.WriteFile(dir, []byte("x"), 0o600)
	code, out, e = runCLI("show-config", "-name", "Carol")
	if code != 1 || !strings.Contains(e, "Не удалось прочитать папку конфигураций или файл в ней") || strings.Contains(out+e, "не найдена в папках") || strings.Contains(out, "rekey") {
		t.Errorf("«не прочитано»: %d\n%s\n%s", code, out, e)
	}
}

func legacyPaths() []string {
	var out []string
	for _, d := range legacyConfigDirs() {
		out = append(out, d.Path)
	}
	return out
}

// TestShowConfigPrintNeedsVerifiedServer — SEC-01 R1-b: -print печатает
// содержимое только при совпавшем ключе сервера; при чужом и не сверенном —
// нет содержимого, код ≠ 0 и подсказка -print-unverified.
func TestShowConfigPrintNeedsVerifiedServer(t *testing.T) {
	base := t.TempDir()
	t.Setenv("LOCALAPPDATA", base)
	t.Setenv("XDG_CONFIG_HOME", base)
	t.Setenv("HOME", base) // macOS: UserConfigsDir от HOME
	dir, err := core.UserConfigsDir()
	if err != nil {
		t.Fatal(err)
	}
	key, kh, srv := setupFakeSSHForRunWithExec(t)
	runCLI := func(args ...string) (int, string, string) {
		var o, e bytes.Buffer
		code := run(append(args, "-key", key), strings.NewReader(""), &o, &e, kh)
		return code, o.String(), e.String()
	}
	if code, _, e := runCLI("add", "-name", "Carol"); code != 0 {
		t.Fatalf("add: %s", e)
	}
	if code, out, _ := runCLI("show-config", "-name", "Carol", "-print"); code != 0 || !strings.Contains(out, "PrivateKey = ") {
		t.Fatalf("ключ сервера совпал, а -print не напечатал: %d", code)
	}
	path := filepath.Join(dir, "Carol.conf")
	conf, _ := os.ReadFile(path)
	s := string(conf)
	i := strings.Index(s, "[Peer]\nPublicKey = ") + len("[Peer]\nPublicKey = ")
	j := strings.Index(s[i:], "\n")
	forged := s[:i] + "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=" + s[i+j:]
	os.WriteFile(path, []byte(forged), 0o600)
	check := func(what string) {
		code, out, e := runCLI("show-config", "-name", "Carol", "-print")
		if code == 0 || strings.Contains(out, "PrivateKey") || !strings.Contains(e, "-print-unverified") {
			t.Errorf("%s: код %d, содержимое напечатано=%v, подсказка=%v", what, code, strings.Contains(out, "PrivateKey"), strings.Contains(e, "-print-unverified"))
		}
		if code, out, _ := runCLI("show-config", "-name", "Carol", "-print-unverified"); code != 0 || !strings.Contains(out, "PrivateKey = ") {
			t.Errorf("%s: -print-unverified не напечатал: %d", what, code)
		}
	}
	check("чужой сервер")

	// не сверен: ключ сервера в wg0.conf не разбирается
	os.WriteFile(path, conf, 0o600)
	wg, _ := srv.File("/opt/amnezia/awg/wg0.conf")
	w := string(wg)
	a := strings.Index(w, "PrivateKey = ") + len("PrivateKey = ")
	b := strings.Index(w[a:], "\n")
	srv.SetFile("/opt/amnezia/awg/wg0.conf", []byte(w[:a]+"не-ключ"+w[a+b:]))
	check("не сверен")
}
