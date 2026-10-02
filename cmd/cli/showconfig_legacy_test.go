package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"amnezia-admin/core"
)

// TestShowConfigLegacyDir — show-config находит конфиг в каталоге прежних
// версий и говорит об этом.
func TestShowConfigLegacyDir(t *testing.T) {
	base := t.TempDir()
	t.Setenv("LOCALAPPDATA", base)
	t.Setenv("XDG_CONFIG_HOME", base)
	t.Setenv("HOME", base) // macOS: UserConfigsDir от HOME
	dir, err := core.UserConfigsDir()
	if err != nil {
		t.Fatal(err)
	}
	legacy := filepath.Join(t.TempDir(), "Конфигурации")
	saved := legacyConfigDirs
	t.Cleanup(func() { legacyConfigDirs = saved })
	legacyConfigDirs = func() []core.SavedDir { return []core.SavedDir{{Path: legacy, Legacy: true}} }
	key, kh, _ := setupFakeSSHForRunWithExec(t)
	var o, e bytes.Buffer
	if code := run([]string{"add", "-name", "Carol", "-key", key}, strings.NewReader(""), &o, &e, kh); code != 0 {
		t.Fatalf("add: %s", e.String())
	}
	if err := os.MkdirAll(legacy, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(dir, "Carol.conf"), filepath.Join(legacy, "Carol.conf")); err != nil {
		t.Fatal(err)
	}
	o.Reset()
	e.Reset()
	code := run([]string{"show-config", "-name", "Carol", "-key", key}, strings.NewReader(""), &o, &e, kh)
	if code != 0 || !strings.Contains(o.String(), "Каталог прежних версий") {
		t.Errorf("%d\n%s\n%s", code, o.String(), e.String())
	}
}

// TestAddAfterRenameKeepsOldConfig — К-1 доездом через CLI: add «Phone»,
// rename в «Old phone», add «Phone» — прежний файл цел, вывод называет
// занятое имя, show-config находит обоих.
func TestAddAfterRenameKeepsOldConfig(t *testing.T) {
	cliConfigsEnv(t)
	key, kh, _ := setupFakeSSHForRunWithExec(t)
	runCLI := func(args ...string) (int, string, string) {
		var o, e bytes.Buffer
		code := run(append(args, "-key", key), strings.NewReader(""), &o, &e, kh)
		return code, o.String(), e.String()
	}
	if code, _, e := runCLI("add", "-name", "Phone"); code != 0 {
		t.Fatalf("add: %s", e)
	}
	if code, _, e := runCLI("rename", "-name", "Phone", "-newname", "Old phone"); code != 0 {
		t.Fatalf("rename: %s", e)
	}
	code, out, e := runCLI("add", "-name", "Phone")
	if code != 0 || !strings.Contains(out, "Файл Phone.conf уже занят конфигом другого клиента — сохранено как Phone (2).conf.") {
		t.Fatalf("второй add: %d\n%s\n%s", code, out, e)
	}
	for _, n := range []string{"Old phone", "Phone"} {
		if code, out, e := runCLI("show-config", "-name", n); code != 0 || !strings.Contains(out, "Конфиг из файла: ") {
			t.Errorf("show-config %q: %d\n%s\n%s", n, code, out, e)
		}
	}
}

// cliConfigsEnv — свой каталог данных пользователя на ВСЕХ ОС: на macOS
// UserConfigsDir идёт от HOME, XDG там не действует (CI раунда 5: тесты
// делили каталог из HOME TestMain, и «каталог — файл» портил соседей).
func cliConfigsEnv(t *testing.T) string {
	t.Helper()
	base := t.TempDir()
	t.Setenv("LOCALAPPDATA", base)
	t.Setenv("XDG_CONFIG_HOME", base)
	t.Setenv("HOME", base) // macOS: UserConfigsDir от HOME
	d, err := core.UserConfigsDir()
	if err != nil {
		t.Fatal(err)
	}
	return d
}
