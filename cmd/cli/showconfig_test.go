package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"amnezia-admin/core"
	"amnezia-admin/internal/guiview"
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
	if code != 1 || !strings.Contains(out, guiview.SavedNotFoundText) || !strings.Contains(out, "rekey -name \"Carol\"") {
		t.Errorf("«не сохранялся»: %d\n%s\n%s", code, out, e)
	}

	os.RemoveAll(dir)
	os.WriteFile(dir, []byte("x"), 0o600)
	code, out, e = runCLI("show-config", "-name", "Carol")
	if code != 1 || !strings.Contains(e, "Не удалось прочитать каталог конфигураций или файл") || strings.Contains(out+e, guiview.SavedNotFoundText) || strings.Contains(out, "rekey") {
		t.Errorf("«не прочитано»: %d\n%s\n%s", code, out, e)
	}
}
