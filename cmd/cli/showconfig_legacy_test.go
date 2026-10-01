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
