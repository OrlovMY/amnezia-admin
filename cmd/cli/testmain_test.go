package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"amnezia-admin/core"
)

// TestMain — каталоги прежних версий («Конфигурации» в текущем каталоге и
// рядом с программой) уводятся во временный: show-config в тестах не читает
// настоящие конфиги владельца.
var testMainDir string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "amnezia-cli-legacy-")
	if err != nil {
		fmt.Fprintln(os.Stderr, "TestMain:", err)
		os.Exit(1)
	}
	testMainDir = dir
	pinGoEnv()
	// Каталог конфигураций этой версии — тоже во временный, на всех ОС
	// (SEC-01 T1: на macOS он от HOME). HOME и каталог прежних версий —
	// РАЗНЫЕ подкаталоги (CI раунда 5: пересечение ломало соседний тест).
	home := filepath.Join(dir, "home")
	os.MkdirAll(home, 0o700)
	os.Setenv("LOCALAPPDATA", home)
	os.Setenv("XDG_CONFIG_HOME", home)
	os.Setenv("HOME", home)
	legacy := filepath.Join(dir, "legacy", "Конфигурации")
	legacyConfigDirs = func() []core.SavedDir { return []core.SavedDir{{Path: legacy, Legacy: true}} }
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

// TestConfigsDirIsTemp — КАНАРЕЙКА (SEC-01 T1): под TestMain оба каталога
// поиска конфигов — во временном каталоге на любой ОС.
func TestConfigsDirIsTemp(t *testing.T) {
	d, err := core.UserConfigsDir()
	if err != nil {
		t.Fatalf("каталог конфигураций не определён: %v", err)
	}
	for _, p := range append([]string{d}, legacyConfigDirs()[0].Path) {
		if rel, err := filepath.Rel(testMainDir, p); err != nil || len(rel) >= 2 && rel[:2] == ".." {
			t.Fatalf("%q вне временного каталога TestMain %q", p, testMainDir)
		}
	}
}

// pinGoEnv — запомнить кэш модулей и сборки Go ДО подмены HOME (CI раунда
// 5): они выводятся из HOME, и после подмены сторож боевого предиката не
// находил исходники Fyne («каталог модуля пуст»). Go нет — ничего не делаем:
// сторож, которому нужны исходники, сам скажет об этом громко.
func pinGoEnv() {
	for _, k := range []string{"GOMODCACHE", "GOPATH", "GOCACHE"} {
		if os.Getenv(k) != "" {
			continue
		}
		out, err := exec.Command("go", "env", k).Output()
		if v := strings.TrimSpace(string(out)); err == nil && v != "" {
			os.Setenv(k, v)
		}
	}
}
