package main

import (
	"fmt"
	"os"
	"path/filepath"
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
	// Каталог конфигураций этой версии — тоже во временный, на всех ОС
	// (SEC-01 T1: на macOS он от HOME).
	os.Setenv("LOCALAPPDATA", dir)
	os.Setenv("XDG_CONFIG_HOME", dir)
	os.Setenv("HOME", dir)
	legacy := filepath.Join(dir, "Конфигурации")
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
