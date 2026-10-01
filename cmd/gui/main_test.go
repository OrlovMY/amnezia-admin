package main

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"amnezia-admin/core"
)

// TestMain — у тестов пакета свой каталог для ui.json (см. uiStateDir):
// клик по заголовку таблицы сохраняет сортировку, и без этого файл ложился
// в общий каталог хранилищ рядом с тестовым бинарником.
// testMainDir — временный каталог TestMain (канарейка TestConfigsDirIsTemp).
var testMainDir string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "amnezia-gui-uistate-")
	if err != nil {
		fmt.Fprintln(os.Stderr, "TestMain:", err)
		os.Exit(1)
	}
	uiStateDir = func() string { return dir }
	testMainDir = dir
	// Окно «Конфиг готов» сохраняет .conf САМО (задача 01.10.2026): без
	// этого любой тест, открывший окно, писал бы в настоящий каталог
	// конфигураций владельца. Тесты, которым нужен свой каталог, задают
	// переменные через t.Setenv поверх этих.
	os.Setenv("LOCALAPPDATA", dir)
	os.Setenv("XDG_CONFIG_HOME", dir)
	// macOS: os.UserConfigDir — $HOME/Library/Application Support, XDG там не
	// действует (SEC-01 T1). Уводится и HOME.
	os.Setenv("HOME", dir)
	// И каталоги прежних версий («Конфигурации» в текущем каталоге и рядом с
	// программой): тест не читает настоящие конфиги владельца.
	legacy := filepath.Join(dir, "legacy-Конфигурации")
	legacyConfigDirs = func() []core.SavedDir { return []core.SavedDir{{Path: legacy, Legacy: true}} }
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

// TestConfigsDirIsTemp — КАНАРЕЙКА (SEC-01 T1): под TestMain каталог
// конфигураций на ЛЮБОЙ ОС лежит во временном каталоге — тесты, открывающие
// «Конфиг готов», не пишут в настоящий каталог владельца.
func TestConfigsDirIsTemp(t *testing.T) {
	d, err := core.UserConfigsDir()
	if err != nil {
		t.Fatalf("каталог конфигураций не определён: %v", err)
	}
	if rel, err := filepath.Rel(testMainDir, d); err != nil || rel == ".." || len(rel) >= 2 && rel[:2] == ".." {
		t.Fatalf("каталог конфигураций %q вне временного каталога TestMain %q", d, testMainDir)
	}
	for _, l := range legacyConfigDirs() {
		if rel, err := filepath.Rel(testMainDir, l.Path); err != nil || len(rel) >= 2 && rel[:2] == ".." {
			t.Fatalf("каталог прежних версий %q вне временного каталога TestMain", l.Path)
		}
	}
}
