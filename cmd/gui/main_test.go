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
	pinGoEnv()
	// Окно «Конфиг готов» сохраняет .conf САМО (задача 01.10.2026): без
	// этого любой тест, открывший окно, писал бы в настоящий каталог
	// конфигураций владельца. Тесты, которым нужен свой каталог, задают
	// переменные через t.Setenv поверх этих.
	home := filepath.Join(dir, "home")
	os.MkdirAll(home, 0o700)
	os.Setenv("LOCALAPPDATA", home)
	os.Setenv("XDG_CONFIG_HOME", home)
	// macOS: os.UserConfigDir — $HOME/Library/Application Support, XDG там не
	// действует (SEC-01 T1). Уводится и HOME — в свой подкаталог.
	os.Setenv("HOME", home)
	// И каталоги прежних версий («Конфигурации» в текущем каталоге и рядом с
	// программой): тест не читает настоящие конфиги владельца.
	legacy := filepath.Join(dir, "legacy", "Конфигурации")
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
