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
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "amnezia-gui-uistate-")
	if err != nil {
		fmt.Fprintln(os.Stderr, "TestMain:", err)
		os.Exit(1)
	}
	uiStateDir = func() string { return dir }
	// Окно «Конфиг готов» сохраняет .conf САМО (задача 01.10.2026): без
	// этого любой тест, открывший окно, писал бы в настоящий каталог
	// конфигураций владельца. Тесты, которым нужен свой каталог, задают
	// переменные через t.Setenv поверх этих.
	os.Setenv("LOCALAPPDATA", dir)
	os.Setenv("XDG_CONFIG_HOME", dir)
	// И каталоги прежних версий («Конфигурации» в текущем каталоге и рядом с
	// программой): тест не читает настоящие конфиги владельца.
	legacy := filepath.Join(dir, "legacy-Конфигурации")
	legacyConfigDirs = func() []core.SavedDir { return []core.SavedDir{{Path: legacy, Legacy: true}} }
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}
