package main

import (
	"fmt"
	"os"
	"testing"
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
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}
