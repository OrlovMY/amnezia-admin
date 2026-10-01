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
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "amnezia-cli-legacy-")
	if err != nil {
		fmt.Fprintln(os.Stderr, "TestMain:", err)
		os.Exit(1)
	}
	legacy := filepath.Join(dir, "Конфигурации")
	legacyConfigDirs = func() []core.SavedDir { return []core.SavedDir{{Path: legacy, Legacy: true}} }
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}
