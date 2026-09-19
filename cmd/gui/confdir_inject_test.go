package main

import (
	"os"
	"path/filepath"
	"testing"

	"amnezia-admin/core"
)

// Отдельный файл — намеренно, см. cmd/cli/confdir_inject_test.go.

// TestGuiWriteConfigFileToUsesGivenDir — точка подмены каталога существует.
func TestGuiWriteConfigFileToUsesGivenDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "Конфигурации")
	nu := &core.NewUser{Name: "Петя", IP: "10.8.1.8", Config: "[Interface]\n"}
	abs, err := writeConfigFileTo(dir, nu)
	if err != nil {
		t.Fatalf("writeConfigFileTo: %v", err)
	}
	if want := filepath.Join(dir, "Петя.conf"); abs != want {
		t.Errorf("записано в %q, ожидалось %q", abs, want)
	}
	if _, err := os.Stat(abs); err != nil {
		t.Fatalf("файла нет: %v", err)
	}
}
