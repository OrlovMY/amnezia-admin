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
	abs, _, err := writeConfigFileTo(dir, nu)
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

// TestGuiWriteConfigFileReportsFirstSave — признак «каталога не было», по
// которому диалог один раз показывает подсказку о смене места (ревью UX-01,
// блокирующее 3). Показ в самом диалоге тестом не покрыт — окно требует
// дисплея; за то, что GUI берёт ТУ ЖЕ подсказку, отвечает сторож
// internal/confdirguard.
func TestGuiWriteConfigFileReportsFirstSave(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "amnezia-admin", "Конфигурации")
	nu := &core.NewUser{Name: "Петя", IP: "10.8.1.8", Config: "[Interface]\n"}

	_, created, err := writeConfigFileTo(dir, nu)
	if err != nil {
		t.Fatalf("первое сохранение: %v", err)
	}
	if !created {
		t.Error("каталога не было, а признак первого сохранения не выставлен — подсказка не покажется никогда")
	}

	_, created, err = writeConfigFileTo(dir, nu)
	if err != nil {
		t.Fatalf("второе сохранение: %v", err)
	}
	if created {
		t.Error("каталог уже существовал, а признак первого сохранения выставлен — подсказка повторится")
	}
}
