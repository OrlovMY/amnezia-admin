package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"amnezia-admin/core"
)

// Отдельный файл — намеренно: он ссылается на НОВУЮ функцию saveUserConfigTo
// и на предыдущей ревизии не компилируется. Поведенческий тест из
// confdir_test.go таких ссылок не содержит и потому там КРАСНЕЕТ, а не падает
// сборкой.

// TestSaveUserConfigToUsesGivenDir — точка подмены существует и работает:
// каталог берётся из параметра, а не из окружения.
func TestSaveUserConfigToUsesGivenDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "Конфигурации")
	u := &core.NewUser{Name: "Петя", IP: "10.8.1.8", Config: "[Interface]\n"}
	var buf bytes.Buffer
	if err := saveUserConfigTo(&buf, dir, u, "awg"); err != nil {
		t.Fatalf("saveUserConfigTo: %v", err)
	}
	want := filepath.Join(dir, "Петя.conf")
	if _, err := os.Stat(want); err != nil {
		t.Fatalf("конфига нет в переданном каталоге %s: %v", want, err)
	}
	if !strings.Contains(buf.String(), want) {
		t.Errorf("в выводе нет пути %s. Вывод:\n%s", want, buf.String())
	}
}
