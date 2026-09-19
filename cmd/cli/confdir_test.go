package main

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"amnezia-admin/core"
)

// A4в: клиентские .conf сохраняются в каталог данных пользователя ОС, а не в
// «Конфигурации» рядом с текущим каталогом процесса.
//
// ЭТОТ ТЕСТ ОБЯЗАН КРАСНЕТЬ НА ПРЕДЫДУЩЕЙ РЕВИЗИИ и краснеет: он вызывает
// saveUserConfig, существовавшую и там с той же сигнатурой (то есть падение —
// не ошибка компиляции), и требует, чтобы в текущем каталоге НЕ появилось
// «Конфигурации». Старый код создаёт его первой же строкой.
//
// Настоящий каталог данных владельца не трогается: подменяется переменная
// окружения, из которой его берёт core.UserConfigsDir.

func fakeUserDataBaseCLI(t *testing.T) string {
	t.Helper()
	base := t.TempDir()
	switch runtime.GOOS {
	case "windows":
		t.Setenv("LOCALAPPDATA", base)
	case "darwin", "ios":
		t.Setenv("HOME", base)
	default:
		t.Setenv("XDG_CONFIG_HOME", base)
	}
	return base
}

func wantConfigsDirCLI(base string) string {
	switch runtime.GOOS {
	case "darwin", "ios":
		return filepath.Join(base, "Library", "Application Support", "amnezia-admin", "Конфигурации")
	default:
		return filepath.Join(base, "amnezia-admin", "Конфигурации")
	}
}

func TestSaveUserConfigWritesToUserDataDirNotCwd(t *testing.T) {
	base := fakeUserDataBaseCLI(t)
	cwd := t.TempDir()
	t.Chdir(cwd)

	u := &core.NewUser{Name: "Вася", IP: "10.8.1.7", Config: "[Interface]\n"}
	var buf bytes.Buffer
	if err := saveUserConfig(&buf, u, "awg"); err != nil {
		t.Fatalf("saveUserConfig: %v", err)
	}

	// 1. Рядом с текущим каталогом не появилось ничего.
	if entries, err := os.ReadDir(cwd); err != nil {
		t.Fatalf("читаю текущий каталог: %v", err)
	} else if len(entries) != 0 {
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("в текущем каталоге создано %v — конфиг снова пишется относительно текущего каталога", names)
	}

	// 2. Файл лежит в каталоге данных пользователя.
	want := filepath.Join(wantConfigsDirCLI(base), "Вася.conf")
	if _, err := os.Stat(want); err != nil {
		t.Fatalf("конфига нет по ожидаемому пути %s: %v", want, err)
	}

	// 3. Человеку напечатан АБСОЛЮТНЫЙ путь — иначе файл для него потерян.
	out := buf.String()
	if !strings.Contains(out, want) {
		t.Errorf("в выводе нет абсолютного пути %s. Вывод:\n%s", want, out)
	}
}
