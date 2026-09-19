package main

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"amnezia-admin/core"
)

// A4в для GUI. Отдельный тест, а не «покрыто тестом CLI»: мест записи два, и
// разъехавшись, GUI и CLI станут сохранять в разные каталоги — это хуже
// прежнего положения.
//
// КРАСНЕЕТ НА ПРЕДЫДУЩЕЙ РЕВИЗИИ: writeConfigFile существовала там с той же
// сигнатурой и тем же приёмником (ни одного поля ui она не читает), так что
// падение — поведенческое, а не ошибка компиляции.

func fakeUserDataBaseGUI(t *testing.T) string {
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

func wantConfigsDirGUI(base string) string {
	switch runtime.GOOS {
	case "darwin", "ios":
		return filepath.Join(base, "Library", "Application Support", "amnezia-admin", "Конфигурации")
	default:
		return filepath.Join(base, "amnezia-admin", "Конфигурации")
	}
}

func TestGuiWriteConfigFileWritesToUserDataDirNotCwd(t *testing.T) {
	base := fakeUserDataBaseGUI(t)
	cwd := t.TempDir()
	t.Chdir(cwd)

	var u ui
	nu := &core.NewUser{Name: "Вася", IP: "10.8.1.7", Config: "[Interface]\n"}
	abs, err := u.writeConfigFile(nu)
	if err != nil {
		t.Fatalf("writeConfigFile: %v", err)
	}

	if entries, err := os.ReadDir(cwd); err != nil {
		t.Fatalf("читаю текущий каталог: %v", err)
	} else if len(entries) != 0 {
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("в текущем каталоге создано %v — GUI снова пишет относительно текущего каталога", names)
	}

	want := filepath.Join(wantConfigsDirGUI(base), "Вася.conf")
	if abs != want {
		t.Errorf("возвращён путь %q, ожидался %q", abs, want)
	}
	if !filepath.IsAbs(abs) {
		t.Errorf("путь %q не абсолютный, а его показывают человеку в диалоге", abs)
	}
	if _, err := os.Stat(want); err != nil {
		t.Fatalf("конфига нет по ожидаемому пути %s: %v", want, err)
	}
}
