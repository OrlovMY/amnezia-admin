package core

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// fakeUserDataBase подменяет каталог данных пользователя на временный и
// возвращает его. Настоящий %LOCALAPPDATA% (и $HOME) владельца в тестах не
// трогается ВООБЩЕ: подменяется именно та переменная, которую читает
// UserConfigsDir на этой ОС.
func fakeUserDataBase(t *testing.T) string {
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

// wantConfigsDir — где обязан оказаться каталог при базе base. Раскладка
// каждой ОС выписана буквой, а не собрана тем же кодом, что в UserConfigsDir:
// иначе тест повторил бы ошибку проверяемого кода и зазеленел бы на ней.
func wantConfigsDir(base string) string {
	switch runtime.GOOS {
	case "darwin", "ios":
		return filepath.Join(base, "Library", "Application Support", "amnezia-admin", "Конфигурации")
	default: // windows: %LOCALAPPDATA%\…; unix: $XDG_CONFIG_HOME/…
		return filepath.Join(base, "amnezia-admin", "Конфигурации")
	}
}

func TestUserConfigsDirIsInUserDataDir(t *testing.T) {
	base := fakeUserDataBase(t)
	got, err := UserConfigsDir()
	if err != nil {
		t.Fatalf("UserConfigsDir: %v", err)
	}
	if !filepath.IsAbs(got) {
		t.Errorf("каталог %q не абсолютный — ровно то, что чинит A4в", got)
	}
	if want := wantConfigsDir(base); got != want {
		t.Errorf("каталог конфигов = %q, ожидался %q", got, want)
	}
}

// TestUserConfigsDirSaysItDoesNotKnow — П-НЕЗНАНИЕ: база не определена, и это
// ОШИБКА, а не тихий возврат относительного пути «Конфигурации».
func TestUserConfigsDirSaysItDoesNotKnow(t *testing.T) {
	// Гасим все три источника сразу — так случай одинаков на любой ОС.
	t.Setenv("LOCALAPPDATA", "")
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("HOME", "")
	got, err := UserConfigsDir()
	if err == nil {
		t.Fatalf("каталог данных пользователя определить нельзя, а функция вернула %q без ошибки", got)
	}
	if got != "" {
		t.Errorf("вместе с ошибкой вернулся путь %q — его могут записать", got)
	}
	if !strings.Contains(err.Error(), "не удалось определить") {
		t.Errorf("текст ошибки не говорит, ЧТО не удалось: %v", err)
	}
}

func TestWriteClientConfigRejectsRelativeDir(t *testing.T) {
	if _, _, err := WriteClientConfig("Конфигурации", "Вася", "[Interface]"); err == nil {
		t.Fatal("относительный каталог принят — файл снова уйдёт рядом с текущим каталогом")
	}
	if _, err := os.Stat("Конфигурации"); err == nil {
		t.Fatal("каталог «Конфигурации» всё-таки создан рядом с тестом")
	}
}

// TestWriteClientConfigDirPerm — фактические права каталога на диске.
func TestWriteClientConfigDirPerm(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("ПРОПУСК, а не успех: на Windows POSIX-биты каталога не применяются — доступ решают ACL, и проверять здесь нечего. Смысл 0700 на Windows не проверен ничем.")
	}
	dir := filepath.Join(t.TempDir(), "amnezia-admin", "Конфигурации")
	path, _, err := WriteClientConfig(dir, "Вася", "[Interface]")
	if err != nil {
		t.Fatalf("WriteClientConfig: %v", err)
	}
	di, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat каталога: %v", err)
	}
	if got := di.Mode().Perm(); got != 0700 {
		t.Errorf("права каталога %v, ожидались 0700 — каталог с именами клиентов открыт другим пользователям машины", got)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat файла: %v", err)
	}
	if got := fi.Mode().Perm(); got != 0600 {
		t.Errorf("права файла %v, ожидались 0600", got)
	}
}
