package core

import (
	"errors"
	"io/fs"
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

// TestWriteClientConfigRejectsRelativeDir — единственный тест, отдающий
// НАСТОЯЩЕМУ писателю относительный путь, и потому единственный, который при
// регрессии IsAbs напишет файл сам.
//
// ДВА ИЗЪЯНА, НАЙДЕННЫЕ РЕВЬЮ SEC-01, и почему они чинятся вместе:
//   - тесты пакета идут с рабочим каталогом core/, и на подмене, снимающей
//     IsAbs, этот тест создавал core/Конфигурации/Вася.conf прямо в дереве
//     репозитория — а .gitignore (`*.conf`, `/Конфигурации/`) прячет такой
//     мусор от git status. Лечится t.Chdir во временный каталог: писать,
//     если регрессия случится, будет некуда, кроме выбрасываемого каталога;
//   - первая проверка была t.Fatal, поэтому в ТОМ САМОМ прогоне, где
//     регрессия сработала, вторая (каталог не создан) не исполнялась вовсе:
//     файл находился только следующим прогоном, как остаток. С t.Errorf обе
//     проверки видят одну и ту же регрессию.
func TestWriteClientConfigRejectsRelativeDir(t *testing.T) {
	t.Chdir(t.TempDir())

	if _, _, err := WriteClientConfig("Конфигурации", "Вася", "[Interface]"); err == nil {
		t.Error("относительный каталог принят — файл снова уйдёт рядом с текущим каталогом")
	}
	if _, err := os.Stat("Конфигурации"); err == nil {
		t.Error("каталог «Конфигурации» всё-таки создан рядом с тестом")
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

// TestWriteClientConfigCreatedDirIsNarrow — ПРИЗНАК «каталога не было» узкий,
// и это проверяется, а не обещается комментарием (ревью SEC-01, замечание 2).
//
// Подмена, которую этот тест обязан ловить: createdDir = statErr != nil, то
// есть «любая ошибка Stat считается отсутствием каталога». Она проходит все
// остальные тесты набора зелёной, потому что в них Stat отвечает ровно двумя
// способами: «нет такого каталога» и «каталог есть».
//
// Третий ответ добывается БОЕВЫМ ПУТЁМ, а не присваиванием: родителем
// каталога делается обычный файл. Stat тогда отвечает не «нет такого
// каталога» (на Windows — ENOTDIR/«имя каталога недопустимо», на Unix —
// ENOTDIR), и признак обязан остаться false: программа не знает, новое это
// место или нет, и не имеет права утверждать, что новое.
// Случаев два, потому что один и тот же приём даёт третий ответ не на каждой
// ОС: под файлом-препятствием Windows отвечает как раз «нет такого каталога»
// (проверено: GetFileAttributesEx … The system cannot find the path
// specified), и одного этого случая хватило бы ровно до первого прогона на
// Windows — то есть на машине, где я работаю.
func TestWriteClientConfigCreatedDirIsNarrow(t *testing.T) {
	cases := []struct {
		name string
		dir  func(base string) (string, error)
	}{
		{
			// Реалистичный: на месте родительского каталога — обычный файл.
			"родитель — обычный файл",
			func(base string) (string, error) {
				blocker := filepath.Join(base, "не-каталог")
				if err := os.WriteFile(blocker, []byte("я файл"), 0600); err != nil {
					return "", err
				}
				return filepath.Join(blocker, "Конфигурации"), nil
			},
		},
		{
			// Переносимый: нулевой байт в имени. Stat отвечает «недопустимый
			// аргумент» и на Windows, и на Unix — это не «каталога нет».
			"недопустимое имя пути",
			func(base string) (string, error) {
				return filepath.Join(base, "плохое\x00имя", "Конфигурации"), nil
			},
		},
	}

	checked := 0
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir, err := c.dir(t.TempDir())
			if err != nil {
				t.Fatalf("подготовка случая: %v", err)
			}
			// Сначала убеждаемся, что случай ТОТ САМЫЙ: Stat ответил ошибкой,
			// но не «нет такого каталога». Иначе подслучай проверял бы не то,
			// что заявлено, и зеленел бы на подмене.
			_, statErr := os.Stat(dir)
			if statErr == nil {
				t.Fatalf("случай не воспроизведён: Stat(%q) прошёл успешно", dir)
			}
			if errors.Is(statErr, fs.ErrNotExist) {
				t.Skipf("ПРОПУСК, а не успех: на этой ОС Stat здесь отвечает «нет такого каталога» (%v) — третьего ответа этим способом не получить", statErr)
			}

			_, createdDir, err := WriteClientConfig(dir, "Вася", "[Interface]")
			if err == nil {
				t.Fatal("запись удалась — случай не тот")
			}
			if createdDir {
				t.Errorf("Stat ответил %v (это НЕ «каталога нет»), а признак первого сохранения выставлен: "+
					"человеку скажут «это новое место», хотя программа этого не знает", statErr)
			}
			checked++
		})
	}

	// Канарейка на молчаливый пропуск ВСЕХ случаев: тест, который на этой ОС
	// ничего не проверил, обязан отличаться от теста, которому нечего сказать.
	if checked == 0 {
		t.Fatal("ни один случай не дал третьего ответа Stat — узость признака createdDir на этой ОС НЕ проверена; нужен новый способ его получить")
	}
}
