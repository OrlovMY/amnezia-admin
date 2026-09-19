package core

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// Куда сохраняются клиентские .conf (A4в).
//
// БЫЛО: os.MkdirAll("Конфигурации", 0755) — путь ОТНОСИТЕЛЬНЫЙ, то есть
// каталог заводился рядом с текущим рабочим каталогом процесса. Для CLI это
// был каталог, из которого человек запустил команду, для GUI — каталог, из
// которого ярлык запустил программу. Файлы расползались по машине, и человек
// узнавал, куда именно, только из напечатанного пути.
//
// СТАЛО: каталог данных пользователя ОС (решение владельца от 19.09.2026).
// Старые файлы НЕ переносятся и не трогаются — ни программой, ни установщиком.
//
// ПРАВА КАТАЛОГА 0700 вместо 0755. Файлы и раньше были 0600, но каталог был
// открыт на чтение и обход всем пользователям машины: имена клиентов видны, а
// новый файл в нём — ещё и создаваем чужим процессом с правом записи в группе
// нет, но перечисление имён уже утечка. На Windows POSIX-биты не применяются
// вовсе (доступ решают ACL) — ровно та же оговорка, что в internal/permguard:
// 0700 там означает «в исходниках права узкие», а не «каталог на диске закрыт».
const (
	// appDirName — имя каталога программы внутри каталога данных пользователя.
	appDirName = "amnezia-admin"
	// clientConfigsDirName — единственное место в коде, где это имя написано
	// буквой. За тем, чтобы оно не завелось снова в cmd/ относительным путём,
	// следит сторож internal/confdirguard.
	clientConfigsDirName = "Конфигурации"
	// configsDirPerm — права каталога с клиентскими конфигами (см. шапку).
	configsDirPerm os.FileMode = 0700
)

// UserConfigsDir возвращает АБСОЛЮТНЫЙ путь каталога, куда сохраняются
// клиентские .conf, и ошибку, если определить каталог данных пользователя не
// удалось. Ошибка — именно ошибка, а не тихий возврат относительного пути:
// «не знаю, куда писать» не превращается в «пишу куда попало» (П-НЕЗНАНИЕ,
// признак 2).
//
// Что берётся за базу на каждой ОС:
//   - Windows: %LOCALAPPDATA% — так решил владелец. os.UserConfigDir на
//     Windows возвращает НЕ его, а %AppData% (перемещаемый профиль Roaming),
//     проверено по исходнику os/file.go go1.26.3, поэтому здесь отдельная
//     ветка, а не os.UserConfigDir;
//   - Linux и прочий Unix: os.UserConfigDir — $XDG_CONFIG_HOME, иначе
//     $HOME/.config;
//   - macOS: os.UserConfigDir — $HOME/Library/Application Support.
func UserConfigsDir() (string, error) {
	var base string
	if runtime.GOOS == "windows" {
		base = os.Getenv("LOCALAPPDATA")
		if base == "" {
			return "", errors.New("не удалось определить каталог данных пользователя: переменная окружения LOCALAPPDATA не задана")
		}
	} else {
		var err error
		base, err = os.UserConfigDir()
		if err != nil {
			return "", fmt.Errorf("не удалось определить каталог данных пользователя: %w", err)
		}
	}
	if !filepath.IsAbs(base) {
		return "", fmt.Errorf("каталог данных пользователя %q не абсолютный — программа не станет гадать, куда писать конфиги", base)
	}
	return filepath.Join(base, appDirName, clientConfigsDirName), nil
}

// WriteClientConfig записывает конфиг клиента name в каталог dir и возвращает
// путь записанного файла. dir передаётся ЯВНО (а не берётся из UserConfigsDir
// внутри) ровно затем, чтобы тест мог подставить свой каталог и не писать в
// настоящий каталог данных владельца — тот же приём, что у writeCrashLog(dir,…)
// и saveSortStateTo(dir,…) в cmd/gui.
//
// dir обязан быть абсолютным: возвращаемый путь показывается человеку как
// «куда сохранено», и относительный путь в этой строке — то самое, что A4в
// чинит.
func WriteClientConfig(dir, name, config string) (string, error) {
	if !filepath.IsAbs(dir) {
		return "", fmt.Errorf("каталог для конфигов %q не абсолютный", dir)
	}
	if err := os.MkdirAll(dir, configsDirPerm); err != nil {
		return "", err
	}
	path := filepath.Join(dir, SanitizeName(name)+".conf")
	if err := os.WriteFile(path, []byte(config), 0600); err != nil {
		return "", err
	}
	return path, nil
}
