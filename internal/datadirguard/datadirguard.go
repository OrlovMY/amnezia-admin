// Package datadirguard — сторож тестов: прогон пакета не пишет в настоящий
// каталог данных пользователя (долг 02.10: в %LOCALAPPDATA%\amnezia-admin\
// Конфигурации владельца накопились тысячи canary-*.conf от тестов
// internal/canary).
//
// Run подменяет каталог данных всего тестового процесса (LOCALAPPDATA,
// XDG_CONFIG_HOME, HOME — см. core.UserConfigsDir) на временный каталог и
// после m.Run роняет прогон, если в нём появился хоть один файл. Настоящий
// каталог данных тестам при этом недоступен вовсе, а запись «по
// наследству» (в том числе дочерними процессами) видна.
package datadirguard

import (
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Vars — переменные окружения, от которых зависит каталог данных
// пользователя на Windows, Linux и macOS.
var Vars = []string{"LOCALAPPDATA", "XDG_CONFIG_HOME", "HOME"}

// Run — m.Run под подменённым каталогом данных; dir — сам каталог (для
// тестов, которые проверяют, что в нём пусто). Код выхода: m.Run, а если
// он 0 и в каталоге появились файлы — 1.
func Run(m *testing.M, dir *string) int {
	d, err := os.MkdirTemp("", "amnezia-inherited-data-")
	if err != nil {
		fmt.Fprintln(os.Stderr, "datadirguard:", err)
		return 1
	}
	defer os.RemoveAll(d)
	// Кэши Go выводятся из HOME — запомнить их до подмены.
	for _, k := range []string{"GOMODCACHE", "GOPATH", "GOCACHE"} {
		if os.Getenv(k) != "" {
			continue
		}
		if out, err := exec.Command("go", "env", k).Output(); err == nil {
			if v := strings.TrimSpace(string(out)); v != "" {
				os.Setenv(k, v)
			}
		}
	}
	for _, k := range Vars {
		os.Setenv(k, d)
	}
	if dir != nil {
		*dir = d
	}
	code := m.Run()
	leaked, werr := Files(d)
	if werr != nil {
		// QA-01 Н4: каталог не обойти — «утечек нет» не утверждается.
		fmt.Fprintf(os.Stderr, "СТОРОЖ datadirguard: унаследованный каталог данных не обойти (%v) — есть ли в нём записи, неизвестно\n", werr)
		return 1
	}
	if len(leaked) > 0 {
		fmt.Fprintf(os.Stderr, "СТОРОЖ datadirguard: прогон записал %d файл(ов) в унаследованный каталог данных (на машине владельца это настоящий каталог данных): %s\n",
			len(leaked), strings.Join(leaked, "; "))
		return 1
	}
	return code
}

// Files — файлы под dir, имена относительно dir (содержимое не читается).
// Ошибка обхода (каталог исчез, не читается) — ошибка, а не «файлов нет».
func Files(dir string) ([]string, error) {
	var out []string
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			rel, _ := filepath.Rel(dir, p)
			out = append(out, rel)
		}
		return nil
	})
	return out, err
}
