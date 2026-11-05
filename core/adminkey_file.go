package core

// Запись ключа vpn:// в файл — общая для CLI (migrate -to-host) и GUI
// (режим «Новый чистый сервер»): ключ — только через AdminKey.Reveal() в
// новый файл 0600 (на Windows — права каталога), существующий файл не
// перезаписывается, при неудаче записи файл удаляется.

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// AdminKeyFileName — имя файла ключа по адресу и времени:
// admin-<адрес>-<ГГГГММДД-ЧЧММСС>.vpn.txt (знаки вне [A-Za-z0-9.-] → «_»).
func AdminKeyFileName(host string, now time.Time) string {
	safe := strings.Map(func(r rune) rune {
		if r == '.' || r == '-' || r >= '0' && r <= '9' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' {
			return r
		}
		return '_'
	}, host)
	return "admin-" + safe + "-" + now.Format("20060102-150405") + ".vpn.txt"
}

// WriteAdminKeyFile — ключ в НОВЫЙ файл path (O_EXCL, 0600). Возвращает
// абсолютный путь. Содержимое ключа в текст ошибки не попадает.
func WriteAdminKeyFile(path string, key AdminKey) (string, error) {
	if key.Len() == 0 {
		return "", errors.New("ключ пуст — файл не пишется")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	f, err := os.OpenFile(abs, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return "", fmt.Errorf("файл %s уже есть — не перезаписываю", abs)
		}
		return "", err
	}
	_, werr := f.WriteString(key.Reveal() + "\n")
	cerr := f.Close()
	if werr != nil || cerr != nil {
		_ = os.Remove(abs)
		return "", fmt.Errorf("запись файла %s не удалась", abs)
	}
	return abs, nil
}
