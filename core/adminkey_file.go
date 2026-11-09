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
	if err := AdminKeyFileNameErr(filepath.Base(path)); err != nil {
		return "", err
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	if err := adminKeyTargetErr(path, abs); err != nil {
		return "", err
	}
	f, err := os.OpenFile(abs, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return "", fmt.Errorf("файл %s уже есть — не перезаписываю", abs)
		}
		return "", err
	}
	// Открыт не обычный файл (устройство) — ключ туда не пишется, и
	// открытое не удаляется: это не наш файл.
	if st, serr := f.Stat(); serr != nil || adminKeyRegularErr(st) != nil {
		_ = f.Close()
		return "", fmt.Errorf("%s — не обычный файл; ключ не записан", abs)
	}
	_, werr := f.WriteString(key.Reveal() + "\n")
	cerr := f.Close()
	if werr != nil || cerr != nil {
		_ = os.Remove(abs)
		return "", fmt.Errorf("запись файла %s не удалась", abs)
	}
	if st, err := os.Lstat(abs); err != nil || adminKeyRegularErr(st) != nil {
		return "", fmt.Errorf("после записи %s — не обычный файл; ключ не считается записанным", abs)
	}
	return abs, nil
}

// adminKeyReserved — имена устройств Windows (основа имени до первой точки,
// без хвостовых пробелов, без учёта регистра). Проверяются на ВСЕХ ОС:
// файл переносят между системами, а проверка исполняется в CI на трёх ОС.
var adminKeyReserved = func() map[string]bool {
	m := map[string]bool{"CON": true, "PRN": true, "AUX": true, "NUL": true, "CONIN$": true, "CONOUT$": true}
	for _, p := range []string{"COM", "LPT"} {
		for _, d := range []string{"0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "¹", "²", "³"} {
			m[p+d] = true
		}
	}
	return m
}()

// AdminKeyFileNameErr — имя файла ключа: только имя (без каталога и
// двоеточия), не имя устройства Windows (NUL, CON, COM1, «nul.txt»…) и без
// хвостовых точек и пробелов (Windows их молча отбрасывает).
func AdminKeyFileNameErr(name string) error {
	if name == "" || name == "." || name == ".." || strings.ContainsAny(name, `/\:`) || strings.ContainsRune(name, 0) {
		return errors.New("имя файла ключа — только имя, без каталога и двоеточия; каталог выбирается в следующем окне")
	}
	if strings.HasSuffix(name, ".") || strings.HasSuffix(name, " ") {
		return errors.New("имя файла ключа не должно кончаться точкой или пробелом — Windows их отбрасывает и создаёт файл с другим именем")
	}
	base := name
	if i := strings.IndexByte(base, '.'); i >= 0 {
		base = base[:i]
	}
	if adminKeyReserved[strings.ToUpper(strings.TrimRight(base, " "))] {
		return errors.New("имя файла ключа — имя устройства Windows (NUL, CON, PRN, AUX, COM*, LPT*): запись ушла бы в устройство, а не в файл; выберите другое имя")
	}
	return nil
}

// adminKeyTargetErr — итоговый путь обязан лежать в каталоге из path под
// тем же именем и не быть путём устройства (\\.\ или \\?\).
func adminKeyTargetErr(path, abs string) error {
	dir, err := filepath.Abs(filepath.Dir(path))
	if err != nil {
		return err
	}
	if strings.HasPrefix(abs, `\\.\`) || strings.HasPrefix(abs, `\\?\`) ||
		filepath.Dir(abs) != dir || filepath.Base(abs) != filepath.Base(path) {
		return fmt.Errorf("путь %s — не файл в каталоге %s; ключ не записан", abs, dir)
	}
	return nil
}

// adminKeyRegularErr — открытое или записанное — обычный файл.
func adminKeyRegularErr(st os.FileInfo) error {
	if !st.Mode().IsRegular() {
		return errors.New("не обычный файл")
	}
	return nil
}
