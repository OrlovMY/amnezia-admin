package core

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
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
			return "", errors.New(`не удалось определить каталог данных пользователя: переменная окружения LOCALAPPDATA не задана (обычно это C:\Users\<имя>\AppData\Local). Конфиг НЕ сохранён`)
		}
	} else {
		var err error
		base, err = os.UserConfigDir()
		if err != nil {
			return "", fmt.Errorf("не удалось определить каталог данных пользователя: %w. Конфиг НЕ сохранён", err)
		}
	}
	if !filepath.IsAbs(base) {
		return "", fmt.Errorf("каталог данных пользователя %q не абсолютный — конфиг не сохранён", base)
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
//
// Второе возвращаемое значение — dirWasMissing: каталога перед этим вызовом
// НЕ БЫЛО. По нему CLI и GUI показывают ОДНОРАЗОВУЮ подсказку о смене места
// (ревью UX-01) — но только при успехе: при ошибке оба возвращаются раньше.
//
// Признак намеренно узкий: true только если os.Stat ответил «нет такого
// каталога». Если Stat не смог ответить по другой причине (нет прав, сбой
// ФС, недопустимое имя), признак остаётся false — лучше не показать
// подсказку, чем объявить место новым, не зная этого.
//
// ЗНАЧЕНИЕ ВОЗВРАЩАЕТСЯ И ВМЕСТЕ С ОШИБКОЙ, а не заменяется на false
// (ревью SEC-01, второй круг). Пока ветви ошибок отдавали константный false,
// подмена `любая ошибка Stat = каталога нет` проходила ВЕСЬ набор зелёной:
// единственные случаи, где Stat отвечает третьим способом, — это как раз
// случаи, где запись потом не удаётся, и вычисленное значение до теста не
// доезжало. Узость признака проверяема ровно потому, что значение не
// затирается.
func WriteClientConfig(dir, name, config string) (path string, dirWasMissing bool, err error) {
	r, err := SaveClientConfig(dir, name, config, "")
	return r.Path, r.DirWasMissing, err
}

// SaveResult — итог SaveClientConfig.
type SaveResult struct {
	Path          string
	DirWasMissing bool
	// Occupied — имя файла, занятого конфигом ДРУГОГО клиента (или
	// непроверяемым файлом): сохранено под другим именем (Path). "" — нет.
	Occupied string
}

// SaveClientConfig — запись конфига клиента name, которая НЕ затирает файл
// другого клиента (АУДИТ-МЕНЮ-QR-LOGIC К-1: «Phone» переименован в «Old
// phone», создан новый «Phone» — прежде Phone.conf, единственная копия
// ключа «Old phone», затирался молча; то же для «Phone»/«phone» на Windows).
//
// Имя занято, если в каталоге есть файл с тем же именем БЕЗ учёта регистра
// (на Windows и macOS это один файл). Перезаписать можно, только если его
// PrivateKey даёт ключ ЭТОГО клиента или replaces (прежний ключ этого же
// клиента при rekey). Другой ключ, не читается, не разбирается — файл не
// трогается, берётся «<имя> (2).conf», «(3)»… и Occupied называет занятое.
// Запись атомарная: временный файл 0600 в том же каталоге и rename.
func SaveClientConfig(dir, name, config, replaces string) (SaveResult, error) {
	return SaveClientConfigExt(dir, name, config, replaces, ".conf")
}

// SaveUserConfig — SaveClientConfig для выданного конфига: расширение и
// «чей файл» — по виду конфига (XRay — .json и UUID клиента).
func SaveUserConfig(dir string, u *NewUser) (SaveResult, error) {
	return SaveClientConfigExt(dir, u.Name, u.Config, u.Replaces, u.FileExt())
}

// SaveClientConfigExt — SaveClientConfig с расширением ext (".conf" или
// ".json" у XRay). Чей файл — по ключу клиента в конфиге (configIdentity).
func SaveClientConfigExt(dir, name, config, replaces, ext string) (SaveResult, error) {
	if ext != ".conf" && ext != ".json" {
		return SaveResult{}, fmt.Errorf("недопустимое расширение конфига %q — конфиг не сохранён", ext)
	}
	var r SaveResult
	if !filepath.IsAbs(dir) {
		return r, fmt.Errorf("каталог для конфигов %q не абсолютный — конфиг не сохранён", dir)
	}
	_, statErr := os.Stat(dir)
	r.DirWasMissing = errors.Is(statErr, fs.ErrNotExist)
	if err := os.MkdirAll(dir, configsDirPerm); err != nil {
		return r, err
	}
	// Выбор имени и запись — под межпроцессным замком каталога
	// (АУДИТ-МЕНЮ-QR-LOGIC М-2): две копии программы, сохраняющие одно имя
	// (или одно без учёта регистра), иначе обе видят имя свободным и вторая
	// затирает первую. Тот же механизм, что у known_hosts (PR #31).
	err := withConfigsLock(dir, func() error {
		var err error
		r, err = saveClientConfigLocked(dir, name, config, replaces, ext, r)
		return err
	})
	return r, err
}

// ErrConfigsBusy — каталог конфигураций занят другой копией программы
// дольше configsLockWait: конфиг НЕ сохранён.
var ErrConfigsBusy = errors.New("каталог конфигураций занят другой копией программы — конфиг не сохранён, повторите")

// configsLockWait — сколько ждать замок каталога конфигураций.
var configsLockWait = 10 * time.Second

// configsLockName — файл замка в каталоге конфигураций (не *.conf: поиск
// конфигов его не видит).
const configsLockName = ".configs.lock"

// withConfigsLock — fn под межпроцессным замком каталога dir (файл
// .configs.lock, 0600; flock/LockFileEx через tryLockFile). Ждём не дольше
// configsLockWait, затем — громкий отказ ErrConfigsBusy.
func withConfigsLock(dir string, fn func() error) error {
	lf, err := os.OpenFile(filepath.Join(dir, configsLockName), os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		return fmt.Errorf("замок каталога конфигураций: %w — конфиг не сохранён", err)
	}
	defer lf.Close()
	deadline := time.Now().Add(configsLockWait)
	for {
		busy, err := tryLockFile(lf)
		if err != nil {
			return fmt.Errorf("замок каталога конфигураций: %w — конфиг не сохранён", err)
		}
		if !busy {
			break
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("%w (ждали %v): %s", ErrConfigsBusy, configsLockWait, dir)
		}
		time.Sleep(20 * time.Millisecond)
	}
	defer unlockFile(lf)
	return fn()
}

func saveClientConfigLocked(dir, name, config, replaces, ext string, r SaveResult) (SaveResult, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return r, fmt.Errorf("каталог конфигов %s не прочитан — не проверить, не занято ли имя; конфиг не сохранён: %w", dir, err)
	}
	mine := configIdentity(config, ext)
	base := SanitizeName(name)
	for n := 1; n <= 1000; n++ {
		cand := base + ext
		if n > 1 {
			cand = fmt.Sprintf("%s (%d)%s", base, n, ext)
		}
		existing := ""
		for _, e := range entries {
			if strings.EqualFold(e.Name(), cand) {
				existing = e.Name()
				break
			}
		}
		if existing != "" {
			if !sameClientFile(filepath.Join(dir, existing), mine, replaces, ext) {
				if r.Occupied == "" {
					r.Occupied = existing
				}
				continue
			}
			cand = existing // тот же файл — писать под его настоящим именем
		}
		r.Path = filepath.Join(dir, cand)
		if err := atomicWrite0600(dir, r.Path, []byte(config)); err != nil {
			return SaveResult{DirWasMissing: r.DirWasMissing}, err
		}
		return r, nil
	}
	return SaveResult{DirWasMissing: r.DirWasMissing}, fmt.Errorf("в каталоге %s заняты все имена %q (1…1000) — конфиг не сохранён", dir, base)
}

// sameClientFile — файл p содержит конфиг клиента с ключом mine или
// replaces. Не читается, не разбирается, не обычный — НЕ этот клиент
// (перезаписывать нельзя).
func sameClientFile(p, mine, replaces, ext string) bool {
	b, err := readSavedFile(p)
	if err != nil {
		return false
	}
	pub := configIdentity(string(b), ext)
	if pub == "" {
		return false
	}
	return (mine != "" && pub == mine) || (replaces != "" && pub == replaces)
}

// configIdentity — ключ клиента в тексте конфига: публичный ключ из
// PrivateKey (.conf) или UUID пользователя vless (.json XRay); "" — не
// разобрать (такой файл — не этот клиент).
func configIdentity(config, ext string) string {
	if ext == ".json" {
		var c struct {
			Outbounds []struct {
				Settings struct {
					Vnext []struct {
						Users []struct {
							ID string `json:"id"`
						} `json:"users"`
					} `json:"vnext"`
				} `json:"settings"`
			} `json:"outbounds"`
		}
		if json.Unmarshal([]byte(config), &c) != nil || len(c.Outbounds) == 0 || len(c.Outbounds[0].Settings.Vnext) == 0 ||
			len(c.Outbounds[0].Settings.Vnext[0].Users) == 0 || !reUUID.MatchString(c.Outbounds[0].Settings.Vnext[0].Users[0].ID) {
			return ""
		}
		return c.Outbounds[0].Settings.Vnext[0].Users[0].ID
	}
	pub, err := pubFromPriv(parseWgConf(config).iface["PrivateKey"])
	if err != nil {
		return ""
	}
	return pub
}

// atomicWrite0600 — временный файл 0600 в каталоге dir, затем rename на
// path: при сбое прежний файл цел.
func atomicWrite0600(dir, path string, data []byte) error {
	f, err := os.CreateTemp(dir, ".amnezia-conf-*.tmp")
	if err != nil {
		return err
	}
	tmp := f.Name()
	ok := false
	defer func() {
		if !ok {
			os.Remove(tmp)
		}
	}()
	if err := f.Chmod(0o600); err != nil && runtime.GOOS != "windows" {
		f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	ok = true
	return nil
}

// SaveFailedAdvice — ЧТО ДЕЛАТЬ, когда конфиг сохранить не удалось.
//
// Текст общий для CLI и GUI и живёт здесь именно поэтому (ревью SEC-01,
// второй круг): половины уже разъехались один раз — в CLI совет был, в GUI
// был голый dialog.ShowError. Каждая половина дописывает к этому тексту
// СВОЙ способ перевыпуска (команду или кнопку) и ничего больше.
//
// К моменту показа пользователь на сервере УЖЕ СОЗДАН (AddUser или
// RegenerateUser отработали), а конфиг существует только в памяти процесса.
// Сам конфиг ни здесь, ни в вызывающих не печатается: терминал и журналы
// сохраняют его в местах, о которых человек в момент досады не думает
// (решение ядра, 19.09.2026).
func SaveFailedAdvice(name string) string {
	return fmt.Sprintf("Пользователь %q на сервере создан, но конфиг сохранить не удалось. "+
		"Исправьте каталог и перевыпустите конфиг — прежний конфиг этого пользователя "+
		"после перевыпуска работать не будет.", name)
}

// FirstSaveHint — текст одноразовой подсказки о смене места сохранения
// (показывается, когда WriteClientConfig вернул dirWasMissing).
//
// Формулировка НИЧЕГО НЕ УТВЕРЖДАЕТ о содержимом каталогов владельца:
// программа не открывает прежнюю папку, не знает, лежит ли там что-нибудь, и
// не знает, откуда её запускали раньше. Поэтому «если такие файлы есть», а не
// «ваши файлы остались там-то».
const FirstSaveHint = "Это новое место. Прежние версии сохраняли .conf в папку «Конфигурации» " +
	"рядом с каталогом, из которого запускалась программа. Если такие файлы есть, они остались " +
	"на прежнем месте: эта версия их не переносит, не открывает и не удаляет."
