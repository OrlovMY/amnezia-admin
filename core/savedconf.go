package core

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Сохранённый конфиг клиента (меню «Показать QR» / «Сохранить конфигурацию…»).
//
// Приватный ключ клиента сервер НЕ хранит: он есть только в .conf, который
// программа сохранила на этом компьютере. Поэтому показать или сохранить
// конфиг можно лишь из такого файла, а если его нет — восстановить нельзя.
//
// Сопоставление — по ПУБЛИЧНОМУ ключу: из PrivateKey файла вычисляется
// публичный и сравнивается с ClientID. Имени файла не доверяем: файлы по
// имени перезаписываются (два клиента с одним именем, переименование).

// SavedConfState — нашёлся ли сохранённый конфиг. ТРИ состояния: «не
// сохранялся» и «не удалось прочитать» — разные вещи (CLAUDE.md, признак 1):
// первое значит «восстановить нельзя», второе — «не знаем».
type SavedConfState int

const (
	// SavedUnreadable — каталог или файл прочитать не удалось: есть ли среди
	// нечитаемого конфиг этого клиента — неизвестно. Нулевое значение —
	// именно «не знаем» (признак 2).
	SavedUnreadable SavedConfState = iota
	// SavedNotFound — НЕ НАЙДЕН: все каталоги поиска прочитаны, конфига этого
	// клиента в них нет. Это не «не сохранялся»: его могли сохранить в
	// другое место (другой рабочий каталог, «Сохранить ещё в…»).
	SavedNotFound
	// SavedFound — найден файл с приватным ключом этого клиента.
	SavedFound
)

// SavedConfig — результат поиска. Config содержит ПРИВАТНЫЙ КЛЮЧ клиента:
// его не печатают, не логируют и не кладут в текст ошибок. Why — без
// секретов (пути и тексты ошибок файловой системы).
type SavedConfig struct {
	State   SavedConfState
	Path    string // найденный файл (State == SavedFound)
	Config  string // содержимое (State == SavedFound) — СЕКРЕТ
	Matches int    // сколько файлов с этим ключом (взят первый по имени)
	Why     string // почему не найден или не прочитан
	Legacy  bool   // найден в каталоге прежних версий («Конфигурации» рядом с программой)
	// Searched — где искали (абсолютные пути), для «не найден»: человек должен
	// видеть, ГДЕ не нашли, а не только что не нашли.
	Searched []string
}

// SavedDir — каталог поиска. Err — каталог не определён. Legacy — каталог
// прежних версий: только чтение, файлы там не трогаются и не переносятся
// (решение владельца 19.09.2026).
type SavedDir struct {
	Path   string
	Err    error
	Legacy bool
}

// LegacyConfigDirs — где лежат .conf, сохранённые версиями ДО A4в
// (42eafbd, 19.09.2026). Тогда путь был ОТНОСИТЕЛЬНЫМ —
// filepath.Join("Конфигурации", имя) — то есть от ТЕКУЩЕГО каталога процесса,
// а не от программы. При запуске двойным щелчком текущий каталог — папка
// программы, поэтому ищем в обоих: «Конфигурации» в текущем каталоге и рядом
// с исполняемым файлом (совпадают — один раз).
func LegacyConfigDirs() []SavedDir {
	var out []SavedDir
	seen := map[string]bool{}
	add := func(p string, err error) {
		if err != nil {
			out = append(out, SavedDir{Err: err, Legacy: true})
			return
		}
		key := strings.ToLower(filepath.Clean(p))
		if seen[key] {
			return
		}
		seen[key] = true
		out = append(out, SavedDir{Path: p, Legacy: true})
	}
	if wd, err := legacyGetwd(); err != nil {
		add("", fmt.Errorf("текущий каталог не определён: %w", err))
	} else {
		add(filepath.Join(wd, legacyConfigsDirName), nil)
	}
	if exe, err := legacyExecutable(); err != nil {
		add("", fmt.Errorf("каталог программы не определён: %w", err))
	} else {
		add(filepath.Join(filepath.Dir(exe), legacyConfigsDirName), nil)
	}
	return out
}

const legacyConfigsDirName = "Конфигурации"

// Швы для теста «каталог не определён».
var (
	legacyGetwd      = os.Getwd
	legacyExecutable = os.Executable
)

// FindSavedConfigIn — поиск по нескольким каталогам (каталог данных ОС и
// каталоги прежних версий). «Не сохранялся» — только если ВСЕ каталоги
// прочитаны и совпадений нет; любой непрочитанный — «не прочитано»
// (решение 01.10.2026: у владельца настоящие конфиги лежат в старом месте).
// Найденный — первый по порядку каталогов, затем по имени файла.
func FindSavedConfigIn(dirs []SavedDir, clientID string) SavedConfig {
	var found SavedConfig
	var unread, notFound, searched []string
	for _, d := range dirs {
		if d.Err == nil {
			searched = append(searched, d.Path)
		}
		r := FindSavedConfig(d.Path, d.Err, clientID)
		switch r.State {
		case SavedFound:
			if found.State != SavedFound {
				found = r
				found.Legacy = d.Legacy
				found.Matches = 0
			}
			found.Matches += r.Matches
		case SavedNotFound:
			notFound = append(notFound, r.Why)
		default:
			unread = append(unread, r.Why)
		}
	}
	switch {
	case found.State == SavedFound:
		return found
	case len(unread) > 0:
		return SavedConfig{State: SavedUnreadable, Why: strings.Join(unread, "; ")}
	case len(dirs) == 0:
		return SavedConfig{State: SavedUnreadable, Why: "не задано ни одного каталога поиска"}
	}
	return SavedConfig{State: SavedNotFound, Why: strings.Join(notFound, "; "), Searched: searched}
}

// FindSavedConfig ищет в каталоге dir (каталог конфигураций, UserConfigsDir)
// .conf, чей PrivateKey даёт публичный ключ clientID. dirErr — ошибка
// определения каталога: тогда State = SavedUnreadable.
func FindSavedConfig(dir string, dirErr error, clientID string) SavedConfig {
	if dirErr != nil {
		return SavedConfig{State: SavedUnreadable, Why: "каталог конфигураций не определён: " + dirErr.Error()}
	}
	want := strings.TrimSpace(clientID)
	if want == "" {
		return SavedConfig{State: SavedUnreadable, Why: "у клиента нет ключа (clientId пуст) — сопоставить не с чем"}
	}
	entries, err := os.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		// «Нет» — только если и Stat говорит «нет»: на Windows ReadDir ФАЙЛА
		// вместо каталога тоже даёт ErrNotExist, а это «не прочитано».
		if _, serr := os.Stat(dir); errors.Is(serr, fs.ErrNotExist) {
			return SavedConfig{State: SavedNotFound, Why: "каталог конфигураций " + dir + " ещё не создавался"}
		}
		return SavedConfig{State: SavedUnreadable, Why: "каталог конфигураций не прочитан: " + err.Error()}
	}
	if err != nil {
		return SavedConfig{State: SavedUnreadable, Why: "каталог конфигураций не прочитан: " + err.Error()}
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() && strings.EqualFold(filepath.Ext(e.Name()), ".conf") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	var found SavedConfig
	var unreadable []string
	for _, n := range names {
		p := filepath.Join(dir, n)
		b, err := readSavedFile(p)
		if err != nil {
			unreadable = append(unreadable, err.Error())
			continue
		}
		priv := parseWgConf(string(b)).iface["PrivateKey"]
		if priv == "" {
			continue
		}
		pub, err := pubFromPriv(priv)
		if err != nil || pub != want {
			continue
		}
		if found.State != SavedFound {
			found = SavedConfig{State: SavedFound, Path: p, Config: string(b)}
		}
		found.Matches++
	}
	if found.State == SavedFound {
		return found
	}
	if len(unreadable) > 0 {
		return SavedConfig{State: SavedUnreadable, Why: fmt.Sprintf("в каталоге %s не прочитано файлов: %d (%s); среди прочитанных конфига этого клиента нет", dir, len(unreadable), unreadable[0])}
	}
	return SavedConfig{State: SavedNotFound, Why: "в каталоге " + dir + " конфига этого клиента нет"}
}

// readSavedFile — чтение файла (шов для теста «файл не читается»).
var readSavedFile = os.ReadFile

// CheckState — сверка параметра файла с сервером: три состояния, нулевое —
// «не сверено».
type CheckState int

const (
	CheckUnknown CheckState = iota // сервер не прочитан или параметра там нет
	CheckSame
	CheckDiffer
)

// SavedCheck — сверка сохранённого конфига с сервером.
type SavedCheck struct {
	PSK, Address CheckState
	Why          string // почему не сверено (CheckUnknown)
	Endpoint     string // Endpoint из файла — как есть (может отличаться от текущего адреса)
}

// CheckSavedConfig сверяет PresharedKey и Address файла с параметрами
// сервера. serverErr != nil — сервер не прочитан: обе сверки CheckUnknown.
func CheckSavedConfig(config, serverPSK, serverAddr string, serverErr error) SavedCheck {
	conf := parseWgConf(config)
	var ch SavedCheck
	if len(conf.peers) > 0 {
		ch.Endpoint = conf.peers[0]["Endpoint"]
	}
	if serverErr != nil {
		ch.Why = serverErr.Error()
		return ch
	}
	filePSK := ""
	if len(conf.peers) > 0 {
		filePSK = conf.peers[0]["PresharedKey"]
	}
	ch.PSK = compareParam(filePSK, serverPSK)
	ch.Address = compareParam(normAddrs(conf.iface["Address"]), normAddrs(serverAddr))
	return ch
}

func compareParam(file, server string) CheckState {
	file, server = strings.TrimSpace(file), strings.TrimSpace(server)
	switch {
	case server == "":
		return CheckUnknown
	case file == server:
		return CheckSame
	}
	return CheckDiffer
}

// normAddrs — список адресов без пробелов, по порядку как есть.
func normAddrs(s string) string {
	var out []string
	for _, a := range strings.Split(s, ",") {
		if a = strings.TrimSpace(a); a != "" {
			out = append(out, a)
		}
	}
	return strings.Join(out, ",")
}

// ClientPeerParams — PresharedKey и адрес клиента по данным сервера: из блока
// [Peer] wg0.conf (активный) или из clientsTable (отключённый — peer'а в
// wg0.conf нет, параметры сохранены в записи). Не найдено — ошибка, а не
// пустые строки (признак 2).
func (s *Session) ClientPeerParams(c *Container, cl ClientEntry) (psk, addr string, err error) {
	if cl.EnabledState() == EnabledDisabled {
		psk, addr = Str(cl.UserData, "psk"), Str(cl.UserData, "allowedIP")
		if psk == "" || addr == "" {
			return "", "", errors.New("клиент отключён, а параметры peer'а в его записи не сохранены")
		}
		return psk, addr, nil
	}
	text, err := s.catIn(c, c.Dir+"/wg0.conf")
	if err != nil {
		return "", "", fmt.Errorf("wg0.conf не прочитан: %w", err)
	}
	for _, p := range parseWgConf(text).peers {
		if p["PublicKey"] == cl.ClientID {
			if p["PresharedKey"] == "" || p["AllowedIPs"] == "" {
				return "", "", errors.New("в wg0.conf у peer'а этого клиента нет PresharedKey или AllowedIPs")
			}
			return p["PresharedKey"], p["AllowedIPs"], nil
		}
	}
	return "", "", errors.New("peer этого клиента в wg0.conf не найден")
}
