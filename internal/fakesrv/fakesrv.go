// Package fakesrv — сервер Amnezia в памяти для юнит-тестов пакета core: без
// сети, без диска (кроме собственной map в памяти) и без реального SSH. core
// подменяет транспорт через структурный интерфейс core.Runner (метод
// Run(cmd string, stdin []byte) (string, error)) — Server реализует этот же
// метод, но НАМЕРЕННО НЕ импортирует core, иначе тесты пакета core (которые
// импортируют fakesrv) замкнулись бы в цикл импорта.
//
// Server разбирает РОВНО те серверные команды, что на 2026-09-14 шлёт core
// (docker ps/exec, резервное копирование, wg syncconf/show, sudo-фолбэк,
// test -f, запись со сверкой под замком — A3б) — и только их. Любая другая команда
// возвращает ошибку "неизвестная команда": это не удобство, а страж — если
// core когда-нибудь начнёт слать на
// сервер что-то новое или изменит текст существующей команды, тест на
// fakesrv тут же упадёт, а не тихо отработает "как-нибудь".
package fakesrv

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"
)

// clientEntry — форма записи clientsTable (json-теги должны совпадать с
// core.ClientEntry). Локальная копия без импорта core — см. комментарий пакета.
type clientEntry struct {
	ClientID string         `json:"clientId"`
	UserData map[string]any `json:"userData"`
}

// Server — фейковый сервер Amnezia. Экспортированные поля — хуки для
// тестов; их правят до вызова методов Session (гонок в тестах пакета core не
// бывает — один Session работает поверх одного Server последовательно).
type Server struct {
	// Names — контейнеры, которые "запущены" на сервере (вернёт `docker ps`).
	Names []string

	// FailRead — путь → ошибка для `docker exec … cat <path>`. Общий хук на
	// чтение файла: PR-2 пользуется этим же полем, а не заводит своё.
	FailRead map[string]error

	// WriteFault — номер по счёту команды записи (apply и rollback вместе,
	// счёт с 1) → исход, подменяющий настоящий: код выхода и, если Written,
	// файлы перед этим всё-таки записываются (A3б: «неизвестно, записано
	// ли» бывает и после записи).
	WriteFault map[int]WriteFault

	// ForeignWrite — номер по счёту команды записи (как в WriteFault) →
	// файлы (путь → байты), которые «другой писатель» записывает на сервер
	// непосредственно ПЕРЕД этой командой. Боевой путь исходов «изменён
	// другим» (N = 1) и «откат не тронул чужое» (N = 2 после сбоя verify)
	// без обёртки над Runner — нужен тестам через настоящий SSH (A3б PR-3).
	ForeignWrite map[int]map[string][]byte

	// FailMvTo — имя файла (wg0.conf или clientsTable): mv на него в
	// настоящем скрипте падает с «Permission denied» (подменой mv в PATH).
	FailMvTo string

	// Violations — нарушения протокола, замеченные сервером (повтор записи
	// под sudo после начатой записи).
	Violations []string

	// TempLeft — сколько временных файлов *.aa.* скрипт оставил после себя
	// (сумма по всем командам записи); читать после работы Session.
	TempLeft int

	// LockBusy — замок на хосте занят: команда записи возвращает код 4
	// (flock -E 4), ничего не записав.
	LockBusy bool

	// MissingTool — нет утилиты. "timeout"/"flock" (на хосте) — модель: код
	// 127 оболочки. Утилиты контейнера (sha256sum, base64, mv, rm) убираются
	// из PATH настоящего скрипта — код 5 даёт сам скрипт.
	MissingTool string

	// FailTool — утилита контейнера (сейчас "sha256sum"), которая в
	// настоящем скрипте запускается, но падает с кодом 1.
	FailTool string

	// FailSyncconf — если задана, `wg syncconf` вернёт эту ошибку, а рантайм
	// (множество применённых peer'ов) не меняется.
	FailSyncconf error

	// FailSyncconfFrom — если > 0, `wg syncconf` начинает возвращать ошибку
	// начиная с N-го по счёту вызова (счёт с 1) и до конца жизни Server;
	// вызовы до этого — как обычно. Нужен, чтобы отличить в тесте "первый
	// (apply-time) syncconf прошёл, второй (restore-time retry) — упал" (SEC-01,
	// PR-2 changes-requested: restore обязан ПРОВЕРЯТЬ состояние, а не
	// верить коду возврата повторного syncconf).
	FailSyncconfFrom int

	// DenyOnce — самая первая команда без префикса "sudo " будет отклонена
	// ошибкой со словом "denied" (проверка sudo-фолбэка в Session.docker).
	// Все последующие команды, включая повтор той же команды с "sudo ",
	// выполняются как обычно.
	DenyOnce bool

	// DropPeerOnSync — если задан, `wg syncconf` "применяется" без ошибки, но
	// этот PublicKey исключается из результирующего рантайма (PR-2,
	// TestVerifyMissingPeerRestores): имитирует случай, когда syncconf
	// вернул код 0, но peer фактически не поднялся.
	DropPeerOnSync string

	mu            sync.Mutex
	files         map[string][]byte
	peers         map[string]bool // публичные ключи peer'ов, применённые последним syncconf
	commands      []string
	stdins        [][]byte // stdin команд записи
	writeStarted  string   // команда записи, дошедшая до скрипта последней командой
	denyOnceUsed  bool
	syncconfCalls int // счётчик вызовов syncconf — для FailSyncconfFrom
	writeCalls    int // счётчик команд записи — для WriteFault
}

// New создаёт Server с дефолтным состоянием: один контейнер amnezia-awg,
// wg0.conf с PrivateKey/Address=10.8.1.1/24/ListenPort и двумя peer'ами,
// clientsTable с двумя соответствующими записями. Приватный ключ сервера и
// ключи peer'ов — случайные (не константы из чужого конфига).
func New() *Server {
	srvPriv := randBase64()
	peer1Pub, peer1Psk := randBase64(), randBase64()
	peer2Pub, peer2Psk := randBase64(), randBase64()

	wg0 := fmt.Sprintf(
		"[Interface]\nPrivateKey = %s\nAddress = 10.8.1.1/24\nListenPort = 51820\n\n"+
			"[Peer]\nPublicKey = %s\nPresharedKey = %s\nAllowedIPs = 10.8.1.2/32\n\n"+
			"[Peer]\nPublicKey = %s\nPresharedKey = %s\nAllowedIPs = 10.8.1.3/32\n",
		srvPriv, peer1Pub, peer1Psk, peer2Pub, peer2Psk)

	now := time.Now().Format(time.RFC3339)
	clients := []clientEntry{
		{ClientID: peer1Pub, UserData: map[string]any{"clientName": "Alice", "creationDate": now}},
		{ClientID: peer2Pub, UserData: map[string]any{"clientName": "Bob", "creationDate": now}},
	}
	tbl, err := json.MarshalIndent(clients, "", "    ")
	if err != nil {
		panic("fakesrv: не удалось собрать дефолтную clientsTable: " + err.Error())
	}

	return &Server{
		Names: []string{"amnezia-awg"},
		files: map[string][]byte{
			"/opt/amnezia/awg/wg0.conf":     []byte(wg0),
			"/opt/amnezia/awg/clientsTable": tbl,
		},
		peers: map[string]bool{peer1Pub: true, peer2Pub: true},
	}
}

func randBase64() string {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("fakesrv: rand.Read: " + err.Error())
	}
	return base64.StdEncoding.EncodeToString(b[:])
}

// Commands возвращает журнал всех полученных команд в порядке получения
// (включая отклонённые хуками — DenyOnce и т.п.).
func (s *Server) Commands() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, len(s.commands))
	copy(out, s.commands)
	return out
}

// Stdins — stdin всех команд записи (apply и rollback) по порядку.
func (s *Server) Stdins() [][]byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([][]byte, len(s.stdins))
	copy(out, s.stdins)
	return out
}

// File возвращает содержимое файла фейковой ФС и признак, что он существует.
func (s *Server) File(path string) ([]byte, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.files == nil {
		return nil, false
	}
	data, ok := s.files[path]
	return data, ok
}

// SetFile кладёт файл в фейковую ФС (создаёт или заменяет).
func (s *Server) SetFile(path string, data []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.files == nil {
		s.files = map[string][]byte{}
	}
	s.files[path] = append([]byte(nil), data...)
}

// DeleteFile убирает файл из фейковой ФС (моделирует "файла нет").
func (s *Server) DeleteFile(path string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.files, path)
}

// RuntimePeers возвращает публичные ключи peer'ов, применённые последним
// успешным `wg syncconf` (или заданные в New(), если syncconf ещё не вызывался).
func (s *Server) RuntimePeers() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, 0, len(s.peers))
	for k := range s.peers {
		out = append(out, k)
	}
	return out
}

// ---------- разбор серверных команд ----------
//
// Регэкспы ниже — рабочая копия литеральных шаблонов из core/core.go
// (d6b3a5a); эталонная проверка байт-в-байт — TestServerCommandsUnchanged в
// core/core_test.go, а не эти регэкспы. Здесь важно распознать и правильно
// исполнить команду; повторяющиеся %s (например, каталог контейнера в
// команде резервного копирования) захватываются отдельными группами и потом
// сверяются в коде — Go/RE2 не поддерживает обратные ссылки в самом паттерне.
var (
	reDockerPS = `docker ps --format '{{.Names}}'`
	reCat      = regexp.MustCompile(`^docker exec (\S+) cat (\S+)$`)
	// reCASWrite — A3б: запись обоих файлов со сверкой под flock на каталоге
	// /run/lock. Тело скрипта берётся из команды и ИСПОЛНЯЕТСЯ настоящим sh
	// (execScript); побайтно текст сверяет TestServerCommandsUnchanged в core.
	// Замок flock здесь — мьютекс s.mu; настоящую строку замка исполняет
	// TestCASLockLineRealFlock (Linux).
	reCASWrite = regexp.MustCompile(`^timeout 75 flock -w 15 -E 4 /run/lock/ docker exec -i (\S+) timeout 50 sh -c '([^']*)' (amnezia-admin-apply|amnezia-admin-rollback) (\S+) ([0-9a-f]{64}) ([0-9a-f]{64}|absent)$`)
	reTestFile = regexp.MustCompile(`^docker exec (\S+) sh -c 'test -f (\S+)/clientsTable && echo yes \|\| echo no'$`)
	reBackup   = regexp.MustCompile(`^docker exec (\S+) sh -c 'mkdir -p (\S+)/backup && ts=\$\(date \+%Y%m%d-%H%M%S\) && ` +
		`cp (\S+)/wg0\.conf (\S+)/backup/wg0\.conf\.\$ts && ` +
		`\(cp (\S+)/clientsTable (\S+)/backup/clientsTable\.\$ts 2>/dev/null; ` +
		`ls -1t (\S+)/backup/wg0\.conf\.\* 2>/dev/null \| tail -n \+21 \| while read f; do rm -f "\$f"; done; ` +
		`ls -1t (\S+)/backup/clientsTable\.\* 2>/dev/null \| tail -n \+21 \| while read f; do rm -f "\$f"; done\)'$`)
	reSyncconf = regexp.MustCompile(`^docker exec (\S+) bash -c 'wg syncconf wg0 <\(wg-quick strip (\S+)/wg0\.conf\)'$`)
	reWgShow   = regexp.MustCompile(`^docker exec (\S+) wg show wg0 dump$`)
)

// Run — реализация core.Runner. Каждая полученная команда логируется в
// Commands() ДО обработки (в том числе отклонённая хуками) — тесты проверяют
// "ни одной записи не произошло" именно по этому журналу.
func (s *Server) Run(cmd string, stdin []byte) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.commands = append(s.commands, cmd)

	actual := cmd
	isSudo := false
	if strings.HasPrefix(actual, "sudo ") {
		isSudo = true
		actual = strings.TrimPrefix(actual, "sudo ")
	}
	// Второй признак SEC F1: повтор ТОЙ ЖЕ команды записи под sudo сразу
	// после того, как она дошла до скрипта, — повтор после (возможно)
	// частичной записи. Отказ и запись в Violations.
	started := s.writeStarted
	s.writeStarted = ""
	if isSudo && started != "" && started == actual {
		s.Violations = append(s.Violations, "повтор записи под sudo после начатой записи")
		return "", fmt.Errorf("fakesrv: НАРУШЕНИЕ: повтор записи под sudo после начатой записи: %.80q", cmd)
	}
	if s.DenyOnce && !isSudo && !s.denyOnceUsed {
		s.denyOnceUsed = true
		return "", fmt.Errorf("команда %q: permission denied", cmd)
	}

	return s.dispatch(actual, stdin)
}

func (s *Server) dispatch(cmd string, stdin []byte) (string, error) {
	switch {
	case cmd == reDockerPS:
		return strings.Join(s.Names, "\n"), nil

	case reCat.MatchString(cmd):
		m := reCat.FindStringSubmatch(cmd)
		path := m[2]
		if s.FailRead != nil {
			if err, ok := s.FailRead[path]; ok {
				return "", err
			}
		}
		data, ok := s.files[path]
		if !ok {
			return "", fmt.Errorf("команда %q: exit status 1; stderr: cat: %s: No such file or directory", cmd, path)
		}
		return string(data), nil

	case reCASWrite.MatchString(cmd):
		return s.casWrite(cmd, reCASWrite.FindStringSubmatch(cmd), stdin)

	case reTestFile.MatchString(cmd):
		m := reTestFile.FindStringSubmatch(cmd)
		path := m[2] + "/clientsTable"
		if _, ok := s.files[path]; ok {
			return "yes\n", nil
		}
		return "no\n", nil

	case reBackup.MatchString(cmd):
		m := reBackup.FindStringSubmatch(cmd)
		dir := m[2]
		for _, g := range m[3:] {
			if g != dir {
				return "", fmt.Errorf("fakesrv: неизвестная команда %q", cmd)
			}
		}
		wg0, ok := s.files[dir+"/wg0.conf"]
		if !ok {
			return "", fmt.Errorf("команда %q: exit status 1; stderr: cp: %s/wg0.conf: No such file or directory", cmd, dir)
		}
		ts := time.Now().Format("20060102-150405")
		if s.files == nil {
			s.files = map[string][]byte{}
		}
		s.files[dir+"/backup/wg0.conf."+ts] = append([]byte(nil), wg0...)
		if ct, ok := s.files[dir+"/clientsTable"]; ok {
			s.files[dir+"/backup/clientsTable."+ts] = append([]byte(nil), ct...)
		}
		return "", nil

	case reSyncconf.MatchString(cmd):
		m := reSyncconf.FindStringSubmatch(cmd)
		dir := m[2]
		s.syncconfCalls++
		if s.FailSyncconf != nil {
			return "", s.FailSyncconf
		}
		if s.FailSyncconfFrom > 0 && s.syncconfCalls >= s.FailSyncconfFrom {
			return "", fmt.Errorf("команда %q: exit status 1; stderr: wg syncconf: имитированный отказ (вызов №%d)", cmd, s.syncconfCalls)
		}
		wg0, ok := s.files[dir+"/wg0.conf"]
		if !ok {
			return "", fmt.Errorf("команда %q: exit status 1; stderr: wg-quick: %s/wg0.conf: No such file or directory", cmd, dir)
		}
		peers := peerKeysFromConf(string(wg0))
		if s.DropPeerOnSync != "" {
			delete(peers, s.DropPeerOnSync)
		}
		s.peers = peers
		return "", nil

	case reWgShow.MatchString(cmd):
		var b strings.Builder
		b.WriteString("serverpriv\tserverpub\t51820\toff\n") // строка интерфейса — parsePeerStats её пропускает
		for pub := range s.peers {
			fmt.Fprintf(&b, "%s\t(none)\t(none)\t0.0.0.0/0\t0\t0\t0\toff\n", pub)
		}
		return b.String(), nil

	default:
		return "", fmt.Errorf("fakesrv: неизвестная команда %q", cmd)
	}
}

// peerKeysFromConf достаёт PublicKey из блоков [Peer] текста wg0.conf. Своя
// (упрощённая, но для нужд теста достаточная) реализация — пакет
// принципиально не импортирует core, чтобы не замкнуть тесты пакета core в
// цикл импорта.
func peerKeysFromConf(text string) map[string]bool {
	peers := map[string]bool{}
	inPeer := false
	for _, line := range strings.Split(text, "\n") {
		l := strings.TrimSpace(line)
		switch {
		case strings.EqualFold(l, "[Peer]"):
			inPeer = true
		case strings.HasPrefix(l, "["):
			inPeer = false
		case inPeer && strings.Contains(l, "="):
			kv := strings.SplitN(l, "=", 2)
			if strings.EqualFold(strings.TrimSpace(kv[0]), "PublicKey") {
				peers[strings.TrimSpace(kv[1])] = true
			}
		}
	}
	return peers
}

// WriteFault — подменённый исход команды записи (см. Server.WriteFault).
type WriteFault struct {
	Code    int
	Written bool
}

// ExitError — отказ команды с кодом выхода. Метод ExitStatus совпадает по
// форме с golang.org/x/crypto/ssh.ExitError: core распознаёт код одинаково
// у настоящего SSH и у фейка, а SSHServer отдаёт этот код клиенту.
type ExitError struct {
	Cmd    string
	Status int
	Stderr string
}

func (e *ExitError) Error() string {
	return fmt.Sprintf("команда %q: exit status %d; stderr: %s", e.Cmd, e.Status, e.Stderr)
}

// ExitStatus — код выхода.
func (e *ExitError) ExitStatus() int { return e.Status }

// casWrite исполняет команду записи: хуки хоста (замок занят, нет
// timeout/flock) — модель, тело скрипта — настоящий sh (execScript). Весь Run
// идёт под s.mu, поэтому две команды записи взаимно исключены, как под flock.
func (s *Server) casWrite(cmd string, m []string, stdin []byte) (string, error) {
	dir, wantWg, wantTbl := m[4], m[5], m[6]
	fail := func(code int, stderr string) (string, error) {
		return "", &ExitError{Cmd: cmd, Status: code, Stderr: stderr}
	}
	switch s.MissingTool {
	case "timeout", "flock":
		return fail(127, "sh: "+s.MissingTool+": not found")
	}
	if s.LockBusy {
		return fail(4, "")
	}
	s.writeCalls++
	for path, data := range s.ForeignWrite[s.writeCalls] {
		if s.files == nil {
			s.files = map[string][]byte{}
		}
		s.files[path] = append([]byte(nil), data...)
	}
	s.writeStarted = cmd
	s.stdins = append(s.stdins, append([]byte(nil), stdin...))
	fault, faulty := s.WriteFault[s.writeCalls]
	if faulty && !fault.Written {
		return fail(fault.Code, "имитированный отказ записи")
	}

	code, stderr, err := s.execScript(m[2], m[3], dir, wantWg, wantTbl, stdin)
	if err != nil {
		return "", err
	}
	if code != 0 {
		return fail(code, stderr)
	}
	if faulty {
		return fail(fault.Code, "имитированный отказ после записи")
	}
	return "", nil
}

// execScript исполняет НАСТОЯЩИЙ скрипт из команды (core.CASWriteScript —
// fakesrv берёт его из текста команды, импортировать core нельзя) настоящим
// sh на временном каталоге с копией двух файлов, затем забирает результат
// обратно в память. Замок flock моделирует s.mu: весь Run идёт под ним.
// Нет sh — громкий отказ с причиной, а не тихая подмена моделью.
func (s *Server) execScript(script, label, dir, wantWg, wantTbl string, stdin []byte) (int, string, error) {
	sh, err := FindSh()
	if err != nil {
		return 0, "", err
	}
	tmp, err := os.MkdirTemp("", "fakesrv-cas-")
	if err != nil {
		return 0, "", fmt.Errorf("fakesrv: временный каталог: %w", err)
	}
	defer os.RemoveAll(tmp)
	work := filepath.Join(tmp, "d")
	if err := os.Mkdir(work, 0o700); err != nil {
		return 0, "", fmt.Errorf("fakesrv: %w", err)
	}
	for _, name := range casFiles {
		if data, ok := s.files[dir+"/"+name]; ok {
			if err := os.WriteFile(filepath.Join(work, name), data, 0o600); err != nil {
				return 0, "", fmt.Errorf("fakesrv: %w", err)
			}
		}
	}
	env := os.Environ()
	if s.FailMvTo != "" || s.MissingTool != "" || s.FailTool != "" {
		shim, err := s.toolShim(sh, tmp)
		if err != nil {
			return 0, "", err
		}
		env = append(env, "PATH="+shim)
	}
	cmd := exec.Command(sh, "-c", script, label, filepath.ToSlash(work), wantWg, wantTbl)
	cmd.Env = env
	cmd.Stdin = bytes.NewReader(stdin)
	var errb bytes.Buffer
	cmd.Stderr = &errb
	code := 0
	if err := cmd.Run(); err != nil {
		var ee *exec.ExitError
		if !errors.As(err, &ee) {
			return 0, "", fmt.Errorf("fakesrv: не удалось запустить %s: %w", sh, err)
		}
		code = ee.ExitCode()
	}
	for _, name := range casFiles {
		data, err := os.ReadFile(filepath.Join(work, name))
		switch {
		case err == nil:
			if s.files == nil {
				s.files = map[string][]byte{}
			}
			s.files[dir+"/"+name] = data
		case os.IsNotExist(err):
			delete(s.files, dir+"/"+name)
		default:
			return 0, "", fmt.Errorf("fakesrv: %w", err)
		}
	}
	left, _ := filepath.Glob(filepath.Join(work, "*.aa.*"))
	s.TempLeft += len(left)
	return code, strings.TrimSpace(errb.String()), nil
}

var casFiles = []string{"wg0.conf", "clientsTable"}

// FindSh — путь к POSIX sh: из PATH, а на Windows ещё и из Git for Windows.
// Ошибка называет причину: без sh fakesrv не может исполнить скрипт записи.
func FindSh() (string, error) {
	if p, err := exec.LookPath("sh"); err == nil {
		return p, nil
	}
	if runtime.GOOS == "windows" {
		for _, p := range []string{`C:\Program Files\Git\bin\sh.exe`, `C:\Program Files\Git\usr\bin\sh.exe`} {
			if _, err := os.Stat(p); err == nil {
				return p, nil
			}
		}
	}
	return "", errors.New("fakesrv: не найден POSIX sh — скрипт записи (core.CASWriteScript) исполняется настоящей оболочкой, без неё проверка невозможна; на Windows установите Git for Windows (Git\\bin\\sh.exe)")
}

// casTools — внешние утилиты скрипта записи в контейнере.
var casTools = []string{"sha256sum", "base64", "mv", "rm"}

// toolShim — каталог, который становится ЕДИНСТВЕННЫМ PATH скрипта: обёртки
// над настоящими утилитами, кроме MissingTool (её нет вовсе), FailTool
// (падает) и mv на FailMvTo (Permission denied).
func (s *Server) toolShim(sh, tmp string) (string, error) {
	out, err := exec.Command(sh, "-c", "for t in "+strings.Join(casTools, " ")+"; do command -v $t || exit 1; done").Output()
	if err != nil {
		return "", fmt.Errorf("fakesrv: не найдены утилиты для скрипта записи (%s) в sh: %w", strings.Join(casTools, ", "), err)
	}
	paths := strings.Fields(string(out))
	if len(paths) != len(casTools) {
		return "", fmt.Errorf("fakesrv: пути утилит: %q", out)
	}
	shim := filepath.Join(tmp, "shim")
	if err := os.Mkdir(shim, 0o700); err != nil {
		return "", fmt.Errorf("fakesrv: %w", err)
	}
	for i, tool := range casTools {
		if tool == s.MissingTool {
			continue
		}
		body := "#!/bin/sh\n"
		switch {
		case tool == s.FailTool:
			body += "echo \"" + tool + ": имитированный отказ\" >&2\nexit 1\n"
		case tool == "mv" && s.FailMvTo != "":
			body += "for a; do last=$a; done\ncase \"$last\" in */" + s.FailMvTo +
				") echo \"mv: cannot move to $last: Permission denied\" >&2; exit 1;; esac\n"
			body += "exec \"" + paths[i] + "\" \"$@\"\n"
		default:
			body += "exec \"" + paths[i] + "\" \"$@\"\n"
		}
		if err := os.WriteFile(filepath.Join(shim, tool), []byte(body), 0o700); err != nil {
			return "", fmt.Errorf("fakesrv: %w", err)
		}
	}
	return shim, nil
}
