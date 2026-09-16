// Package fakesrv — сервер Amnezia в памяти для юнит-тестов пакета core: без
// сети, без диска (кроме собственной map в памяти) и без реального SSH. core
// подменяет транспорт через структурный интерфейс core.Runner (метод
// Run(cmd string, stdin []byte) (string, error)) — Server реализует этот же
// метод, но НАМЕРЕННО НЕ импортирует core, иначе тесты пакета core (которые
// импортируют fakesrv) замкнулись бы в цикл импорта.
//
// Server разбирает РОВНО те серверные команды, что на 2026-09-14 шлёт core
// (docker ps/exec, резервное копирование, wg syncconf/show, sudo-фолбэк,
// test -f) — и только их. Любая другая команда возвращает ошибку "неизвестная
// команда": это не удобство, а страж — если core когда-нибудь начнёт слать на
// сервер что-то новое или изменит текст существующей команды, тест на
// fakesrv тут же упадёт, а не тихо отработает "как-нибудь".
package fakesrv

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"regexp"
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

	// FailSyncconf — если задана, `wg syncconf` вернёт эту ошибку, а рантайм
	// (множество применённых peer'ов) не меняется.
	FailSyncconf error

	// DenyOnce — самая первая команда без префикса "sudo " будет отклонена
	// ошибкой со словом "denied" (проверка sudo-фолбэка в Session.docker).
	// Все последующие команды, включая повтор той же команды с "sudo ",
	// выполняются как обычно.
	DenyOnce bool

	mu           sync.Mutex
	files        map[string][]byte
	peers        map[string]bool // публичные ключи peer'ов, применённые последним syncconf
	commands     []string
	denyOnceUsed bool
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
	reWrite    = regexp.MustCompile(`^docker exec -i (\S+) sh -c 'cat > (\S+)\.tmp && mv (\S+)\.tmp (\S+)'$`)
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

	case reWrite.MatchString(cmd):
		m := reWrite.FindStringSubmatch(cmd)
		path := m[2]
		if m[3] != path || m[4] != path {
			return "", fmt.Errorf("fakesrv: неизвестная команда %q", cmd)
		}
		if s.files == nil {
			s.files = map[string][]byte{}
		}
		s.files[path] = append([]byte(nil), stdin...)
		return "", nil

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
		if s.FailSyncconf != nil {
			return "", s.FailSyncconf
		}
		wg0, ok := s.files[dir+"/wg0.conf"]
		if !ok {
			return "", fmt.Errorf("команда %q: exit status 1; stderr: wg-quick: %s/wg0.conf: No such file or directory", cmd, dir)
		}
		s.peers = peerKeysFromConf(string(wg0))
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
