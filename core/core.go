// Package core — логика администрирования сервера Amnezia VPN:
// декодирование ключа vpn://, SSH, контейнеры, пользователи WireGuard/AmneziaWG.
// UI (CLI и GUI) живёт в cmd/.
package core

import (
	"bytes"
	"compress/zlib"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/skip2/go-qrcode"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/ssh"
)

// ---------- декодирование ключа vpn:// ----------

func DecodeVpnKey(key string) (map[string]any, error) {
	s := strings.TrimSpace(key)
	s = strings.TrimPrefix(s, "vpn://")

	var raw []byte
	var err error
	for _, enc := range []*base64.Encoding{
		base64.RawURLEncoding, base64.URLEncoding, base64.RawStdEncoding, base64.StdEncoding,
	} {
		raw, err = enc.DecodeString(s)
		if err == nil {
			break
		}
	}
	if err != nil {
		return nil, fmt.Errorf("не удалось декодировать base64: %w", err)
	}

	// Вариант 1: qCompress — 4 байта big-endian длины + zlib-поток
	if len(raw) > 4 {
		_ = binary.BigEndian.Uint32(raw[:4])
		if data, e := zlibDecompress(raw[4:]); e == nil {
			return parseJSON(data)
		}
	}
	// Вариант 2: просто zlib
	if data, e := zlibDecompress(raw); e == nil {
		return parseJSON(data)
	}
	// Вариант 3: JSON без сжатия
	return parseJSON(raw)
}

func zlibDecompress(raw []byte) ([]byte, error) {
	r, err := zlib.NewReader(bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	defer r.Close()
	return io.ReadAll(r)
}

func parseJSON(data []byte) (map[string]any, error) {
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("внутри ключа не JSON: %w", err)
	}
	return m, nil
}

// Str достаёт строковое значение по первому найденному ключу
func Str(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if v, ok := m[k]; ok {
			switch t := v.(type) {
			case string:
				return t
			case float64:
				return strconv.Itoa(int(t))
			}
		}
	}
	return ""
}

// ---------- SSH ----------

type ServerCreds struct {
	Host, User, Password string
	Port                 string
}

func CredsFromConfig(cfg map[string]any) (*ServerCreds, error) {
	c := &ServerCreds{
		Host:     Str(cfg, "hostName"),
		User:     Str(cfg, "userName"),
		Password: Str(cfg, "password"),
		Port:     Str(cfg, "port"),
	}
	if c.Port == "" || c.Port == "0" {
		c.Port = "22"
	}
	if c.Host == "" || c.User == "" {
		return nil, fmt.Errorf("в ключе нет SSH-доступа (hostName/userName) — похоже, это пользовательский ключ, а не админский")
	}
	return c, nil
}

// Session — установленное SSH-подключение к серверу Amnezia
type Session struct {
	Client *ssh.Client
	Creds  *ServerCreds
}

func Connect(creds *ServerCreds) (*Session, error) {
	var auths []ssh.AuthMethod
	if strings.Contains(creds.Password, "PRIVATE KEY") {
		signer, err := ssh.ParsePrivateKey([]byte(creds.Password))
		if err != nil {
			return nil, fmt.Errorf("не удалось разобрать SSH-ключ из конфига: %w", err)
		}
		auths = append(auths, ssh.PublicKeys(signer))
	} else {
		auths = append(auths,
			ssh.Password(creds.Password),
			ssh.KeyboardInteractive(func(_, _ string, questions []string, _ []bool) ([]string, error) {
				ans := make([]string, len(questions))
				for i := range questions {
					ans[i] = creds.Password
				}
				return ans, nil
			}),
		)
	}
	conf := &ssh.ClientConfig{
		User:            creds.User,
		Auth:            auths,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         15 * time.Second,
	}
	client, err := ssh.Dial("tcp", net.JoinHostPort(creds.Host, creds.Port), conf)
	if err != nil {
		return nil, err
	}
	return &Session{Client: client, Creds: creds}, nil
}

func (s *Session) Close() {
	if s.Client != nil {
		s.Client.Close()
	}
}

func (s *Session) run(cmd string, stdin []byte) (string, error) {
	sess, err := s.Client.NewSession()
	if err != nil {
		return "", err
	}
	defer sess.Close()
	if stdin != nil {
		sess.Stdin = bytes.NewReader(stdin)
	}
	var out, errb bytes.Buffer
	sess.Stdout = &out
	sess.Stderr = &errb
	err = sess.Run(cmd)
	if err != nil {
		return out.String(), fmt.Errorf("команда %q: %w; stderr: %s", cmd, err, errb.String())
	}
	return out.String(), nil
}

// docker выполняет команду, при отказе прав пробует с sudo
func (s *Session) docker(cmd string, stdin []byte) (string, error) {
	out, err := s.run(cmd, stdin)
	if err != nil && strings.Contains(strings.ToLower(err.Error()), "denied") {
		return s.run("sudo "+cmd, stdin)
	}
	return out, err
}

// ---------- контейнеры Amnezia ----------

type Container struct {
	Name, Dir, Proto string
	Managed          bool // умеем ли управлять пользователями (WG-семейство)
}

var knownContainers = []Container{
	{"amnezia-awg", "/opt/amnezia/awg", "AmneziaWG", true},
	{"amnezia-wireguard", "/opt/amnezia/wireguard", "WireGuard", true},
	{"amnezia-xray", "/opt/amnezia/xray", "XRay", false},
	{"amnezia-openvpn", "/opt/amnezia/openvpn", "OpenVPN", false},
	{"amnezia-shadowsocks", "/opt/amnezia/shadowsocks", "OpenVPN+ShadowSocks", false},
	{"amnezia-openvpn-cloak", "/opt/amnezia/openvpn-cloak", "OpenVPN+Cloak", false},
	{"amnezia-ikev2", "/opt/amnezia/ikev2", "IKEv2", false},
	{"amnezia-sftp", "/opt/amnezia/sftp", "SFTP", false},
	{"amnezia-tor", "/opt/amnezia/tor", "Tor site", false},
	{"amnezia-dns", "/opt/amnezia/dns", "DNS", false},
}

func (s *Session) FindContainers() ([]Container, error) {
	out, err := s.docker("docker ps --format '{{.Names}}'", nil)
	if err != nil {
		return nil, fmt.Errorf("docker ps: %w", err)
	}
	names := strings.Fields(out)
	var found []Container
	for _, n := range names {
		matched := false
		for _, kc := range knownContainers {
			if n == kc.Name {
				found = append(found, kc)
				matched = true
				break
			}
		}
		if !matched && strings.HasPrefix(n, "amnezia-") {
			suffix := strings.TrimPrefix(n, "amnezia-")
			// неизвестные контейнеры WG-семейства (awg2, wireguard2 и т.п.) тоже управляемы
			managed := strings.HasPrefix(suffix, "awg") || strings.HasPrefix(suffix, "wireguard")
			found = append(found, Container{Name: n, Dir: "/opt/amnezia/" + suffix, Proto: suffix, Managed: managed})
		}
	}
	if len(found) == 0 {
		return nil, fmt.Errorf("контейнеры Amnezia на сервере не найдены; запущено: %s", strings.Join(names, ", "))
	}
	return found, nil
}

func (s *Session) catIn(c *Container, path string) (string, error) {
	return s.docker(fmt.Sprintf("docker exec %s cat %s", c.Name, path), nil)
}

// writeIn пишет файл атомарно: во временный файл, затем rename поверх целевого
func (s *Session) writeIn(c *Container, path string, data []byte) error {
	_, err := s.docker(fmt.Sprintf("docker exec -i %s sh -c 'cat > %s.tmp && mv %s.tmp %s'", c.Name, path, path, path), data)
	return err
}

// backup делает резервную копию wg0.conf и clientsTable перед мутацией,
// ротируя старые копии РАЗДЕЛЬНО по каждому префиксу — хранится по 20
// последних файлов wg0.conf.* и 20 последних clientsTable.* (а не 20
// суммарно). Копирование wg0.conf — обязательное условие (fail-closed):
// если его не удалось скопировать, вся операция бэкапа считается
// провалившейся. clientsTable может отсутствовать (например, до первого
// пользователя) — для неё отсутствие файла не является ошибкой.
func (s *Session) backup(c *Container) error {
	cmd := fmt.Sprintf(
		"docker exec %s sh -c 'mkdir -p %s/backup && ts=$(date +%%Y%%m%%d-%%H%%M%%S) && "+
			"cp %s/wg0.conf %s/backup/wg0.conf.$ts && "+
			"(cp %s/clientsTable %s/backup/clientsTable.$ts 2>/dev/null; "+
			"ls -1t %s/backup/wg0.conf.* 2>/dev/null | tail -n +21 | while read f; do rm -f \"$f\"; done; "+
			"ls -1t %s/backup/clientsTable.* 2>/dev/null | tail -n +21 | while read f; do rm -f \"$f\"; done)'",
		c.Name, c.Dir, c.Dir, c.Dir, c.Dir, c.Dir, c.Dir, c.Dir)
	if _, err := s.docker(cmd, nil); err != nil {
		return fmt.Errorf("не удалось создать резервную копию: %w", err)
	}
	return nil
}

// ---------- clientsTable ----------

type ClientEntry struct {
	ClientID string         `json:"clientId"`
	UserData map[string]any `json:"userData"`
}

func (e ClientEntry) Name() string    { return Str(e.UserData, "clientName") }
func (e ClientEntry) Created() string { return Str(e.UserData, "creationDate") }

// Disabled — временно отключён (SetEnabled(c, id, false)). Хранится как
// UserData["disabled"] = true; отсутствие поля или false означает "активен".
// Это наше совместимое расширение clientsTable — клиент Amnezia лишние поля
// в userData сохраняет и игнорирует.
func (e ClientEntry) Disabled() bool {
	v, ok := e.UserData["disabled"]
	if !ok {
		return false
	}
	b, _ := v.(bool)
	return b
}

func (s *Session) LoadClients(c *Container) ([]ClientEntry, error) {
	out, err := s.catIn(c, c.Dir+"/clientsTable")
	if err != nil || strings.TrimSpace(out) == "" {
		return []ClientEntry{}, nil // таблицы может не быть — это не ошибка
	}
	var list []ClientEntry
	if err := json.Unmarshal([]byte(out), &list); err != nil {
		return nil, fmt.Errorf("clientsTable повреждена: %w", err)
	}
	return list, nil
}

func (s *Session) saveClients(c *Container, list []ClientEntry) error {
	tbl, _ := json.MarshalIndent(list, "", "    ")
	return s.writeIn(c, c.Dir+"/clientsTable", tbl)
}

// PeerStat — статистика по одному peer'у из `wg show wg0 dump`
type PeerStat struct {
	LastHandshake time.Time // нулевое время = подключений не было
	RxBytes       int64
	TxBytes       int64
}

// parsePeerStats разбирает вывод `wg show wg0 dump`: первая строка — интерфейс
// (пропускается), остальные — peer'ы, поля разделены табами. Endpoint может
// быть "(none)", поэтому strings.Fields недопустим — только split по "\t".
func parsePeerStats(out string) map[string]PeerStat {
	stats := map[string]PeerStat{}
	lines := strings.Split(out, "\n")
	for i, line := range lines {
		if i == 0 {
			continue // строка интерфейса
		}
		line = strings.TrimRight(line, "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		f := strings.Split(line, "\t")
		if len(f) < 8 {
			continue
		}
		pub := f[0]
		hs, _ := strconv.ParseInt(f[4], 10, 64)
		rx, _ := strconv.ParseInt(f[5], 10, 64)
		tx, _ := strconv.ParseInt(f[6], 10, 64)
		var t time.Time
		if hs > 0 {
			t = time.Unix(hs, 0)
		}
		stats[pub] = PeerStat{LastHandshake: t, RxBytes: rx, TxBytes: tx}
	}
	return stats
}

// GetPeerStats возвращает статистику по каждому peer'у (handshake, трафик)
func (s *Session) GetPeerStats(c *Container) (map[string]PeerStat, error) {
	out, err := s.docker(fmt.Sprintf("docker exec %s wg show wg0 dump", c.Name), nil)
	if err != nil {
		return nil, fmt.Errorf("wg show wg0 dump: %w", err)
	}
	return parsePeerStats(out), nil
}

// GetHandshakes возвращает время последнего handshake по каждому публичному ключу
// ("—" — подключений не было); обёртка над GetPeerStats для обратной совместимости
func (s *Session) GetHandshakes(c *Container) map[string]string {
	handshakes := map[string]string{}
	stats, err := s.GetPeerStats(c)
	if err != nil {
		return handshakes
	}
	for pub, st := range stats {
		if st.LastHandshake.IsZero() {
			handshakes[pub] = "—"
		} else {
			handshakes[pub] = st.LastHandshake.Format("2006-01-02 15:04")
		}
	}
	return handshakes
}

// HumanBytes форматирует размер в человекочитаемый вид (десятичные единицы, 1000)
func HumanBytes(n int64) string {
	const unit = 1000.0
	if n < 1000 {
		return fmt.Sprintf("%d B", n)
	}
	v := float64(n)
	units := []string{"KB", "MB", "GB", "TB"}
	i := -1
	for v >= unit && i < len(units)-1 {
		v /= unit
		i++
	}
	return fmt.Sprintf("%.1f %s", v, units[i])
}

// ValidateName проверяет имя пользователя: не пустое, не длиннее 64 рун,
// без управляющих символов и без символов, опасных рядом с JSON/shell.
func ValidateName(name string) error {
	n := strings.TrimSpace(name)
	if n == "" {
		return fmt.Errorf("имя пользователя не может быть пустым")
	}
	if len([]rune(n)) > 64 {
		return fmt.Errorf("имя пользователя слишком длинное (максимум 64 символа)")
	}
	const forbidden = `'"` + "`" + `\$;|&<>`
	for _, r := range n {
		if unicode.IsControl(r) {
			return fmt.Errorf("имя пользователя содержит недопустимый управляющий символ")
		}
		if strings.ContainsRune(forbidden, r) {
			return fmt.Errorf("имя пользователя содержит запрещённый символ %q", r)
		}
	}
	return nil
}

// ResolveClient ищет клиента по номеру в списке (с 1), имени или публичному ключу; -1 если не найден
func ResolveClient(clients []ClientEntry, ident string) int {
	if n, e := strconv.Atoi(strings.TrimSpace(ident)); e == nil && n >= 1 && n <= len(clients) {
		return n - 1
	}
	for i, cl := range clients {
		if cl.Name() == ident || cl.ClientID == ident {
			return i
		}
	}
	return -1
}

// ResolveNonNumeric резолвит идентификатора клиента ТОЛЬКО по имени или
// публичному ключу — числовой ident явно отклоняется с понятной ошибкой.
// Предназначен для non-interactive CLI-команд (del/rename/toggle), где нет
// напечатанного пронумерованного списка: там, откуда взято число, порядок
// LoadClients не совпадает с порядком, который видел пользователь
// (LoadClients не сортирован по активности, как отображаемая таблица), и
// резолв по номеру мог бы попасть не в того клиента (wrong-target).
func ResolveNonNumeric(clients []ClientEntry, ident string) (int, error) {
	if _, err := strconv.Atoi(strings.TrimSpace(ident)); err == nil {
		return -1, fmt.Errorf("укажите имя или публичный ключ — номера действительны только внутри интерактивного списка")
	}
	idx := ResolveClient(clients, ident)
	if idx < 0 {
		return -1, fmt.Errorf("пользователь %q не найден (укажите имя или публичный ключ)", ident)
	}
	return idx, nil
}

// SortByActivity сортирует клиентов по активности: недавний LastHandshake —
// первым (по убыванию); клиенты без единого подключения — в конце, среди
// них порядок по дате создания (Created). Сортировка стабильна и выполняется
// на месте (in place). stats — карта ClientID → PeerStat (как из GetPeerStats).
func SortByActivity(clients []ClientEntry, stats map[string]PeerStat) {
	sort.SliceStable(clients, func(i, j int) bool {
		hi, hj := stats[clients[i].ClientID].LastHandshake, stats[clients[j].ClientID].LastHandshake
		if hi.IsZero() && hj.IsZero() {
			return clients[i].Created() < clients[j].Created()
		}
		if hi.IsZero() {
			return false
		}
		if hj.IsZero() {
			return true
		}
		return hi.After(hj)
	})
}

// OrphanPeers — публичные ключи peer'ов из wg0.conf, отсутствующие в clientsTable
func (s *Session) OrphanPeers(c *Container, clients []ClientEntry) []string {
	raw, err := s.catIn(c, c.Dir+"/wg0.conf")
	if err != nil {
		return nil
	}
	known := map[string]bool{}
	for _, cl := range clients {
		known[cl.ClientID] = true
	}
	var orphans []string
	for _, p := range parseWgConf(raw).peers {
		if pk := p["PublicKey"]; pk != "" && !known[pk] {
			orphans = append(orphans, pk)
		}
	}
	return orphans
}

// ---------- wg0.conf ----------

type wgConf struct {
	iface map[string]string
	peers []map[string]string
}

func parseWgConf(text string) *wgConf {
	conf := &wgConf{iface: map[string]string{}}
	var cur map[string]string
	for _, line := range strings.Split(text, "\n") {
		l := strings.TrimSpace(line)
		switch {
		case strings.EqualFold(l, "[Interface]"):
			cur = conf.iface
		case strings.EqualFold(l, "[Peer]"):
			cur = map[string]string{}
			conf.peers = append(conf.peers, cur)
		case strings.Contains(l, "=") && cur != nil && !strings.HasPrefix(l, "#"):
			kv := strings.SplitN(l, "=", 2)
			cur[strings.TrimSpace(kv[0])] = strings.TrimSpace(kv[1])
		}
	}
	return conf
}

// removePeerFromConf удаляет блок [Peer] с указанным PublicKey из текста конфига
func removePeerFromConf(text, pubKey string) string {
	lines := strings.Split(text, "\n")
	var out []string
	i := 0
	for i < len(lines) {
		l := strings.TrimSpace(lines[i])
		if strings.EqualFold(l, "[Peer]") {
			j := i + 1
			hasKey := false
			for j < len(lines) {
				t := strings.TrimSpace(lines[j])
				if strings.HasPrefix(t, "[") {
					break
				}
				if strings.HasPrefix(t, "PublicKey") && strings.Contains(t, pubKey) {
					hasKey = true
				}
				j++
			}
			if hasKey {
				i = j
				continue
			}
			out = append(out, lines[i:j]...)
			i = j
			continue
		}
		out = append(out, lines[i])
		i++
	}
	res := strings.Join(out, "\n")
	res = regexp.MustCompile(`\n{3,}`).ReplaceAllString(res, "\n\n")
	return res
}

// ---------- крипто WireGuard ----------

func genKey() (priv, pub string, err error) {
	var p [32]byte
	if _, err = rand.Read(p[:]); err != nil {
		return
	}
	p[0] &= 248
	p[31] = (p[31] & 127) | 64
	pubBytes, err := curve25519.X25519(p[:], curve25519.Basepoint)
	if err != nil {
		return
	}
	return base64.StdEncoding.EncodeToString(p[:]), base64.StdEncoding.EncodeToString(pubBytes), nil
}

func genPSK() (string, error) {
	var k [32]byte
	if _, err := rand.Read(k[:]); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(k[:]), nil
}

func pubFromPriv(privB64 string) (string, error) {
	priv, err := base64.StdEncoding.DecodeString(strings.TrimSpace(privB64))
	if err != nil || len(priv) != 32 {
		return "", fmt.Errorf("некорректный приватный ключ сервера")
	}
	pub, err := curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(pub), nil
}

// ---------- операции ----------

func (s *Session) syncWg(c *Container) error {
	_, err := s.docker(
		fmt.Sprintf("docker exec %s bash -c 'wg syncconf wg0 <(wg-quick strip %s/wg0.conf)'", c.Name, c.Dir), nil)
	return err
}

var ipRe = regexp.MustCompile(`(\d+\.\d+\.\d+)\.(\d+)`)

// buildPeerBlock собирает текст блока [Peer] для wg0.conf. allowedIPs
// передаётся уже полностью сформированным (например "10.8.1.5/32") —
// функция ничего не достраивает, только форматирует. Чистая функция,
// используется и в AddUser, и в SetEnabled(enabled=true) при восстановлении
// ранее отключённого peer'а с теми же ключом/IP.
func buildPeerBlock(pubKey, presharedKey, allowedIPs string) string {
	return fmt.Sprintf("\n[Peer]\nPublicKey = %s\nPresharedKey = %s\nAllowedIPs = %s\n", pubKey, presharedKey, allowedIPs)
}

// NewUser — результат создания пользователя
type NewUser struct {
	Name   string
	IP     string
	Config string // готовый клиентский .conf (WireGuard/AmneziaWG)
}

// AddUser создаёт пользователя: peer в wg0.conf, запись в clientsTable, wg syncconf.
// Возвращает клиентский конфиг; сохранение в файл — забота вызывающего.
func (s *Session) AddUser(c *Container, name string) (*NewUser, error) {
	if !c.Managed {
		return nil, fmt.Errorf("создание пользователей для %s не поддерживается этой утилитой", c.Proto)
	}
	if err := ValidateName(name); err != nil {
		return nil, err
	}
	name = strings.TrimSpace(name)
	existing, err := s.LoadClients(c)
	if err != nil {
		return nil, err
	}
	for _, cl := range existing {
		if cl.Name() == name {
			return nil, fmt.Errorf("пользователь с именем %q уже существует", name)
		}
	}
	if err := s.backup(c); err != nil {
		return nil, err
	}
	raw, err := s.catIn(c, c.Dir+"/wg0.conf")
	if err != nil {
		return nil, fmt.Errorf("чтение wg0.conf: %w", err)
	}
	conf := parseWgConf(raw)

	serverPriv := conf.iface["PrivateKey"]
	if serverPriv == "" {
		return nil, fmt.Errorf("в wg0.conf нет PrivateKey сервера")
	}
	serverPub, err := pubFromPriv(serverPriv)
	if err != nil {
		return nil, err
	}
	listenPort := conf.iface["ListenPort"]
	if listenPort == "" {
		listenPort = "51820"
	}

	// подсеть и следующий свободный IP
	subnet := ""
	used := map[int]bool{}
	if m := ipRe.FindStringSubmatch(conf.iface["Address"]); m != nil {
		subnet = m[1]
		n, _ := strconv.Atoi(m[2])
		used[n] = true
	}
	for _, p := range conf.peers {
		if m := ipRe.FindStringSubmatch(p["AllowedIPs"]); m != nil {
			if subnet == "" {
				subnet = m[1]
			}
			n, _ := strconv.Atoi(m[2])
			used[n] = true
		}
	}
	if subnet == "" {
		subnet = "10.8.1"
		used[1] = true
	}
	next := 2
	for used[next] {
		next++
	}
	if next > 254 {
		return nil, fmt.Errorf("свободных адресов в подсети %s.0/24 не осталось", subnet)
	}
	clientIP := fmt.Sprintf("%s.%d", subnet, next)

	priv, pub, err := genKey()
	if err != nil {
		return nil, err
	}
	psk, err := genPSK()
	if err != nil {
		return nil, err
	}

	// 1) peer в wg0.conf — читаем текущий конфиг и пишем атомарно (read+writeIn),
	// без "cat >>" (не атомарно и не защищено от гонок/обрыва на середине)
	peerBlock := buildPeerBlock(pub, psk, clientIP+"/32")
	if err := s.writeIn(c, c.Dir+"/wg0.conf", []byte(raw+peerBlock)); err != nil {
		return nil, fmt.Errorf("запись peer в wg0.conf: %w", err)
	}

	// 2) clientsTable
	clients := append(existing, ClientEntry{
		ClientID: pub,
		UserData: map[string]any{
			"clientName":   name,
			"creationDate": time.Now().Format(time.RFC3339),
		},
	})
	if err := s.saveClients(c, clients); err != nil {
		return nil, fmt.Errorf("запись clientsTable: %w", err)
	}

	// 3) применить без разрыва соединений
	if err := s.syncWg(c); err != nil {
		return nil, fmt.Errorf("wg syncconf: %w (peer записан в конфиг, но не применён)", err)
	}

	// 4) клиентский конфиг
	config := buildClientConfigText(conf, serverPub, s.Creds.Host, listenPort, priv, psk, clientIP)
	return &NewUser{Name: name, IP: clientIP, Config: config}, nil
}

// buildClientConfigText собирает текст готового клиентского .conf
// (WireGuard/AmneziaWG), включая junk-параметры AmneziaWG (Jc/Jmin/.../H4)
// из серверного wg0.conf, если они там есть. Общий helper для AddUser и
// RegenerateUser — чтобы не дублировать сборку конфига.
func buildClientConfigText(conf *wgConf, serverPub, host, listenPort, clientPriv, psk, clientIP string) string {
	var junk []string
	for _, k := range []string{"Jc", "Jmin", "Jmax", "S1", "S2", "H1", "H2", "H3", "H4"} {
		if v, ok := conf.iface[k]; ok {
			junk = append(junk, fmt.Sprintf("%s = %s", k, v))
		}
	}
	var b strings.Builder
	fmt.Fprintf(&b, "[Interface]\nPrivateKey = %s\nAddress = %s/32\nDNS = 1.1.1.1, 1.0.0.1\n", clientPriv, clientIP)
	if len(junk) > 0 {
		b.WriteString(strings.Join(junk, "\n") + "\n")
	}
	fmt.Fprintf(&b, "\n[Peer]\nPublicKey = %s\nPresharedKey = %s\nAllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = %s:%s\nPersistentKeepalive = 25\n",
		serverPub, psk, host, listenPort)
	return b.String()
}

// filterClientsByID удаляет из списка запись с указанным ClientID (pubkey),
// сохраняя исходный порядок остальных. Возвращает новый список и признак,
// была ли запись найдена и удалена. Чистая функция — используется и в
// DeleteByID, и в тестах.
func filterClientsByID(clients []ClientEntry, clientID string) ([]ClientEntry, bool) {
	out := make([]ClientEntry, 0, len(clients))
	found := false
	for _, cl := range clients {
		if cl.ClientID == clientID {
			found = true
			continue
		}
		out = append(out, cl)
	}
	return out, found
}

// DeleteByID удаляет клиента по каноническому идентификатору — публичному
// ключу (ClientID). Номер строки в отрисованном списке — лишь презентационный
// алиас и не годится в качестве ключа удаления (сортировка/гонки могут
// сместить индексы), поэтому единственный вход — ClientID.
func (s *Session) DeleteByID(c *Container, clientID string) error {
	if !c.Managed {
		return fmt.Errorf("удаление пользователей для %s не поддерживается этой утилитой", c.Proto)
	}
	clients, err := s.LoadClients(c)
	if err != nil {
		return err
	}
	newClients, found := filterClientsByID(clients, clientID)
	if !found {
		return fmt.Errorf("клиент с ключом %q не найден", clientID)
	}

	if err := s.backup(c); err != nil {
		return err
	}

	raw, err := s.catIn(c, c.Dir+"/wg0.conf")
	if err != nil {
		return fmt.Errorf("чтение wg0.conf: %w", err)
	}
	newConf := removePeerFromConf(raw, clientID)
	if err := s.writeIn(c, c.Dir+"/wg0.conf", []byte(newConf)); err != nil {
		return fmt.Errorf("запись wg0.conf: %w", err)
	}

	if err := s.saveClients(c, newClients); err != nil {
		return fmt.Errorf("запись clientsTable: %w", err)
	}

	if err := s.syncWg(c); err != nil {
		return fmt.Errorf("wg syncconf: %w", err)
	}
	return nil
}

// rekeyClientInList — чистая часть RegenerateUser: находит запись по старому
// ClientID и заменяет её НА МЕСТЕ (порядок остальных записей не меняется) на
// запись с новым ClientID. clientName и creationDate берутся из старой записи
// как есть (сохраняются); disable-связанные поля (disabled/disabledAt/psk/
// allowedIP) отбрасываются — новый peer уже активен и восстановление старого
// отключённого состояния не имеет смысла после re-key. Добавляется
// UserData["rekeyedAt"] с текущим временем.
func rekeyClientInList(clients []ClientEntry, oldID, newID string) ([]ClientEntry, error) {
	idx := -1
	for i, cl := range clients {
		if cl.ClientID == oldID {
			idx = i
			break
		}
	}
	if idx < 0 {
		return nil, fmt.Errorf("клиент с ключом %q не найден", oldID)
	}
	out := make([]ClientEntry, len(clients))
	copy(out, clients)
	ud := make(map[string]any, len(out[idx].UserData)+1)
	for k, v := range out[idx].UserData {
		if k == "disabled" || k == "disabledAt" || k == "psk" || k == "allowedIP" {
			continue
		}
		ud[k] = v
	}
	ud["rekeyedAt"] = time.Now().Format(time.RFC3339)
	out[idx] = ClientEntry{ClientID: newID, UserData: ud}
	return out, nil
}

// RegenerateUser перевыпускает конфиг клиента: генерирует новую пару ключей
// и новый preshared key, сохраняя имя и (по возможности) IP-адрес. Сервер не
// хранит приватный ключ клиента, поэтому "показать старый конфиг" невозможно
// в принципе — единственный способ восстановить доступ при потере .conf это
// re-key. СТАРЫЙ КОНФИГ ПОСЛЕ ЭТОГО ПЕРЕСТАЁТ РАБОТАТЬ (отзыв старого
// доступа) — это ожидаемое поведение (by design), а не побочный эффект.
func (s *Session) RegenerateUser(c *Container, clientID string) (*NewUser, error) {
	if !c.Managed {
		return nil, fmt.Errorf("перевыпуск конфигов для %s не поддерживается этой утилитой", c.Proto)
	}
	clients, err := s.LoadClients(c)
	if err != nil {
		return nil, err
	}
	var name string
	found := false
	for _, cl := range clients {
		if cl.ClientID == clientID {
			name = cl.Name()
			found = true
			break
		}
	}
	if !found {
		return nil, fmt.Errorf("клиент с ключом %q не найден", clientID)
	}

	if err := s.backup(c); err != nil {
		return nil, err
	}

	raw, err := s.catIn(c, c.Dir+"/wg0.conf")
	if err != nil {
		return nil, fmt.Errorf("чтение wg0.conf: %w", err)
	}
	conf := parseWgConf(raw)

	serverPriv := conf.iface["PrivateKey"]
	if serverPriv == "" {
		return nil, fmt.Errorf("в wg0.conf нет PrivateKey сервера")
	}
	serverPub, err := pubFromPriv(serverPriv)
	if err != nil {
		return nil, err
	}
	listenPort := conf.iface["ListenPort"]
	if listenPort == "" {
		listenPort = "51820"
	}

	// сохраняем прежний IP, если peer ещё в wg0.conf (например, не был отключён);
	// иначе (peer уже отсутствует — клиент был Disabled) выделяем свободный IP,
	// как в AddUser
	clientIP := ""
	for _, p := range conf.peers {
		if p["PublicKey"] == clientID {
			if m := ipRe.FindStringSubmatch(p["AllowedIPs"]); m != nil {
				clientIP = fmt.Sprintf("%s.%s", m[1], m[2])
			}
			break
		}
	}
	if clientIP == "" {
		subnet := ""
		used := map[int]bool{}
		if m := ipRe.FindStringSubmatch(conf.iface["Address"]); m != nil {
			subnet = m[1]
			n, _ := strconv.Atoi(m[2])
			used[n] = true
		}
		for _, p := range conf.peers {
			if m := ipRe.FindStringSubmatch(p["AllowedIPs"]); m != nil {
				if subnet == "" {
					subnet = m[1]
				}
				n, _ := strconv.Atoi(m[2])
				used[n] = true
			}
		}
		if subnet == "" {
			subnet = "10.8.1"
			used[1] = true
		}
		next := 2
		for used[next] {
			next++
		}
		if next > 254 {
			return nil, fmt.Errorf("свободных адресов в подсети %s.0/24 не осталось", subnet)
		}
		clientIP = fmt.Sprintf("%s.%d", subnet, next)
	}

	priv, pub, err := genKey()
	if err != nil {
		return nil, err
	}
	psk, err := genPSK()
	if err != nil {
		return nil, err
	}

	// wg0.conf: убрать старый peer (если был) и добавить новый с тем же IP —
	// порядок "сначала новый, потом старый" не нужен, это тот же пользователь
	newConfText := removePeerFromConf(raw, clientID) + buildPeerBlock(pub, psk, clientIP+"/32")
	if err := s.writeIn(c, c.Dir+"/wg0.conf", []byte(newConfText)); err != nil {
		return nil, fmt.Errorf("запись wg0.conf: %w", err)
	}

	newClients, err := rekeyClientInList(clients, clientID, pub)
	if err != nil {
		return nil, err // не должно случиться — clientID уже найден выше
	}
	if err := s.saveClients(c, newClients); err != nil {
		return nil, fmt.Errorf("запись clientsTable: %w", err)
	}

	if err := s.syncWg(c); err != nil {
		return nil, fmt.Errorf("wg syncconf: %w", err)
	}

	config := buildClientConfigText(conf, serverPub, s.Creds.Host, listenPort, priv, psk, clientIP)
	return &NewUser{Name: name, IP: clientIP, Config: config}, nil
}

// renameClientInList — чистая часть RenameUser: находит клиента по ClientID,
// проверяет дубль имени среди остальных и возвращает новый slice с обновлённым
// UserData["clientName"] (порядок и остальные записи не меняются, исходный
// slice не мутируется — под записью с найденным индексом кладётся новый
// UserData с скопированными полями).
func renameClientInList(clients []ClientEntry, clientID, newName string) ([]ClientEntry, error) {
	newName = strings.TrimSpace(newName)
	if err := ValidateName(newName); err != nil {
		return nil, err
	}
	idx := -1
	for i, cl := range clients {
		if cl.ClientID == clientID {
			idx = i
			break
		}
	}
	if idx < 0 {
		return nil, fmt.Errorf("клиент с ключом %q не найден", clientID)
	}
	for i, cl := range clients {
		if i != idx && cl.Name() == newName {
			return nil, fmt.Errorf("пользователь с именем %q уже существует", newName)
		}
	}
	out := make([]ClientEntry, len(clients))
	copy(out, clients)
	ud := make(map[string]any, len(out[idx].UserData)+1)
	for k, v := range out[idx].UserData {
		ud[k] = v
	}
	ud["clientName"] = newName
	out[idx].UserData = ud
	return out, nil
}

// RenameUser переименовывает клиента по ClientID (pubkey). wg0.conf не
// трогается и wg syncconf не вызывается — ключи и IP не меняются, значит
// соединение не рвётся.
func (s *Session) RenameUser(c *Container, clientID, newName string) error {
	if !c.Managed {
		return fmt.Errorf("переименование пользователей для %s не поддерживается этой утилитой", c.Proto)
	}
	clients, err := s.LoadClients(c)
	if err != nil {
		return err
	}
	newClients, err := renameClientInList(clients, clientID, newName)
	if err != nil {
		return err
	}
	if err := s.backup(c); err != nil {
		return err
	}
	if err := s.saveClients(c, newClients); err != nil {
		return fmt.Errorf("запись clientsTable: %w", err)
	}
	return nil
}

// SetEnabled временно отключает клиента (enabled=false) или включает обратно
// (enabled=true) без удаления записи из clientsTable.
//
// Отключение: peer убирается из wg0.conf и рантайма (wg syncconf), а
// PresharedKey и AllowedIPs сохраняются в UserData (["psk"], ["allowedIP"]),
// чтобы включение могло восстановить точно тот же блок [Peer]. Флаг
// UserData["disabled"]=true и UserData["disabledAt"] пишутся в clientsTable
// после удаления peer из wg0.conf, но до syncconf — если syncconf упадёт,
// запись уже помечена отключённой (безопасная сторона: пользователь считается
// отключённым, даже если фактически ещё активен до следующего syncconf).
//
// Включение: блок [Peer] восстанавливается из сохранённых psk/allowedIP,
// затем снимается флаг disabled и вызывается syncconf.
func (s *Session) SetEnabled(c *Container, clientID string, enabled bool) error {
	if !c.Managed {
		return fmt.Errorf("управление пользователями для %s не поддерживается этой утилитой", c.Proto)
	}
	if enabled {
		return s.enableClient(c, clientID)
	}
	return s.disableClient(c, clientID)
}

func (s *Session) disableClient(c *Container, clientID string) error {
	clients, err := s.LoadClients(c)
	if err != nil {
		return err
	}
	idx := -1
	for i, cl := range clients {
		if cl.ClientID == clientID {
			idx = i
			break
		}
	}
	if idx < 0 {
		return fmt.Errorf("клиент с ключом %q не найден", clientID)
	}
	if clients[idx].Disabled() {
		return fmt.Errorf("пользователь %q уже отключён", clients[idx].Name())
	}

	if err := s.backup(c); err != nil {
		return err
	}

	raw, err := s.catIn(c, c.Dir+"/wg0.conf")
	if err != nil {
		return fmt.Errorf("чтение wg0.conf: %w", err)
	}
	conf := parseWgConf(raw)
	var peer map[string]string
	for _, p := range conf.peers {
		if p["PublicKey"] == clientID {
			peer = p
			break
		}
	}
	if peer == nil {
		return fmt.Errorf("peer с ключом %q не найден в wg0.conf", clientID)
	}

	newConf := removePeerFromConf(raw, clientID)
	if err := s.writeIn(c, c.Dir+"/wg0.conf", []byte(newConf)); err != nil {
		return fmt.Errorf("запись wg0.conf: %w", err)
	}

	newClients := make([]ClientEntry, len(clients))
	copy(newClients, clients)
	ud := make(map[string]any, len(newClients[idx].UserData)+4)
	for k, v := range newClients[idx].UserData {
		ud[k] = v
	}
	ud["disabled"] = true
	ud["disabledAt"] = time.Now().Format(time.RFC3339)
	ud["psk"] = peer["PresharedKey"]
	ud["allowedIP"] = peer["AllowedIPs"]
	newClients[idx].UserData = ud
	if err := s.saveClients(c, newClients); err != nil {
		return fmt.Errorf("запись clientsTable: %w", err)
	}

	if err := s.syncWg(c); err != nil {
		return fmt.Errorf("wg syncconf: %w (пользователь уже помечен отключённым)", err)
	}
	return nil
}

func (s *Session) enableClient(c *Container, clientID string) error {
	clients, err := s.LoadClients(c)
	if err != nil {
		return err
	}
	idx := -1
	for i, cl := range clients {
		if cl.ClientID == clientID {
			idx = i
			break
		}
	}
	if idx < 0 {
		return fmt.Errorf("клиент с ключом %q не найден", clientID)
	}
	if !clients[idx].Disabled() {
		return fmt.Errorf("пользователь %q уже активен", clients[idx].Name())
	}
	psk := Str(clients[idx].UserData, "psk")
	allowedIP := Str(clients[idx].UserData, "allowedIP")
	if psk == "" || allowedIP == "" {
		return fmt.Errorf("невозможно включить: параметры peer не сохранены, пересоздайте пользователя")
	}

	if err := s.backup(c); err != nil {
		return err
	}

	raw, err := s.catIn(c, c.Dir+"/wg0.conf")
	if err != nil {
		return fmt.Errorf("чтение wg0.conf: %w", err)
	}
	block := buildPeerBlock(clientID, psk, allowedIP)
	if err := s.writeIn(c, c.Dir+"/wg0.conf", []byte(raw+block)); err != nil {
		return fmt.Errorf("запись wg0.conf: %w", err)
	}

	newClients := make([]ClientEntry, len(clients))
	copy(newClients, clients)
	ud := make(map[string]any, len(newClients[idx].UserData))
	for k, v := range newClients[idx].UserData {
		if k == "disabled" || k == "disabledAt" || k == "psk" || k == "allowedIP" {
			continue // peer восстановлен — лишняя копия psk/IP в clientsTable больше не нужна
		}
		ud[k] = v
	}
	newClients[idx].UserData = ud
	if err := s.saveClients(c, newClients); err != nil {
		return fmt.Errorf("запись clientsTable: %w", err)
	}

	if err := s.syncWg(c); err != nil {
		return fmt.Errorf("wg syncconf: %w", err)
	}
	return nil
}

// SanitizeName убирает символы, запрещённые в именах файлов Windows,
// сохраняя пробелы и кириллицу ("Иванов Иван" → "Иванов Иван")
var nameRe = regexp.MustCompile(`[\\/:*?"<>|]+`)

func SanitizeName(s string) string {
	s = strings.TrimSpace(nameRe.ReplaceAllString(strings.TrimSpace(s), "_"))
	if s == "" {
		s = "client"
	}
	return s
}

// ---------- QR ----------

// QRPNG кодирует text в QR-код и возвращает PNG-байты размером size×size px.
// Используется в GUI, чтобы клиент мог отсканировать конфиг приложением
// AmneziaWG на телефоне, не передавая файл.
func QRPNG(text string, size int) ([]byte, error) {
	png, err := qrcode.Encode(text, qrcode.Medium, size)
	if err != nil {
		return nil, fmt.Errorf("генерация QR-кода: %w", err)
	}
	return png, nil
}
