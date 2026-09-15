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
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
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
	r      Runner // транспорт команд; см. core/runner.go

	// HostKeyFingerprint — отпечаток (SHA256:…) ключа хоста, принятого при
	// установлении ЭТОГО соединения (core/hostkey.go, PR-4). Пусто, если
	// Session собрана в обход ConnectWithHostKey (например,
	// NewSessionWithRunner в тестах).
	HostKeyFingerprint string

	// mu — мьютекс мутаций (I5, core/txn.go). Экспортированные Plan*/Apply
	// берут его сами; AddUser/DeleteByID/... держат его один раз на весь
	// plan→apply и внутри вызывают только *Locked-варианты — sync.Mutex не
	// реентерабелен, повторный Lock из-под уже взятого — deadlock.
	mu sync.Mutex
}

func (s *Session) Close() {
	if s.Client != nil {
		s.Client.Close()
	}
}

func (s *Session) run(cmd string, stdin []byte) (string, error) {
	return s.r.Run(cmd, stdin)
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
			// Неизвестный контейнер (в т.ч. amnezia-awg2 и подобные) — не наш
			// формат конфига (у awg2 файл называется awg0.conf, а не wg0.conf),
			// поэтому не управляем; раньше здесь угадывался Managed=true по
			// префиксу имени, из-за чего awg2 читался как "пустой сервер"
			// (аудит-2026-09-14, Backlog).
			found = append(found, Container{
				Name:    n,
				Dir:     "/opt/amnezia/" + suffix,
				Proto:   suffix + " (не поддерживается: другой формат конфига)",
				Managed: false,
			})
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

// LoadClients читает clientsTable. "Файла нет" и "не удалось прочитать" —
// разные исходы: отсутствие таблицы до первого пользователя — это нормально
// (пустой список, err == nil), а сбой чтения (нет прав, контейнер
// перезапускается и т.п.) обязан быть ошибкой, а не тихо превращаться в
// пустой список — иначе AddUser поверх такой ошибки сохранит таблицу из
// одной новой записи и сотрёт всех существующих пользователей (аудит
// 2026-09-14, Critical). Различаем через `test -f` + echo yes/no, а не по
// коду возврата `cat`: `test -f` даёт код 1 и при "нет файла", и при прочих
// отказах exec, а различить их по *ssh.ExitError фейковый сервер не сможет
// (поля Waitmsg не экспортированы) — текст в stdout одинаково даёт и
// реальный сервер, и фейк.
func (s *Session) LoadClients(c *Container) ([]ClientEntry, error) {
	data, existed, err := s.readClientsTableRaw(c) // core/txn.go — общее чтение для LoadClients и Plan*
	if err != nil {
		return nil, err
	}
	if !existed {
		return []ClientEntry{}, nil // таблицы ещё нет — до первого пользователя это нормально
	}
	return parseClientsTable(data) // пустой файл (например, после восстановления) — пустой список, не ошибка
}

// LoadClientsView — то же чтение clientsTable, что и LoadClients
// (readClientsTableRaw+parseClientsTable), но БЕЗ проверки Managed и с
// сохранением признака "файл существовал" (existed) — GUI (internal/guiview)
// различает по нему три состояния для непроверяемых протоколов (XRay, DNS и
// т.п.): "файла нет" (existed=false, err=nil), "не удалось прочитать/разобрать"
// (err!=nil) и "список есть" (existed=true, err=nil). LoadClients не подходит
// для этого: она намеренно схлопывает "файла нет" в пустой список без
// признака существования (FIX-VIEW, задание Д1).
//
// ЗАГЛУШКА (коммит 1 FIX-VIEW): возвращает nil, false, nil всегда — нужна
// только чтобы TestContainersWasNowTable и TestLoadClientsViewNoExtraCommands
// скомпилировались и дали контролируемый FAIL по сравнению с ожиданиями, а не
// ошибку компиляции. Реализация — следующий коммит.
func (s *Session) LoadClientsView(c *Container) (clients []ClientEntry, existed bool, err error) {
	return nil, false, nil
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

// removePeerFromConf удаляет блок [Peer] с указанным PublicKey из текста
// конфига. Сравнение точное: строка разбирается как key=value (SplitN по
// первому "=", TrimSpace обеих частей), совпадением считается
// EqualFold(key, "PublicKey") && value == pubKey. Раньше здесь была проверка
// strings.Contains(строка, pubKey) — пустой pubKey входит в любую строку, и
// блок [Peer] с ЛЮБЫМ ключом считался найденным (удалялись все peer'ы);
// ключ-подстрока другого ключа тоже совпадал бы (аудит 2026-09-14, High).
// Пустой (после TrimSpace) pubKey теперь отклоняется явной ошибкой — удалять
// "все, у кого есть PublicKey" не входит в контракт этой функции.
func removePeerFromConf(text, pubKey string) (string, error) {
	key := strings.TrimSpace(pubKey)
	if key == "" {
		return text, fmt.Errorf("отказ: пустой публичный ключ — удалять нечего")
	}
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
				kv := strings.SplitN(t, "=", 2)
				if len(kv) == 2 && strings.EqualFold(strings.TrimSpace(kv[0]), "PublicKey") && strings.TrimSpace(kv[1]) == key {
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
	return res, nil
}

// requireClientID отклоняет пустой (после TrimSpace) идентификатор клиента
// до любого обращения к серверу: filterClientsByID мог бы найти запись с
// пустым ClientID, если такая по ошибке оказалась в таблице, и удаление/
// операция пошли бы дальше по ложному совпадению.
func requireClientID(clientID string) error {
	if strings.TrimSpace(clientID) == "" {
		return fmt.Errorf("отказ: пустой идентификатор клиента")
	}
	return nil
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
// Обёртка над planAddUserLocked → applyLocked (core/txn.go, PR-2): план и
// применение делят один и тот же mu, взятый один раз на весь вызов.
func (s *Session) AddUser(c *Container, name string) (*NewUser, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, err := s.planAddUserLocked(c, name)
	if err != nil {
		return nil, err
	}
	return s.applyLocked(p)
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
// Обёртка над planDeleteLocked → applyLocked (core/txn.go, PR-2).
func (s *Session) DeleteByID(c *Container, clientID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, err := s.planDeleteLocked(c, clientID)
	if err != nil {
		return err
	}
	_, err = s.applyLocked(p)
	return err
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
// Обёртка над planRekeyLocked → applyLocked (core/txn.go, PR-2).
func (s *Session) RegenerateUser(c *Container, clientID string) (*NewUser, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, err := s.planRekeyLocked(c, clientID)
	if err != nil {
		return nil, err
	}
	return s.applyLocked(p)
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
// Обёртка над planRenameLocked → applyLocked (core/txn.go, PR-2). wg0.conf
// не трогается и wg syncconf не вызывается (Apply не пишет wg0.conf, когда
// wgAfter==wgBefore) — ключи и IP не меняются, значит соединение не рвётся.
func (s *Session) RenameUser(c *Container, clientID, newName string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, err := s.planRenameLocked(c, clientID, newName)
	if err != nil {
		return err
	}
	_, err = s.applyLocked(p)
	return err
}

// SetEnabled временно отключает клиента (enabled=false) или включает обратно
// (enabled=true) без удаления записи из clientsTable. Обёртка над
// planSetEnabledLocked → applyLocked (core/txn.go, PR-2); сама транзакция
// (backup/CAS/запись/verify/restore) — в Apply, здесь только план.
func (s *Session) SetEnabled(c *Container, clientID string, enabled bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, err := s.planSetEnabledLocked(c, clientID, enabled)
	if err != nil {
		return err
	}
	_, err = s.applyLocked(p)
	return err
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
