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
			//
			// Proto — голый суффикс, БЕЗ пометки "(не поддерживается...)":
			// такая пометка ранее жила здесь и дублировалась GUI (":836",
			// "+= "(просмотр)""), из-за чего строка протокола рисковала нести
			// два разных суффикса. Единственное место подписи "только
			// просмотр" — internal/guiview.ProtoLabel (FIX-VIEW, решение
			// ядра Э1, 15.09).
			found = append(found, Container{
				Name:    n,
				Dir:     "/opt/amnezia/" + suffix,
				Proto:   suffix,
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

// EnabledState — включён ли клиент по записи clientsTable. ТРИ состояния
// (долг У1, 30.09.2026): поле disabled — наше расширение clientsTable, и
// его может испортить кто угодно (ручная правка, чужой инструмент). Прежде
// значение не типа bool читалось как «активен» (признак 2 CLAUDE.md), и
// toggle/rekey действовали по догадке — rekey к тому же стирает поле, то
// есть мог молча включить отключённого.
type EnabledState int

const (
	// EnabledActive — поля нет или false.
	EnabledActive EnabledState = iota
	// EnabledDisabled — поле true.
	EnabledDisabled
	// EnabledUnknown — поле есть, но не true/false: включён ли — неизвестно.
	EnabledUnknown
)

// EnabledState — состояние записи; см. тип.
func (e ClientEntry) EnabledState() EnabledState {
	v, ok := e.UserData["disabled"]
	if !ok || v == nil {
		return EnabledActive
	}
	b, isBool := v.(bool)
	switch {
	case !isBool:
		return EnabledUnknown
	case b:
		return EnabledDisabled
	}
	return EnabledActive
}

// Disabled — ТОЧНО отключён (EnabledState() == EnabledDisabled). Хранится как
// UserData["disabled"] = true. Это наше совместимое расширение clientsTable —
// клиент Amnezia лишние поля в userData сохраняет и игнорирует. false здесь
// НЕ значит «активен»: для решений, где это важно, — EnabledState().
func (e ClientEntry) Disabled() bool {
	return e.EnabledState() == EnabledDisabled
}

// EnabledUnknownNote — строка под списком пользователей (CLI list и строка
// состояния GUI): у кого включённость неизвестна. Пусто — таких нет. Строка
// в ячейке таблицы у них прежняя (без пометки «отключён»), поэтому без этой
// строки неизвестное выглядело бы как «активен».
func EnabledUnknownNote(names []string) string {
	if len(names) == 0 {
		return ""
	}
	q := make([]string, len(names))
	for i, n := range names {
		q[i] = fmt.Sprintf("%q", n)
	}
	return fmt.Sprintf("Включён ли пользователь, неизвестно (поле disabled в clientsTable не true/false): %s. "+
		"Отключать, включать и перевыпускать его утилита не будет, пока запись не исправлена.", strings.Join(q, ", "))
}

// EnabledUnknownError — отказ действия, зависящего от того, включён ли
// клиент, когда это неизвестно (EnabledUnknown).
func EnabledUnknownError(e ClientEntry) error {
	v := fmt.Sprintf("%v", e.UserData["disabled"])
	if r := []rune(v); len(r) > 40 {
		v = string(r[:40]) + "…"
	}
	return fmt.Errorf("Включён ли пользователь %q, неизвестно: в clientsTable поле disabled = %q, "+
		"а должно быть true или false. Ничего не изменено. Исправьте запись на сервере, затем повторите.",
		e.Name(), v)
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
func (s *Session) LoadClientsView(c *Container) (clients []ClientEntry, existed bool, err error) {
	data, existed, err := s.readClientsTableRaw(c)
	if err != nil {
		return nil, existed, err
	}
	if !existed {
		return nil, false, nil
	}
	clients, err = parseClientsTable(data)
	return clients, true, err
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
//
// НЕРАЗОБРАННОЕ — ОШИБКА, А НЕ НОЛЬ (A1б, признак 2). Прежде ошибки
// strconv.ParseInt отбрасывались, и поле, которое не разобралось, уезжало к
// человеку нулём: «—» (не подключался) и «0 B / 0 B» как измерение. Строка
// peer'а короче восьми полей молча пропускалась — и клиент оказывался «нет
// в статистике сервера (сейчас сервер его не принимает)», хотя сервер его
// держит. Ответ, который мы не поняли, — это «статистику получить не
// удалось» целиком: для этого состояния у всех потребителей уже есть свой
// текст (core.PeerFailed, core.SeenFailed), а угадывать, какие строки ответа
// верны, если одна из них нет, — не наше право.
func parsePeerStats(out string) (map[string]PeerStat, error) {
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
			return nil, fmt.Errorf("ответ wg show не разобран: в строке %d полей %d, ожидалось 8", i+1, len(f))
		}
		pub := f[0]
		var nums [3]int64
		for k, name := range []string{"время рукопожатия", "принято байт", "передано байт"} {
			n, err := strconv.ParseInt(f[4+k], 10, 64)
			if err != nil {
				return nil, fmt.Errorf("ответ wg show не разобран: строка %d, поле «%s» — не число", i+1, name)
			}
			nums[k] = n
		}
		var t time.Time
		if nums[0] > 0 {
			t = time.Unix(nums[0], 0)
		}
		stats[pub] = PeerStat{LastHandshake: t, RxBytes: nums[1], TxBytes: nums[2]}
	}
	return stats, nil
}

// GetPeerStats возвращает статистику по каждому peer'у (handshake, трафик)
func (s *Session) GetPeerStats(c *Container) (map[string]PeerStat, error) {
	out, err := s.docker(fmt.Sprintf("docker exec %s wg show wg0 dump", c.Name), nil)
	if err != nil {
		return nil, fmt.Errorf("wg show wg0 dump: %w", err)
	}
	stats, err := parsePeerStats(out)
	if err != nil {
		return nil, fmt.Errorf("wg show wg0 dump: %w", err)
	}
	return stats, nil
}

// GetHandshakes возвращает время последнего handshake по каждому публичному ключу
// ("—" — подключений не было); обёртка над GetPeerStats.
//
// ТРЕТЬЕ СОСТОЯНИЕ ВЫРАЖЕНО СИГНАТУРОЙ (задание A1, место № 1). Прежняя
// сигнатура — map[string]string без error — состояний различала два:
// «подключался» и «не подключался». Отказ сервера превращался в ПУСТУЮ
// КАРТУ, то есть в «ни один клиент не подключался», и до диалога удаления
// информация «данных нет» не доезжала ни в каком виде. Починить это в месте
// печати невозможно — там уже нечего различать; уничтожать признак незнания
// на пути к выводу нельзя, даже глубоко внутри.
//
// При ошибке карта возвращается nil, а не пустой: непустая карта рядом с
// ошибкой провоцирует вызывающего прочитать её и снова счесть пустоту
// ответом.
//
// Серверная команда не изменилась: это правка формы возврата в Go,
// `docker exec … wg show wg0 dump` остаётся дословно (TestServerCommandsUnchanged).
func (s *Session) GetHandshakes(c *Container) (map[string]string, error) {
	handshakes := map[string]string{}
	stats, err := s.GetPeerStats(c)
	if err != nil {
		return nil, err
	}
	for pub, st := range stats {
		if st.LastHandshake.IsZero() {
			handshakes[pub] = "—"
		} else {
			handshakes[pub] = st.LastHandshake.Format("2006-01-02 15:04")
		}
	}
	return handshakes, nil
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

// ResolveKind — исход разрешения идентификатора клиента. Три состояния, а не
// два: прежняя сигнатура возвращала int, где -1 означало одновременно «такого
// клиента нет» и «подходящих несколько, выбран первый» — перегруженное
// значение, из-за которого del/rename/toggle могли молча ударить не по тому
// человеку (A8, П-НЕЗНАНИЕ применительно к внутреннему интерфейсу).
type ResolveKind int

const (
	// ResolveNotFound — не подошёл ни один клиент.
	ResolveNotFound ResolveKind = iota
	// ResolveFound — подошёл ровно один клиент, Index указывает на него.
	ResolveFound
	// ResolveAmbiguous — подошло несколько клиентов, Matches перечисляет их.
	// Действовать по первому нельзя: операции необратимы.
	ResolveAmbiguous
	// ResolveBadLine — ввод в явной форме номера строки «#…», но строки с
	// таким номером нет («#99» при трёх строках) или после «#» не номер
	// («#0», «#-1», «#abc»). Отдельный исход, а не «не найдено»: человек
	// назвал СТРОКУ, и тихо искать «#abc» как имя значило бы ответить не на
	// его вопрос (решение владельца 26.09.2026).
	ResolveBadLine
)

// ResolveMode — видел ли человек пронумерованный список в момент ввода.
// От этого зависит, ЧЕМ ему предлагать уточнить выбор: номер строки,
// которой он не видел, — приглашение к wrong-target (ревью UX-01, A8 круг 2).
type ResolveMode int

const (
	// ModeFlags — флаговый режим (amnezia-admin del -name …): списка перед
	// глазами НЕТ, номера строк не называются и не действуют.
	ModeFlags ResolveMode = iota
	// ModeList — интерактивное меню: список только что напечатан, номера
	// строк осмысленны и на них можно ссылаться.
	ModeList
)

// Resolution — результат ResolveClient/ResolveNonNumeric. Выбирать по Index
// можно ТОЛЬКО при Kind == ResolveFound; в остальных случаях Err()
// объясняет, почему нельзя.
type Resolution struct {
	Kind ResolveKind
	// Mode — режим ввода; влияет ТОЛЬКО на тексты Note()/Err(), не на выбор.
	Mode  ResolveMode
	Ident string // что ввёл человек (как есть)
	Index int    // индекс в clients; осмыслен только при ResolveFound
	// Matches — индексы всех совпавших по имени/ключу, в порядке списка;
	// заполняется только при ResolveAmbiguous.
	Matches []int
	// ByName — при ResolveFound: клиент найден по имени/публичному ключу
	// (true) или по номеру строки (false).
	ByName bool
	// NameOverNumber — ввод годился И как номер строки, И как имя
	// существующего клиента. По решению владельца (21.09.2026) имя главнее
	// номера, но программа обязана сказать вслух, кого поняла, — иначе
	// привычный ввод номера однажды молча попадёт не в того клиента.
	NameOverNumber bool
	// LineIfNumber — номер строки (с 1), как ident читался бы числом; 0, если
	// ident числом не читается или выходит за пределы списка.
	LineIfNumber int
	// ShadowedByLine — при выборе по «#N»: строки (индексы) клиентов, чьё
	// ИМЯ дословно «#N». «#N» всегда номер строки, и они не выбраны; Note()
	// говорит об этом вслух.
	ShadowedByLine []int
}

// lineRef разбирает явную форму номера строки «#N» (решение владельца
// 26.09.2026: в интерактивном меню «#12» — ВСЕГДА номер строки, «12» —
// ВСЕГДА имя). isRef — ввод начинается с «#»; n — число после «#», если там
// только цифры, иначе 0 (ноль строкой не бывает, поэтому 0 = «не номер»).
func lineRef(ident string) (isRef bool, n int) {
	s := strings.TrimSpace(ident)
	if !strings.HasPrefix(s, "#") {
		return false, 0
	}
	digits := s[1:]
	if digits == "" {
		return true, 0
	}
	for _, c := range digits {
		if c < '0' || c > '9' {
			return true, 0
		}
	}
	n, err := strconv.Atoi(digits)
	if err != nil { // переполнение: такой строки нет заведомо
		return true, 0
	}
	return true, n
}

// nameMatches — индексы клиентов, чьё имя или публичный ключ дословно ident.
func nameMatches(clients []ClientEntry, ident string) []int {
	var out []int
	for i, cl := range clients {
		if cl.Name() == ident || cl.ClientID == ident {
			out = append(out, i)
		}
	}
	return out
}

// ResolveClient ищет клиента в напечатанном интерактивном списке: по имени
// или публичному ключу, либо по номеру строки (с 1) в явной форме «#N».
//
// РЕШЕНИЕ ВЛАДЕЛЬЦА 26.09.2026: «#12» — ВСЕГДА номер строки, «12» — ВСЕГДА
// имя. Прежнее правило (21.09.2026, «имя главнее номера») угадывало, что
// человек имел в виду под «12», и предупреждало жёлтым; теперь угадывать
// нечего, форма ввода говорит сама. Переспроса на месте нет (тоже решение
// владельца).
//
// Что осталось от предупреждения (Note): «12» совпало с именем, а строка 12
// в списке есть — человек мог по старой привычке иметь в виду строку;
// программа говорит, кого поняла, и как написать номер. И обратное: «#12»
// выбрало строку 12, а клиент с ИМЕНЕМ «#12» тоже есть — не выбран.
func ResolveClient(clients []ClientEntry, ident string) Resolution {
	r := Resolution{Ident: ident, Mode: ModeList}
	matches := nameMatches(clients, ident)
	if isRef, n := lineRef(ident); isRef {
		if n < 1 || n > len(clients) {
			r.Kind = ResolveBadLine
			return r
		}
		r.Kind = ResolveFound
		r.Index = n - 1
		r.LineIfNumber = n
		r.ShadowedByLine = matches
		return r
	}
	if n, e := strconv.Atoi(strings.TrimSpace(ident)); e == nil && n >= 1 && n <= len(clients) {
		r.LineIfNumber = n
	}
	r.Matches = matches
	switch {
	case len(r.Matches) > 1:
		r.Kind = ResolveAmbiguous
	case len(r.Matches) == 1:
		r.Kind = ResolveFound
		r.Index = r.Matches[0]
		r.Matches = nil
		r.ByName = true
		r.NameOverNumber = r.LineIfNumber != 0
	default:
		// Число без «#» номером строки НЕ становится никогда — даже когда
		// имени такого нет. Err() подскажет форму «#N».
		r.Kind = ResolveNotFound
	}
	return r
}

// Note — то, что программа обязана сказать человеку ДО действия; "" если
// говорить нечего. Единственный случай — ввод, годный и как номер строки, и
// как имя: человек должен видеть, кого поняли (условие ядра к решению
// владельца 21.09.2026). Работает в ОБОИХ режимах: во флаговом карточки
// подтверждения у rename нет вовсе, и молчание там опаснее, а не безопаснее.
func (r Resolution) Note() string {
	if r.Kind == ResolveFound && len(r.ShadowedByLine) > 0 {
		lines := make([]string, len(r.ShadowedByLine))
		for i, k := range r.ShadowedByLine {
			lines[i] = strconv.Itoa(k + 1)
		}
		return fmt.Sprintf("Это НОМЕР СТРОКИ: %q — строка %d. Пользователь с именем %q (строка %s) не выбран; к нему — по публичному ключу.",
			r.Ident, r.LineIfNumber, strings.TrimSpace(r.Ident), strings.Join(lines, ", "))
	}
	if r.Kind != ResolveFound || !r.NameOverNumber {
		return ""
	}
	if r.Mode == ModeList {
		return fmt.Sprintf("Это ИМЯ, а не номер: %q — имя пользователя из строки %d. Строка %d не выбрана (номер строки пишется с решёткой: #%d).",
			r.Ident, r.Index+1, r.LineIfNumber, r.LineIfNumber)
	}
	// ГЛАГОЛ ПРОДОЛЖЕНИЯ ОБЯЗАТЕЛЕН (ревью UX-01, круг 3). Ниже в этом же
	// файле ResolveNonNumeric отказывает текстом «номера действительны
	// только внутри интерактивного списка» — почти дословно та же вторая
	// фраза, но означает ОТКАЗ: действие НЕ выполнено. Две почти одинаковые
	// фразы, одна «сделал», другая «не сделал», различимые только по
	// контексту, которого у человека в спешке нет. «Продолжаю с ним» эту
	// двусмысленность снимает; скобка остаётся справкой, а не вердиктом.
	return fmt.Sprintf("Это ИМЯ, а не номер: %q — имя пользователя, продолжаю с ним.\n(Номера строк действуют только внутри интерактивного списка.)",
		r.Ident)
}

// Err — почему по этому вводу действовать нельзя; nil при ResolveFound.
// «Не найдено» и «подходит несколько» — разные ошибки с разным текстом.
//
// Форма перечня зависит от режима (ревью UX-01, A8 круг 2): во флаговом
// режиме человек списка НЕ ВИДЕЛ, поэтому номера строк там не называются
// вовсе — иначе программа предлагает номера несуществующего списка, ровно
// то, что ResolveNonNumeric запрещает своим же текстом. Вместо номеров —
// готовая замена аргумента.
func (r Resolution) Err(clients []ClientEntry) error {
	switch r.Kind {
	case ResolveFound:
		return nil
	case ResolveAmbiguous:
		lines := make([]string, 0, len(r.Matches))
		if r.Mode == ModeList {
			for _, i := range r.Matches {
				lines = append(lines, fmt.Sprintf("\n  строка %d — %q, ключ %s", i+1, clients[i].Name(), clients[i].ClientID))
			}
			return fmt.Errorf("под %q подходит несколько пользователей (%d) — уточните публичным ключом (последний столбец списка):%s",
				r.Ident, len(r.Matches), strings.Join(lines, ""))
		}
		for _, i := range r.Matches {
			lines = append(lines, fmt.Sprintf("\n  -name %s   (пользователь %q)", clients[i].ClientID, clients[i].Name()))
		}
		return fmt.Errorf("под %q подходит несколько пользователей (%d) — повторите команду с публичным ключом вместо имени:%s",
			r.Ident, len(r.Matches), strings.Join(lines, ""))
	case ResolveBadLine:
		_, n := lineRef(r.Ident)
		if len(clients) == 0 {
			return fmt.Errorf("строки %s нет: список пуст", strings.TrimSpace(r.Ident))
		}
		if n > 0 {
			return fmt.Errorf("строки #%d в списке нет — строки от #1 до #%d", n, len(clients))
		}
		hint := ""
		if m := nameMatches(clients, r.Ident); len(m) > 0 {
			hint = fmt.Sprintf("; пользователь с таким именем есть (строка %d) — к нему по публичному ключу", m[0]+1)
		}
		return fmt.Errorf("%q — не номер строки: после «#» нужно число от 1 до %d (первый столбец списка)%s",
			strings.TrimSpace(r.Ident), len(clients), hint)
	default:
		if r.Mode == ModeList {
			if _, e := strconv.Atoi(strings.TrimSpace(r.Ident)); e == nil {
				return fmt.Errorf("пользователя с именем %q нет (номер строки пишется с решёткой: #%s)",
					r.Ident, strings.TrimSpace(r.Ident))
			}
		}
		return fmt.Errorf("пользователь %q не найден", r.Ident)
	}
}

// ResolveNonNumeric резолвит идентификатора клиента ТОЛЬКО по имени или
// публичному ключу — числовой ident явно отклоняется с понятной ошибкой.
// Предназначен для non-interactive CLI-команд (del/rename/toggle), где нет
// напечатанного пронумерованного списка: там, откуда взято число, порядок
// LoadClients не совпадает с порядком, который видел пользователь
// (LoadClients не сортирован по активности, как отображаемая таблица), и
// резолв по номеру мог бы попасть не в того клиента (wrong-target).
//
// A8: «имя главнее номера» действует и здесь. Числовой ident отклоняется
// ТОЛЬКО если клиента с таким именем нет: совпадение по имени однозначно и
// wrong-target не создаёт, а вот резолв по номеру строки по-прежнему
// запрещён — до него дело не доходит никогда.
//
// ВОЗВРАЩАЕТ Resolution, А НЕ int (ревью BE-01/QA-01 M13, A8 круг 2).
// Прежняя сигнатура (int, error) не несла третьего состояния, и Note() —
// «понял как имя, а не как номер» — ВЫБРАСЫВАЛАСЬ по дороге: сужение
// запрета без компенсации. Материально это означало, что
// `amnezia-admin rename -name 12 -newname X` не печатает ничего до
// действия (карточки подтверждения у rename нет) и молча переименовывает
// клиента по имени «12». Тотальный запрет числовых ident назад не
// возвращается — это отменило бы решение владельца для флагового режима;
// вместо этого третье состояние выпущено наружу, а вызывающий обязан
// напечатать Note() ДО действия.
//
// Mode у результата — ModeFlags: списка человек не видел, номера строк в
// текстах не называются.
func ResolveNonNumeric(clients []ClientEntry, ident string) (Resolution, error) {
	r := Resolution{Kind: ResolveNotFound, Mode: ModeFlags, Ident: ident, Matches: nameMatches(clients, ident)}
	isRef, _ := lineRef(ident)
	_, numErr := strconv.Atoi(strings.TrimSpace(ident))
	switch len(r.Matches) {
	case 0:
	case 1:
		r.Kind, r.Index, r.ByName, r.Matches = ResolveFound, r.Matches[0], true, nil
		// Во флаговом режиме «двусмысленно» означает просто «ввод похож на
		// номер» — «12» или «#12»: списка нет, диапазон строк ни при чём.
		r.NameOverNumber = numErr == nil || isRef
		return r, nil
	default:
		r.Kind = ResolveAmbiguous
		return r, r.Err(clients)
	}
	// Не найдено по имени и ключу. Номер строки вне интерактивного списка не
	// резолвим никогда (wrong-target) — ни «12», ни «#12».
	notFound := Resolution{Kind: ResolveNotFound, Mode: ModeFlags, Ident: ident}
	if isRef {
		// «#12» — форма номера строки интерактивного меню (решение владельца
		// 26.09.2026). Здесь списка нет, и имени «#12» тоже нет: отказ,
		// говорящий, ГДЕ эта форма работает, а не голое «не найден».
		return notFound, fmt.Errorf("%q — номер строки, а номера строк («#N») действуют только в интерактивном меню; здесь укажите имя или публичный ключ",
			strings.TrimSpace(ident))
	}
	if numErr == nil {
		return notFound, fmt.Errorf("укажите имя или публичный ключ — номера действительны только внутри интерактивного списка")
	}
	return notFound, fmt.Errorf("пользователь %q не найден (укажите имя или публичный ключ)", ident)
}

// SortByActivity сортирует клиентов по активности: недавний LastHandshake —
// первым (по убыванию); клиенты без единого подключения — в конце, среди
// них порядок по дате создания (Created). Сортировка стабильна и выполняется
// на месте (in place). stats — карта ClientID → PeerStat (как из GetPeerStats).
func SortByActivity(clients []ClientEntry, stats map[string]PeerStat) {
	//
	// Клиенты, про которых статистики нет (запрос не удался или их нет в
	// ответе), — после всех измеренных, даже после «не подключался»:
	// незнание не сортируется как ноль (задание НЕЗНАНИЕ-ТРАФИК). Значения
	// читаются только через ReadPeer(...).Measured().
	sort.SliceStable(clients, func(i, j int) bool {
		si, ki := ReadPeer(stats, false, clients[i].ClientID).Measured()
		sj, kj := ReadPeer(stats, false, clients[j].ClientID).Measured()
		if ki != kj {
			return ki
		}
		hi, hj := si.LastHandshake, sj.LastHandshake
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

// OrphanPeers — публичные ключи peer'ов из wg0.conf, отсутствующие в clientsTable.
//
// ОШИБКА ВОЗВРАЩАЕТСЯ (A1б, признак 2). Прежняя сигнатура — только
// []string — при отказе чтения wg0.conf отдавала nil, то есть «сирот нет»:
// list молчал ровно так же, как на чистом сервере, и человек не узнавал,
// что проверка не состоялась.
func (s *Session) OrphanPeers(c *Container, clients []ClientEntry) ([]string, error) {
	raw, err := s.catIn(c, c.Dir+"/wg0.conf")
	if err != nil {
		return nil, fmt.Errorf("чтение wg0.conf: %w", err)
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
	return orphans, nil
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
