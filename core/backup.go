package core

// Копия пользователей для переезда на новый сервер (проект БК-БЭКАП ред. 3,
// решения владельца 1–6, решения ядра Р-1…Р-6 от 04.10). Этот файл — формат
// копии и снятие её с сервера; только чтение.
//
// Формат файла .aabk — два слоя:
//
//	внешний (этот файл): строка «AABK <версия формата>», строка
//	«layer <имя слоя>», строка «sha256 <сумма тела>», пустая строка, тело;
//	слой (BackupLayer): тело = Seal(манифест JSON). Слой «none» — без
//	шифрования; шифрование паролем — Р-1, решение владельца ещё не принято,
//	поэтому здесь только интерфейс и закрытый список известных слоёв.
//
// Чтение — всё или ничего: незнакомая версия, незнакомый слой, расхождение
// суммы тела или суммы любого файла внутри — отказ «копия не прочитана: …»,
// частичного результата нет.
//
// Секреты: в копии приватный ключ сервера, PSK всех клиентов, UUID и ключи
// XRay. Содержимое файлов — тип Secret: при печати через fmt — «[скрыто,
// N байт]»; в текст ошибок и в предпросмотр байты не попадают.

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// BackupFormat — версия формата, которую пишет и читает эта программа.
const BackupFormat = 1

// BackupMagic — первая строка файла копии.
const BackupMagic = "AABK"

// Secret — байты секрета. Внутри — указатель (SEC-01): глагол %p у
// структуры, содержащей Secret, fmt печатает без вызова методов полей, и
// []byte выдал бы содержимое; указатель вложенного поля печатается адресом.
type Secret struct{ b *[]byte }

// NewSecret — Secret с копией байтов.
func NewSecret(b []byte) Secret {
	c := append([]byte(nil), b...)
	return Secret{&c}
}

// Bytes — копия байтов (только для записи на сервер и в файл копии).
func (s Secret) Bytes() []byte {
	if s.b == nil {
		return nil
	}
	return append([]byte(nil), (*s.b)...)
}

// Len — размер.
func (s Secret) Len() int {
	if s.b == nil {
		return 0
	}
	return len(*s.b)
}

func (s Secret) String() string   { return fmt.Sprintf("[скрыто, %d байт]", s.Len()) }
func (s Secret) GoString() string { return s.String() }

// Format — любой глагол fmt печатает только размер.
func (s Secret) Format(f fmt.State, _ rune) { fmt.Fprint(f, s.String()) }

// MarshalJSON — в файл копии (и только туда) — base64.
func (s Secret) MarshalJSON() ([]byte, error) {
	return json.Marshal(base64.StdEncoding.EncodeToString(s.Bytes()))
}

// UnmarshalJSON — из base64.
func (s *Secret) UnmarshalJSON(b []byte) error {
	var v string
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	d, err := base64.StdEncoding.DecodeString(v)
	if err != nil {
		return err
	}
	*s = NewSecret(d)
	return nil
}

// Format у типов копии (SEC-01): глагол, неверный для типа (например %p у
// структуры), fmt печатает БЕЗ вызова методов поля — сырые байты Secret.
// Поэтому сами типы, содержащие Secret, печатаются сводкой без данных при
// любом глаголе.
func (f BackupFile) Format(st fmt.State, _ rune) {
	fmt.Fprintf(st, "{%s %s %s}", f.Name, f.Status, f.Data.String())
}

func (c BackupContainer) Format(st fmt.State, _ rune) {
	fmt.Fprintf(st, "{%s %s файлов %d}", c.Name, c.Status, len(c.Files))
}

func (b Backup) Format(st fmt.State, _ rune) {
	fmt.Fprintf(st, "{копия формата %d, сервер %s, контейнеров %d, полная %v}", b.FormatVersion, b.Server.Host, len(b.Containers), b.Complete)
}

// Состояния файла в копии — три плюс «не входит» у контейнера.
const (
	FileSaved      = "saved"      // прочитан, согласован
	FileAbsent     = "absent"     // файла на сервере действительно нет
	FileUnreadable = "unreadable" // прочитать не удалось — НЕ «нет»
)

// Состояния контейнера в копии.
const (
	CtrSaved        = "saved"
	CtrNotIncluded  = "not_included" // протокол копией не поддерживается
	CtrUnreadable   = "unreadable"   // хотя бы один обязательный файл не прочитан
	CtrInconsistent = "inconsistent" // файлы менялись между чтениями
)

// Состояния версии протокола.
const (
	VersionKnown   = "known"
	VersionUnknown = "unknown" // определить не удалось (в т.ч. файл не прочитан)
)

// Состояния адреса выдачи.
const (
	ResolveOK         = "ok"
	ResolveFailed     = "failed"
	ResolveNotNeeded  = "not_needed" // адрес — IP
	AddressKindIP     = "ip"
	AddressKindName   = "name"
	AddressKindAbsent = "" // в копии нет адреса
)

// BackupFile — файл контейнера в копии.
type BackupFile struct {
	Name   string `json:"name"` // имя в каталоге контейнера
	Status string `json:"status"`
	SHA256 string `json:"sha256,omitempty"`
	Size   int    `json:"size,omitempty"`
	Data   Secret `json:"data"`
	Reason string `json:"reason,omitempty"` // для unreadable — без содержимого
}

// BackupContainer — контейнер в копии.
type BackupContainer struct {
	Name         string `json:"name"`
	Proto        string `json:"proto"`
	Dir          string `json:"dir,omitempty"`
	Status       string `json:"status"`
	Reason       string `json:"reason,omitempty"`
	Version      string `json:"version,omitempty"` // «1.5», «2», «3.1», «старый AWG», «WireGuard», «XRay»
	VersionState string `json:"version_state,omitempty"`
	// VersionReason — почему версия не определена (QA-01 (а)): показывается
	// в проверке цели.
	VersionReason string       `json:"version_reason,omitempty"`
	Port          string       `json:"port,omitempty"`
	Subnet        string       `json:"subnet,omitempty"` // Address [Interface] (WG); у XRay нет
	Files         []BackupFile `json:"files,omitempty"`
}

// IssuedAddress — адрес, по которому были выданы конфиги (hostName ключа
// vpn:// на момент снятия, П20 проекта БК).
type IssuedAddress struct {
	Value         string `json:"value"`
	Kind          string `json:"kind"` // ip | name
	ResolvedIP    string `json:"resolved_ip,omitempty"`
	ResolveStatus string `json:"resolve_status"`
}

// Backup — манифест копии.
type Backup struct {
	FormatVersion int    `json:"format"`
	CreatedAt     string `json:"created_at"` // UTC RFC 3339
	ToolVersion   string `json:"tool_version"`
	// Complete — нет ни одного контейнера «не удалось прочитать» или
	// «несогласованный снимок». «Не входит» полноты не отменяет, но всегда
	// перечисляется.
	Complete bool `json:"complete"`
	Server   struct {
		Host          string `json:"host"`
		HostKeySHA256 string `json:"hostkey_sha256,omitempty"`
	} `json:"server"`
	IssuedAddress IssuedAddress     `json:"issued_address"`
	Containers    []BackupContainer `json:"containers"`
}

// ---------- слои ----------

// BackupLayer — внутренний слой файла копии (Р-1: шифрование паролем — как
// реализация этого интерфейса, когда владелец решит).
type BackupLayer interface {
	Name() string
	Seal(plain []byte) ([]byte, error)
	Open(sealed []byte) ([]byte, error)
}

// PlainLayer — слой без шифрования (файл защищён правами 0600).
type PlainLayer struct{}

func (PlainLayer) Name() string                  { return "none" }
func (PlainLayer) Seal(b []byte) ([]byte, error) { return append([]byte(nil), b...), nil }
func (PlainLayer) Open(b []byte) ([]byte, error) { return append([]byte(nil), b...), nil }

// ErrBackupNotRead — копия не прочитана (обёртка для errors.Is).
var ErrBackupNotRead = errors.New("копия не прочитана")

func notRead(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrBackupNotRead, fmt.Sprintf(format, a...))
}

// EncodeBackup — байты файла копии.
func EncodeBackup(b *Backup, layer BackupLayer) ([]byte, error) {
	if layer == nil {
		return nil, errors.New("слой копии не задан")
	}
	if b.FormatVersion != BackupFormat {
		return nil, fmt.Errorf("формат копии %d, программа пишет %d", b.FormatVersion, BackupFormat)
	}
	plain, err := json.Marshal(b)
	if err != nil {
		return nil, fmt.Errorf("манифест копии не собран: %v", err)
	}
	body, err := layer.Seal(plain)
	if err != nil {
		return nil, fmt.Errorf("слой %s: %v", layer.Name(), err)
	}
	sum := sha256.Sum256(body)
	var out bytes.Buffer
	fmt.Fprintf(&out, "%s %d\nlayer %s\nsha256 %s\n\n", BackupMagic, BackupFormat, layer.Name(), hex.EncodeToString(sum[:]))
	out.Write(body)
	return out.Bytes(), nil
}

// DecodeBackup — копия из байтов файла. layers — известные слои (закрытый
// список); слоя из файла среди них нет — отказ. Всё или ничего.
func DecodeBackup(data []byte, layers ...BackupLayer) (*Backup, error) {
	head := data
	lines := make([]string, 0, 3)
	for i := 0; i < 4; i++ {
		j := bytes.IndexByte(head, '\n')
		if j < 0 {
			return nil, notRead("файл обрезан или это не копия")
		}
		lines = append(lines, string(head[:j]))
		head = head[j+1:]
	}
	f := strings.Fields(lines[0])
	if len(f) != 2 || f[0] != BackupMagic {
		return nil, notRead("это не файл копии amnezia-admin")
	}
	ver, err := strconv.Atoi(f[1])
	switch {
	case err != nil || ver < 1:
		return nil, notRead("версия формата не разобрана")
	case ver > BackupFormat:
		return nil, notRead("копия сделана более новой версией программы (формат %d, эта программа знает до %d) — обновите программу", ver, BackupFormat)
	}
	lf := strings.Fields(lines[1])
	sf := strings.Fields(lines[2])
	if len(lf) != 2 || lf[0] != "layer" || len(sf) != 2 || sf[0] != "sha256" || lines[3] != "" {
		return nil, notRead("заголовок повреждён")
	}
	var layer BackupLayer
	for _, l := range layers {
		if l != nil && l.Name() == lf[1] {
			layer = l
		}
	}
	if layer == nil {
		return nil, notRead("слой %q этой программе не известен", lf[1])
	}
	sum := sha256.Sum256(head)
	if hex.EncodeToString(sum[:]) != sf[1] {
		if layer.Name() == PasswordLayerName {
			// зашифрованная копия: повреждение и неверный пароль не различаются
			return nil, fmt.Errorf("%w: %w", ErrBackupNotRead, ErrBackupWrongPassword)
		}
		return nil, notRead("файл повреждён (сумма не сошлась)")
	}
	plain, err := layer.Open(head)
	if err != nil {
		if errors.Is(err, ErrBackupWrongPassword) {
			return nil, fmt.Errorf("%w: %w", ErrBackupNotRead, ErrBackupWrongPassword)
		}
		return nil, notRead("слой %s не открыт", layer.Name())
	}
	var b Backup
	dec := json.NewDecoder(bytes.NewReader(plain))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&b); err != nil {
		return nil, notRead("манифест не разобран")
	}
	if b.FormatVersion != ver {
		return nil, notRead("версия формата в заголовке (%d) и в манифесте (%d) расходятся", ver, b.FormatVersion)
	}
	if err := validateBackup(&b); err != nil {
		return nil, err
	}
	return &b, nil
}

// validateBackup — закрытые списки и инварианты манифеста (QA-01 Н1). Любой
// дефект — «копия не прочитана»: восстановление пишет только по закрытому
// списку файлов протокола, и копия, которой нельзя верить в мелочи, не
// читается вовсе.
func validateBackup(b *Backup) error {
	incomplete := false
	seen := map[string]bool{}
	for _, c := range b.Containers {
		if seen[c.Name] {
			return notRead("контейнер %s указан дважды", c.Name)
		}
		seen[c.Name] = true
		switch c.Status {
		case CtrSaved, CtrUnreadable:
		case CtrNotIncluded, CtrInconsistent:
			if len(c.Files) != 0 {
				return notRead("у контейнера %s в состоянии %s есть файлы", c.Name, c.Status)
			}
			incomplete = incomplete || c.Status == CtrInconsistent
			continue
		default:
			return notRead("состояние контейнера %q не из закрытого списка", c.Status)
		}
		incomplete = incomplete || c.Status == CtrUnreadable
		known, _, ok := lookupContainer(c.Name)
		if !ok || known.Dir != c.Dir {
			return notRead("контейнер %s с каталогом %q этой программе не известен", c.Name, c.Dir)
		}
		names, required, ok := backupFilesOf(&known)
		if !ok {
			return notRead("контейнер %s копией не поддерживается", c.Name)
		}
		if len(c.Files) != len(names) {
			return notRead("состав файлов %s не тот (%d вместо %d)", c.Name, len(c.Files), len(names))
		}
		for i, fl := range c.Files {
			if fl.Name != names[i] {
				return notRead("файл %q в %s не из закрытого списка (ждали %s)", fl.Name, c.Name, names[i])
			}
			switch fl.Status {
			case FileSaved:
				s := sha256.Sum256(fl.Data.Bytes())
				if hex.EncodeToString(s[:]) != fl.SHA256 || fl.Data.Len() != fl.Size {
					return notRead("файл %s/%s внутри копии повреждён", c.Name, fl.Name)
				}
			case FileAbsent, FileUnreadable:
				if fl.Data.Len() != 0 || fl.SHA256 != "" || fl.Size != 0 {
					return notRead("у файла %s/%s в состоянии %s есть данные", c.Name, fl.Name, fl.Status)
				}
			default:
				return notRead("состояние файла %q не из закрытого списка", fl.Status)
			}
			if c.Status == CtrSaved && (fl.Status == FileUnreadable || (required[fl.Name] && fl.Status != FileSaved)) {
				return notRead("контейнер %s «сохранён», а файл %s — %s", c.Name, fl.Name, fl.Status)
			}
		}
		if c.Status == CtrSaved && c.VersionState != VersionKnown && c.VersionState != VersionUnknown {
			return notRead("состояние версии %s %q не из закрытого списка", c.Name, c.VersionState)
		}
	}
	if b.Complete == incomplete {
		return notRead("признак полноты копии не соответствует состояниям контейнеров")
	}
	return nil
}

// WriteBackupFile — запись копии: временный файл рядом (имя
// «.<имя>.tmp-XXXX.aabk» — попадает под *.aabk в .gitignore), права 0600,
// fsync, затем итоговое имя — жёсткой ссылкой os.Link: она отказывает, если
// имя занято (SEC-01: Rename молча заменил бы файл, появившийся между
// проверкой и записью). Копии не перезаписываются.
func WriteBackupFile(path string, b *Backup, layer BackupLayer) error {
	data, err := EncodeBackup(b, layer)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*.aabk")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err := tmp.Chmod(0o600); err != nil && !isWindows() {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if beforeBackupLink != nil {
		beforeBackupLink()
	}
	if err := os.Link(name, path); err != nil {
		if errors.Is(err, os.ErrExist) {
			return fmt.Errorf("файл %s уже есть — копия не перезаписывается", path)
		}
		return fmt.Errorf("копия не записана под именем %s: %v", path, err)
	}
	return nil
}

// beforeBackupLink — шов теста: «имя появилось между записью временного
// файла и созданием итогового».
var beforeBackupLink func()

// BackupFileName — имя файла копии: «<хост>-<дата-время UTC>.aabk» (хост не
// секрет).
func BackupFileName(host string, now time.Time) string {
	return fmt.Sprintf("%s-%s.aabk", reSafeName.ReplaceAllString(host, "_"), now.UTC().Format("20060102-150405"))
}

// ReadBackupFile — копия из файла.
func ReadBackupFile(path string, layers ...BackupLayer) (*Backup, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, notRead("файл не открыт: %v", err)
	}
	return DecodeBackup(data, layers...)
}

func isWindows() bool { return os.PathSeparator == '\\' }

// ---------- снятие копии ----------

// backupFilesOf — закрытый список файлов контейнера в копии; required — без
// него контейнер «не удалось прочитать» даже при «нет на сервере».
func backupFilesOf(c *Container) (names []string, required map[string]bool, ok bool) {
	if IsXRay(c) {
		return []string{xrayConfFile, "clientsTable", "xray_uuid.key", "xray_short_id.key", "xray_public.key", "xray_private.key"},
			map[string]bool{xrayConfFile: true}, true
	}
	f, err := WGFamilyOf(c)
	if err != nil {
		return nil, nil, false
	}
	return []string{f.File, "clientsTable", "wireguard_server_public_key.key", "wireguard_psk.key"},
		map[string]bool{f.File: true}, true
}

// readFileState — содержимое файла и его состояние: «нет» — только по
// закрытой фразе cat «No such file or directory», иначе «не прочитан».
func (s *Session) readFileState(c *Container, name string) (data []byte, status, reason string) {
	out, err := s.catIn(c, c.Dir+"/"+name)
	if err == nil {
		return []byte(out), FileSaved, ""
	}
	// AU-LOGIC Low-1: «нет» — только если фраза относится к пути ЭТОГО файла.
	if strings.Contains(stderrText(err), c.Dir+"/"+name+": No such file or directory") {
		return nil, FileAbsent, ""
	}
	return nil, FileUnreadable, "не прочитан: " + MaskText(stderrTail(err))
}

// backupSnapshotTries — сколько раз пытаться получить согласованный снимок.
const backupSnapshotTries = 3

// snapshotContainer — файлы контейнера, прочитанные дважды подряд с
// совпавшим результатом (чужая запись между чтениями — повтор).
func (s *Session) snapshotContainer(c *Container, names []string) ([]BackupFile, bool) {
	read := func() []BackupFile {
		var fs []BackupFile
		for _, n := range names {
			d, st, why := s.readFileState(c, n)
			f := BackupFile{Name: n, Status: st, Reason: why}
			if st == FileSaved {
				sum := sha256.Sum256(d)
				f.SHA256, f.Size, f.Data = hex.EncodeToString(sum[:]), len(d), NewSecret(d)
			}
			fs = append(fs, f)
		}
		return fs
	}
	same := func(a, b []BackupFile) bool {
		for i := range a {
			if a[i].Status != b[i].Status || a[i].SHA256 != b[i].SHA256 {
				return false
			}
		}
		return true
	}
	for i := 0; i < backupSnapshotTries; i++ {
		a := read()
		b := read()
		if same(a, b) {
			return a, true
		}
	}
	return nil, false
}

// protoVersion — версия протокола контейнера по прочитанному файлу
// конфигурации (решение владельца 5: AWG 1.5/2/3.1, старый AWG, WireGuard,
// XRay). Не определено — VersionUnknown с причиной.
func protoVersion(c *Container, conf []byte) (version, state, reason string) {
	switch {
	case IsXRay(c):
		if _, err := parseXRayServer(conf); err != nil {
			return "", VersionUnknown, "формат server.json не распознан"
		}
		return "XRay", VersionKnown, ""
	case isAWG2(c):
		f := ParseAWGFormat(string(conf))
		if f.State != FormatKnown {
			return "", VersionUnknown, AWGReason(f)
		}
		if f.Version == "" {
			return "", VersionUnknown, "версия параметров AWG не определена (нет признаков 1.5, 2 и 3.1)"
		}
		return f.Version, VersionKnown, ""
	case c.Name == "amnezia-awg":
		return "старый AWG", VersionKnown, ""
	case c.Name == "amnezia-wireguard":
		return "WireGuard", VersionKnown, ""
	}
	return "", VersionUnknown, "протокол не из закрытого списка"
}

// portSubnet — порт и подсеть из файла конфигурации ("" — не найдено).
func portSubnet(c *Container, conf []byte) (port, subnet string) {
	if IsXRay(c) {
		if srv, err := parseXRayServer(conf); err == nil {
			return srv.port, ""
		}
		return "", ""
	}
	iface := parseWgConf(string(conf)).iface
	return iface["ListenPort"], iface["Address"]
}

// Resolver — разрешение имени в адреса (net.LookupIP; в тестах — подставной).
type Resolver func(host string) ([]net.IP, error)

// issuedAddress — адрес выдачи и его разрешение: IP — «не нужно»; имя —
// «ok» с адресами или «не удалось» (не пустой IP!).
func issuedAddress(host string, resolve Resolver) IssuedAddress {
	a := IssuedAddress{Value: host}
	if ip := net.ParseIP(host); ip != nil {
		a.Kind, a.ResolvedIP, a.ResolveStatus = AddressKindIP, ip.String(), ResolveNotNeeded
		return a
	}
	a.Kind = AddressKindName
	if resolve == nil {
		a.ResolveStatus = ResolveFailed
		return a
	}
	ips, err := resolve(host)
	if err != nil || len(ips) == 0 {
		a.ResolveStatus = ResolveFailed
		return a
	}
	var ss []string
	for _, ip := range ips {
		ss = append(ss, ip.String())
	}
	a.ResolvedIP, a.ResolveStatus = strings.Join(ss, ","), ResolveOK
	return a
}

// CollectBackup — снятие копии со всех контейнеров сервера (только чтение).
// Ошибка — только если не получен сам список контейнеров; всё прочее —
// состояния внутри копии.
func (s *Session) CollectBackup(toolVersion string, now time.Time, resolve Resolver) (*Backup, error) {
	cs, err := s.FindContainers()
	if err != nil {
		return nil, fmt.Errorf("список контейнеров не получен: %w", err)
	}
	b := &Backup{FormatVersion: BackupFormat, CreatedAt: now.UTC().Format(time.RFC3339), ToolVersion: toolVersion, Complete: true}
	if s.Creds != nil {
		b.Server.Host = s.Creds.Host
		b.IssuedAddress = issuedAddress(s.Creds.Host, resolve)
	}
	b.Server.HostKeySHA256 = s.HostKeyFingerprint
	for i := range cs {
		c := &cs[i]
		bc := BackupContainer{Name: c.Name, Proto: c.Title(), Dir: c.Dir}
		names, required, ok := backupFilesOf(c)
		if !ok {
			bc.Status, bc.Reason = CtrNotIncluded, "протокол копией не поддерживается"
			b.Containers = append(b.Containers, bc)
			continue
		}
		files, consistent := s.snapshotContainer(c, names)
		if !consistent {
			bc.Status, bc.Reason = CtrInconsistent, "файлы менялись между чтениями — согласованный снимок не получен"
			b.Complete = false
			b.Containers = append(b.Containers, bc)
			continue
		}
		bc.Files, bc.Status = files, CtrSaved
		for _, f := range files {
			if f.Status == FileUnreadable || (required[f.Name] && f.Status != FileSaved) {
				bc.Status = CtrUnreadable
				bc.Reason = f.Name + ": " + map[string]string{FileUnreadable: f.Reason, FileAbsent: "нет на сервере"}[f.Status]
				break
			}
		}
		if bc.Status != CtrSaved {
			b.Complete = false
		} else {
			conf := files[0].Data.Bytes()
			bc.Version, bc.VersionState, bc.VersionReason = protoVersion(c, conf)
			bc.Port, bc.Subnet = portSubnet(c, conf)
		}
		b.Containers = append(b.Containers, bc)
	}
	return b, nil
}
