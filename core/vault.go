// Файл vault.go — шифрованное локальное хранилище ключей vpn:// (формат .avlt,
// версии 1 и 2).
//
// Формат файла (little-endian):
//
//	magic          [4]byte  "AVLT"
//	version        byte     = 1 или 2
//	flags          byte     бит0 = DPAPI machine-bind
//	argonMemoryKiB uint32   параметры Argon2id (KiB)
//	argonTime      byte
//	argonThreads   byte
//	salt           [16]byte
//	dpapiBlobLen   uint16   0, если flags.bit0 не установлен
//	dpapiBlob      [dpapiBlobLen]byte  DPAPI-блоб с machineSecret (только Windows)
//	nonce          [24]byte XChaCha20-Poly1305
//	ciphertext     до конца файла (включает 16-байтовый tag Poly1305)
//
// AAD для AEAD — весь заголовок целиком, от magic до nonce включительно.
// Ключ шифрования — Argon2id(pin, salt, params); если machineBind включён,
// финальный ключ = HKDF-SHA256(argonKey, machineSecret), где machineSecret
// генерируется случайно при Seal и хранится в файле, зашифрованный DPAPI
// (доступен для расшифровки только на той же машине/учётке Windows).
//
// v1 → v2 (PR-4, host key pinning): единственное отличие — байт version в
// заголовке и новое (необязательное, omitempty) поле JSON
// VaultPayload.HostKeyFingerprint внутри зашифрованного payload. Формат
// заголовка, AEAD, деривация ключа — не изменились. Строка контекста HKDF
// ("amnezia-admin vault v1") НЕ переименована при переходе на v2: это просто
// метка домена для деривации ключа, а не номер версии формата, и её смена
// сделала бы нечитаемыми все файлы v1 с machine-bind (DPAPI) — оставлена как
// есть намеренно. OpenVault принимает обе версии (1 и 2); версии > 2 —
// ErrVaultNewerVersion. SealVault всегда пишет текущую (2).
package core

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

const (
	vaultMagic = "AVLT"
	// vaultVersion — версия формата, которую пишет SealVault (текущая, 2).
	// OpenVault/OpenVaultInfo принимают файлы версий 1..vaultVersion; версия
	// выше vaultVersion — ErrVaultNewerVersion (см. vaultVersionMin).
	vaultVersion = 2
	// vaultVersionMin — самая старая версия формата, которую ещё открываем
	// (обратная совместимость, PR-4: «у кого уже есть настройки не потеряли
	// доступ»).
	vaultVersionMin = 1
	vaultFlagDPAPI  = 1 << 0

	// длина фиксированной части заголовка до dpapiBlob (magic..salt) +
	// поле длины dpapiBlob (u16)
	vaultFixedHeaderLen = 4 + 1 + 1 + 4 + 1 + 1 + 16 + 2
	vaultSaltLen        = 16
	vaultNonceLen       = 24
)

// ArgonParams — параметры Argon2id, инъектируемые (в проде — ProdArgonParams,
// в тестах — облегчённые, чтобы не ждать секунду на каждый прогон)
type ArgonParams struct {
	MemoryKiB uint32 // m, в KiB
	Time      uint8  // t
	Threads   uint8  // p
}

// ProdArgonParams — параметры для реального использования (~512 MiB, ~1-2 сек).
// Параметры пишутся в заголовок каждого .avlt-файла и читаются оттуда при
// открытии (см. OpenVault) — эта константа влияет только на НОВЫЕ файлы,
// сохраняемые сейчас; ранее сохранённые файлы (например, на 256 MiB)
// продолжают открываться на своих собственных, зафиксированных в заголовке
// параметрах и не зависят от изменения этой константы.
var ProdArgonParams = ArgonParams{MemoryKiB: 524288, Time: 4, Threads: 4}

// VaultPayload — то, что хранится внутри зашифрованного файла
type VaultPayload struct {
	Label   string `json:"label"`
	Key     string `json:"key"`
	Created string `json:"created"`

	// HostKeyFingerprint — отпечаток (SHA256:…) подтверждённого ключа хоста
	// SSH-сервера, к которому относится Key (PR-4, v2). Пусто у файлов v1 и у
	// v2-файлов, для которых ключ хоста ещё не был подтверждён/перезапечатан
	// (см. ForgetHostKey, core/hostkey.go) — это НЕ ошибка, просто "ещё не
	// знаем"; смысловой отказ подключения из-за пустого отпечатка не делается
	// здесь, а на уровне ConnectWithHostKey (пустой ExpectedFingerprint —
	// обычный неизвестный сервер).
	HostKeyFingerprint string `json:"hostKeyFingerprint,omitempty"`
}

// ErrVaultBadPinOrCorrupt — единый текст ошибки для неверного пина и любой
// порчи файла (нельзя различать, иначе это оракул для брутфорса пина)
var ErrVaultBadPinOrCorrupt = errors.New("не удалось расшифровать: неверный пин-код или файл повреждён")

// ErrVaultNewerVersion — файл создан более новой версией формата
var ErrVaultNewerVersion = errors.New("файл создан более новой версией утилиты — обновите её")

// dpapiProtect/dpapiUnprotect — платформенный слой machine-bind (DPAPI на
// Windows), подставляется из vault_windows.go / vault_other.go
var (
	dpapiProtect   func(secret []byte) ([]byte, error)
	dpapiUnprotect func(blob []byte) ([]byte, error)
)

// pinCharClass — ЕДИНСТВЕННОЕ описание набора символов, допустимого в пине:
// печатаемый ASCII (пробел..~, \x20-\x7E) — латинские буквы, цифры И
// спецсимволы (они усиливают пин, поэтому разрешены, а не запрещены).
// Не-ASCII (кириллица, греческий, иврит, диакритика, полноширинные формы,
// эмодзи) и управляющие символы (< 0x20 или 0x7F) исключаются самим
// диапазоном.
//
// ПОЧЕМУ КОНСТАНТА, А НЕ ДВА РЕГУЛЯРНЫХ ВЫРАЖЕНИЯ. Из неё собираются и
// проверка пина целиком (pinRe), и посимвольная проверка
// NonEnglishLayoutSuspect, которой GUI объясняет человеку, что включена не
// английская раскладка. Разойтись им нечему: расширят набор — подсказка
// поедет следом, а не останется «про кириллицу».
// Связь прибита тестом TestLayoutSuspectFollowsValidatePin.
const pinCharClass = `\x20-\x7E`

var pinRe = regexp.MustCompile(`^[` + pinCharClass + `]{12,}$`)

// pinCharRe — тот же набор, но про ОДИН символ.
var pinCharRe = regexp.MustCompile(`^[` + pinCharClass + `]$`)

// NonEnglishLayoutSuspect — во введённом тексте есть хотя бы один символ,
// которого ValidatePin не допускает ПО НАБОРУ СИМВОЛОВ. Практически это
// значит одно: включена не английская раскладка (кириллица, греческий,
// иврит, турецкая ı, é из европейских раскладок, полноширинные формы
// азиатского ввода) либо в текст попали управляющие символы.
//
// Функция отвечает ТОЛЬКО ДА/НЕТ и ничего не возвращает из самого текста:
// её зовут для пин-кода и админского ключа, и ни один символ секрета не
// должен уехать ни в сообщение, ни в журнал.
func NonEnglishLayoutSuspect(s string) bool {
	for _, r := range s {
		if !pinCharRe.MatchString(string(r)) {
			return true
		}
	}
	return false
}

// ValidatePin проверяет пин-код: длина от 12 символов, печатаемый ASCII
// (спецсимволы разрешены), обязательно есть и латинская буква, и цифра.
//
// ВАЖНО: вызывается только там, где пин ЗАДАЁТСЯ ЗАНОВО — то есть в
// SealVault (создание нового хранилища, offerSaveKey в GUI). Ни OpenVault,
// ни SealVaultExisting эту функцию НЕ вызывают, и это не упущение, а
// правило: файл, сохранённый до ужесточения политики (например, с
// 10-символьным пином), обязан и открываться, и ЗАПЕЧАТЫВАТЬСЯ ОБРАТНО
// верным пином любой длины. Иначе «Забыть ключ сервера» и запись нового
// отпечатка для таких файлов не работают никогда — обещанный владельцу путь
// восстановления молча сломан, и обнаруживается это в худший момент, когда
// ключ сервера уже сменился.
//
// Если будете «чинить обратно», добавив ValidatePin в путь перезапечатывания,
// — уроните TestForgetHostKeyOldShortPin (core/vault_shortpin_test.go).
// Сначала прочитайте его шапку.
func ValidatePin(pin string) error {
	const msg = "Пин-код: минимум 12 символов, обязательно латинские буквы и цифры; спецсимволы разрешены; буквы любых других алфавитов (кириллица, диакритика и прочие) и управляющие символы недопустимы."
	if !pinRe.MatchString(pin) {
		return fmt.Errorf("%s", msg)
	}
	hasLetter, hasDigit := false, false
	for _, r := range pin {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z':
			hasLetter = true
		case r >= '0' && r <= '9':
			hasDigit = true
		}
	}
	if !hasLetter || !hasDigit {
		return fmt.Errorf("%s", msg)
	}
	return nil
}

// SealVault шифрует payload пин-кодом и возвращает содержимое .avlt-файла.
//
// Применяется ТОЛЬКО там, где пин задаётся заново (создание хранилища): здесь
// и только здесь действует политика пина (ValidatePin). Для перезаписи уже
// открытого файла тем же пином есть SealVaultExisting — см. его шапку.
func SealVault(pin string, payload VaultPayload, params ArgonParams, machineBind bool) ([]byte, error) {
	if err := ValidatePin(pin); err != nil {
		return nil, err
	}
	return SealVaultExisting(pin, payload, params, machineBind)
}

// SealVaultExisting запечатывает payload пином УЖЕ СУЩЕСТВУЮЩЕГО хранилища,
// НЕ применяя политику создания пина.
//
// Принцип (решение ядра, PR-A4): перезапечатывание существующего файла не
// применяет политику создания пина. Проверка длины — правило для ЗАДАНИЯ
// нового пина, а не для записи в файл, уже открытый верным пином. Пин здесь
// не «принимается на веру»: вызывающий получил его только что успешным
// OpenVault/OpenVaultInfo, то есть он уже доказан расшифровкой AEAD.
//
// Отсюда следует требование, которое проверяется тестом: ForgetHostKey и
// перезапечатывание работают при верном пине ЛЮБОЙ длины.
//
// ОДНО ИСКЛЮЧЕНИЕ — ПУСТОЙ ПИН, и оно здесь не косметика (ревью SEC-01).
// Пустая строка не может быть тем пином, которым файл открылся: в GUI пин
// обнуляется сразу после использования, и попасть сюда пустым он может
// только по ошибке порядка строк в вызывающем. Записать же такой файл —
// значит молча снять защиту совсем: OpenVault политику не применяет и потом
// откроет его кому угодно. Поэтому проверка стоит ЗДЕСЬ, на границе, а не
// держится на порядке операторов в чужой функции.
func SealVaultExisting(pin string, payload VaultPayload, params ArgonParams, machineBind bool) ([]byte, error) {
	if pin == "" {
		return nil, fmt.Errorf("внутренняя ошибка: попытка запечатать хранилище пустым пином — откройте хранилище заново")
	}
	if machineBind && dpapiProtect == nil {
		return nil, fmt.Errorf("привязка к компьютеру недоступна на этой ОС")
	}

	plaintext, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("сериализация ключа: %w", err)
	}

	salt := make([]byte, vaultSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}

	var flags byte
	var dpapiBlob []byte
	var machineSecret []byte
	if machineBind {
		flags |= vaultFlagDPAPI
		machineSecret = make([]byte, 32)
		if _, err := rand.Read(machineSecret); err != nil {
			return nil, err
		}
		dpapiBlob, err = dpapiProtect(machineSecret)
		if err != nil {
			return nil, fmt.Errorf("привязка к компьютеру (DPAPI): %w", err)
		}
	}
	if len(dpapiBlob) > 0xFFFF {
		return nil, fmt.Errorf("внутренняя ошибка: DPAPI-блоб слишком велик")
	}

	argonKey := argon2.IDKey([]byte(pin), salt, uint32(params.Time), params.MemoryKiB, params.Threads, 32)
	finalKey, err := deriveFinalKey(argonKey, flags, machineSecret)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, vaultNonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	header := buildVaultHeader(flags, params, salt, dpapiBlob, nonce)

	aead, err := chacha20poly1305.NewX(finalKey)
	if err != nil {
		return nil, err
	}
	ciphertext := aead.Seal(nil, nonce, plaintext, header)

	return append(header, ciphertext...), nil
}

// buildVaultHeader собирает заголовок файла (AAD) в порядке формата
func buildVaultHeader(flags byte, params ArgonParams, salt, dpapiBlob, nonce []byte) []byte {
	var b bytes.Buffer
	b.WriteString(vaultMagic)
	b.WriteByte(vaultVersion)
	b.WriteByte(flags)
	var u32 [4]byte
	binary.LittleEndian.PutUint32(u32[:], params.MemoryKiB)
	b.Write(u32[:])
	b.WriteByte(params.Time)
	b.WriteByte(params.Threads)
	b.Write(salt)
	var u16 [2]byte
	binary.LittleEndian.PutUint16(u16[:], uint16(len(dpapiBlob)))
	b.Write(u16[:])
	b.Write(dpapiBlob)
	b.Write(nonce)
	return b.Bytes()
}

// vaultMaxArgonMemoryKiB — верхняя граница памяти Argon2, принимаемая из
// заголовка при открытии файла (1 GiB); защита от OOM/DoS через испорченный
// или злонамеренный файл.
const vaultMaxArgonMemoryKiB = 1 << 20 // 1 GiB в KiB

// validateArgonParams проверяет параметры Argon2id из заголовка ПЕРЕД тем,
// как они попадут в argon2.IDKey: 1 ≤ memKiB ≤ 1 GiB, t ≥ 1, 1 ≤ p ≤ 64.
func validateArgonParams(memKiB uint32, t, p uint8) error {
	if memKiB < 1 || memKiB > vaultMaxArgonMemoryKiB {
		return fmt.Errorf("недопустимые параметры Argon2")
	}
	if t < 1 {
		return fmt.Errorf("недопустимые параметры Argon2")
	}
	if p < 1 || p > 64 {
		return fmt.Errorf("недопустимые параметры Argon2")
	}
	return nil
}

// deriveFinalKey — при machine-bind финальный ключ = HKDF-SHA256(argonKey, machineSecret)
func deriveFinalKey(argonKey []byte, flags byte, machineSecret []byte) ([]byte, error) {
	if flags&vaultFlagDPAPI == 0 {
		return argonKey, nil
	}
	hk := hkdf.New(sha256.New, argonKey, machineSecret, []byte("amnezia-admin vault v1"))
	finalKey := make([]byte, 32)
	if _, err := io.ReadFull(hk, finalKey); err != nil {
		return nil, err
	}
	return finalKey, nil
}

// VaultInfo — метаданные .avlt-файла, извлечённые при OpenVaultInfo вместе с
// payload: нужны, чтобы перезапечатать файл (SealVault) с теми же
// параметрами Argon2 и той же привязкой к машине, не спрашивая пользователя
// заново (ForgetHostKey, часть Б — Е1 после подтверждения хоста).
type VaultInfo struct {
	Version     byte
	MachineBind bool
	Params      ArgonParams
}

// OpenVault расшифровывает .avlt-файл. Любая порча данных или неверный пин —
// одна и та же ошибка (ErrVaultBadPinOrCorrupt), без паники. Обёртка над
// OpenVaultInfo для вызывающих, которым не нужны метаданные.
func OpenVault(pin string, data []byte) (VaultPayload, error) {
	payload, _, err := OpenVaultInfo(pin, data)
	return payload, err
}

// OpenVaultInfo — как OpenVault, но дополнительно возвращает VaultInfo
// (версия файла, флаг machine-bind, параметры Argon2 из заголовка).
func OpenVaultInfo(pin string, data []byte) (payload VaultPayload, info VaultInfo, err error) {
	defer func() {
		// защитный рубеж: любая порча не должна приводить к панике вызывающего кода
		if r := recover(); r != nil {
			payload = VaultPayload{}
			info = VaultInfo{}
			err = ErrVaultBadPinOrCorrupt
		}
	}()

	if len(data) < 6 { // magic(4)+version(1)+flags(1)
		return VaultPayload{}, VaultInfo{}, ErrVaultBadPinOrCorrupt
	}
	if string(data[0:4]) != vaultMagic {
		return VaultPayload{}, VaultInfo{}, ErrVaultBadPinOrCorrupt
	}
	version := data[4]
	if version > vaultVersion {
		return VaultPayload{}, VaultInfo{}, ErrVaultNewerVersion
	}
	if version < vaultVersionMin {
		return VaultPayload{}, VaultInfo{}, ErrVaultBadPinOrCorrupt
	}
	flags := data[5]

	if len(data) < vaultFixedHeaderLen {
		return VaultPayload{}, VaultInfo{}, ErrVaultBadPinOrCorrupt
	}
	off := 6
	memKiB := binary.LittleEndian.Uint32(data[off : off+4])
	off += 4
	t := data[off]
	off++
	p := data[off]
	off++
	// Параметры Argon2 из заголовка нельзя доверять (файл мог быть испорчен
	// или подсунут злонамеренно) — проверяем границы ДО вызова argon2.IDKey,
	// иначе можно спровоцировать неограниченное выделение памяти/времени.
	if err := validateArgonParams(memKiB, t, p); err != nil {
		return VaultPayload{}, VaultInfo{}, ErrVaultBadPinOrCorrupt
	}
	salt := data[off : off+vaultSaltLen]
	off += vaultSaltLen
	dpapiLen := int(binary.LittleEndian.Uint16(data[off : off+2]))
	off += 2

	if len(data) < off+dpapiLen+vaultNonceLen {
		return VaultPayload{}, VaultInfo{}, ErrVaultBadPinOrCorrupt
	}
	dpapiBlob := data[off : off+dpapiLen]
	off += dpapiLen
	nonce := data[off : off+vaultNonceLen]
	off += vaultNonceLen

	if len(data) < off+chacha20poly1305.Overhead {
		return VaultPayload{}, VaultInfo{}, ErrVaultBadPinOrCorrupt
	}
	header := data[:off]
	ciphertext := data[off:]

	// ВАЖНО: OpenVault(Info) намеренно НЕ вызывает ValidatePin(pin) — при
	// открытии принимается пин любой длины/формата, чтобы файлы, сохранённые
	// до ужесточения политики (например, с 10-символьным пином), продолжали
	// открываться. Единственная проверка пина — попытка расшифровать AEAD
	// ниже; неверный пин просто не пройдёт аутентификацию тега.

	params := ArgonParams{MemoryKiB: memKiB, Time: t, Threads: p}
	info = VaultInfo{Version: version, MachineBind: flags&vaultFlagDPAPI != 0, Params: params}

	var machineSecret []byte
	if flags&vaultFlagDPAPI != 0 {
		if dpapiUnprotect == nil {
			return VaultPayload{}, info, fmt.Errorf("%w (файл привязан к компьютеру, но привязка недоступна на этой ОС)", ErrVaultBadPinOrCorrupt)
		}
		ms, uerr := dpapiUnprotect(dpapiBlob)
		if uerr != nil {
			return VaultPayload{}, info, fmt.Errorf("%w (возможно, файл привязан к другому компьютеру)", ErrVaultBadPinOrCorrupt)
		}
		machineSecret = ms
	}

	argonKey := argon2.IDKey([]byte(pin), salt, uint32(params.Time), params.MemoryKiB, params.Threads, 32)
	finalKey, ferr := deriveFinalKey(argonKey, flags, machineSecret)
	if ferr != nil {
		return VaultPayload{}, info, ferr
	}

	aead, aerr := chacha20poly1305.NewX(finalKey)
	if aerr != nil {
		return VaultPayload{}, info, aerr
	}
	plaintext, oerr := aead.Open(nil, nonce, ciphertext, header)
	if oerr != nil {
		return VaultPayload{}, info, ErrVaultBadPinOrCorrupt
	}

	var pl VaultPayload
	if jerr := json.Unmarshal(plaintext, &pl); jerr != nil {
		return VaultPayload{}, info, ErrVaultBadPinOrCorrupt
	}
	return pl, info, nil
}

// ---------- файловые операции ----------

// DefaultVaultDir — папка "Настройки" рядом с исполняемым файлом
func DefaultVaultDir() string {
	exe, err := os.Executable()
	if err != nil {
		return "Настройки"
	}
	return filepath.Join(filepath.Dir(exe), "Настройки")
}

// ListVaults возвращает пути к файлам *.avlt в каталоге, отсортированные по имени
func ListVaults(dir string) []string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if strings.EqualFold(filepath.Ext(e.Name()), ".avlt") {
			out = append(out, filepath.Join(dir, e.Name()))
		}
	}
	sort.Strings(out)
	return out
}

// SaveVault сохраняет данные под случайным именем (8 hex-символов + .avlt)
// атомарно (запись во временный файл + rename). Возвращает итоговый путь.
func SaveVault(dir string, data []byte) (string, error) {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", err
	}
	var nameBytes [4]byte
	if _, err := rand.Read(nameBytes[:]); err != nil {
		return "", err
	}
	name := hex.EncodeToString(nameBytes[:]) + ".avlt"
	path := filepath.Join(dir, name)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return "", err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return "", err
	}
	return path, nil
}

// LoadVault читает содержимое файла .avlt
func LoadVault(path string) ([]byte, error) {
	return os.ReadFile(path)
}

// WriteVaultFile атомарно перезаписывает УЖЕ СУЩЕСТВУЮЩИЙ файл по заданному
// пути (tmp + rename, как SaveVault) — в отличие от SaveVault, которая всегда
// выбирает новое случайное имя, эта функция используется для перезапечатывания
// на месте (PR-4: ForgetHostKey и, в части Б, дописывание HostKeyFingerprint
// после первого подтверждённого подключения). Путь не создаётся заново —
// только каталог назначения, если его вдруг нет.
func WriteVaultFile(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}
