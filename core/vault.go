// Файл vault.go — шифрованное локальное хранилище ключей vpn:// (формат .avlt v1).
//
// Формат файла (little-endian):
//
//	magic          [4]byte  "AVLT"
//	version        byte     = 1
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
	vaultMagic     = "AVLT"
	vaultVersion   = 1
	vaultFlagDPAPI = 1 << 0

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

// pinRe допускает печатаемый ASCII (пробел..~, \x20-\x7E) длиной от 12
// символов — то есть латинские буквы, цифры И спецсимволы (они усиливают
// пин, поэтому разрешены, а не запрещены). Не-ASCII (в т.ч. кириллица) и
// управляющие символы (< 0x20 или 0x7F) исключаются самим диапазоном.
var pinRe = regexp.MustCompile(`^[\x20-\x7E]{12,}$`)

// ValidatePin проверяет пин-код: длина от 12 символов, печатаемый ASCII
// (спецсимволы разрешены), обязательно есть и латинская буква, и цифра.
//
// ВАЖНО: вызывается только при СОЗДАНИИ/сохранении пина (SealVault →
// offerSaveKey в GUI). OpenVault эту функцию НЕ вызывает — иначе ключи,
// сохранённые раньше (с прежним порогом длины, например 10 символов),
// перестали бы открываться после ужесточения политики. Открытие обязано
// принимать пин любой длины/формата и просто пытаться расшифровать.
func ValidatePin(pin string) error {
	const msg = "Пин-код: минимум 12 символов, обязательно латинские буквы и цифры; спецсимволы разрешены; кириллица и управляющие символы недопустимы."
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
func SealVault(pin string, payload VaultPayload, params ArgonParams, machineBind bool) ([]byte, error) {
	if err := ValidatePin(pin); err != nil {
		return nil, err
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

// OpenVault расшифровывает .avlt-файл. Любая порча данных или неверный пин —
// одна и та же ошибка (ErrVaultBadPinOrCorrupt), без паники.
func OpenVault(pin string, data []byte) (payload VaultPayload, err error) {
	defer func() {
		// защитный рубеж: любая порча не должна приводить к панике вызывающего кода
		if r := recover(); r != nil {
			payload = VaultPayload{}
			err = ErrVaultBadPinOrCorrupt
		}
	}()

	if len(data) < 6 { // magic(4)+version(1)+flags(1)
		return VaultPayload{}, ErrVaultBadPinOrCorrupt
	}
	if string(data[0:4]) != vaultMagic {
		return VaultPayload{}, ErrVaultBadPinOrCorrupt
	}
	version := data[4]
	if version > vaultVersion {
		return VaultPayload{}, ErrVaultNewerVersion
	}
	if version != vaultVersion {
		return VaultPayload{}, ErrVaultBadPinOrCorrupt
	}
	flags := data[5]

	if len(data) < vaultFixedHeaderLen {
		return VaultPayload{}, ErrVaultBadPinOrCorrupt
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
		return VaultPayload{}, ErrVaultBadPinOrCorrupt
	}
	salt := data[off : off+vaultSaltLen]
	off += vaultSaltLen
	dpapiLen := int(binary.LittleEndian.Uint16(data[off : off+2]))
	off += 2

	if len(data) < off+dpapiLen+vaultNonceLen {
		return VaultPayload{}, ErrVaultBadPinOrCorrupt
	}
	dpapiBlob := data[off : off+dpapiLen]
	off += dpapiLen
	nonce := data[off : off+vaultNonceLen]
	off += vaultNonceLen

	if len(data) < off+chacha20poly1305.Overhead {
		return VaultPayload{}, ErrVaultBadPinOrCorrupt
	}
	header := data[:off]
	ciphertext := data[off:]

	// ВАЖНО: OpenVault намеренно НЕ вызывает ValidatePin(pin) — при открытии
	// принимается пин любой длины/формата, чтобы файлы, сохранённые до
	// ужесточения политики (например, с 10-символьным пином), продолжали
	// открываться. Единственная проверка пина — попытка расшифровать AEAD
	// ниже; неверный пин просто не пройдёт аутентификацию тега.

	var machineSecret []byte
	if flags&vaultFlagDPAPI != 0 {
		if dpapiUnprotect == nil {
			return VaultPayload{}, fmt.Errorf("%w (файл привязан к компьютеру, но привязка недоступна на этой ОС)", ErrVaultBadPinOrCorrupt)
		}
		ms, uerr := dpapiUnprotect(dpapiBlob)
		if uerr != nil {
			return VaultPayload{}, fmt.Errorf("%w (возможно, файл привязан к другому компьютеру)", ErrVaultBadPinOrCorrupt)
		}
		machineSecret = ms
	}

	params := ArgonParams{MemoryKiB: memKiB, Time: t, Threads: p}
	argonKey := argon2.IDKey([]byte(pin), salt, uint32(params.Time), params.MemoryKiB, params.Threads, 32)
	finalKey, err := deriveFinalKey(argonKey, flags, machineSecret)
	if err != nil {
		return VaultPayload{}, err
	}

	aead, err := chacha20poly1305.NewX(finalKey)
	if err != nil {
		return VaultPayload{}, err
	}
	plaintext, err := aead.Open(nil, nonce, ciphertext, header)
	if err != nil {
		return VaultPayload{}, ErrVaultBadPinOrCorrupt
	}

	var pl VaultPayload
	if err := json.Unmarshal(plaintext, &pl); err != nil {
		return VaultPayload{}, ErrVaultBadPinOrCorrupt
	}
	return pl, nil
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
