package core

// Слой шифрования копии паролем (решение владельца по Р-1 от 05.10: «оба
// режима, выбор при сохранении»). Только стандартная криптография:
// Argon2id (golang.org/x/crypto/argon2) — ключ из пароля, соль и параметры
// в заголовке слоя; XChaCha20-Poly1305 — шифрование с проверкой
// целостности, заголовок слоя — связанные данные (подмена параметров или
// соли ломает проверку). Неверный пароль и повреждение не различаются:
// «копия не прочитана: неверный пароль или файл повреждён».

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

// PasswordLayerName — имя слоя в заголовке файла копии.
const PasswordLayerName = "argon2id-xchacha20"

// BackupPasswordMin — наименьшая длина пароля копии (символов).
const BackupPasswordMin = 12

// BackupPasswordWarning — предупреждение при сохранении с паролем.
const BackupPasswordWarning = `Копия будет зашифрована паролем.
Забудете пароль — копию не восстановить никак: ни программа, ни её авторы пароль не знают и обойти его не могут.
Храните пароль отдельно от файла копии.`

// ErrBackupWrongPassword — неверный пароль или файл повреждён (не
// различаются).
var ErrBackupWrongPassword = errors.New("неверный пароль или файл повреждён")

// ValidateBackupPassword — пароль не короче BackupPasswordMin символов.
func ValidateBackupPassword(pw Secret) error {
	if n := utf8.RuneCount(pw.Bytes()); n < BackupPasswordMin {
		return fmt.Errorf("пароль короче %d символов (%d)", BackupPasswordMin, n)
	}
	return nil
}

// PasswordLayer — слой «argon2id-xchacha20». Params — для НОВЫХ копий
// (нулевые — ProdArgonParams); при чтении параметры берутся из заголовка.
type PasswordLayer struct {
	Password Secret
	Params   ArgonParams
}

func (PasswordLayer) Name() string { return PasswordLayerName }

const (
	pwMagic   = "AAPW"
	pwVersion = 1
	pwSaltLen = 16
	pwHdrLen  = 4 + 1 + 4 + 1 + 1 + pwSaltLen + chacha20poly1305.NonceSizeX
)

func (l PasswordLayer) key(salt []byte, m uint32, t, p uint8) []byte {
	return argon2.IDKey(l.Password.Bytes(), salt, uint32(t), m, p, chacha20poly1305.KeySize)
}

// Seal — заголовок слоя (магия, версия, m, t, p, соль, nonce) + шифртекст.
func (l PasswordLayer) Seal(plain []byte) ([]byte, error) {
	if err := ValidateBackupPassword(l.Password); err != nil {
		return nil, err
	}
	pr := l.Params
	if pr == (ArgonParams{}) {
		pr = ProdArgonParams
	}
	if err := validateArgonParams(pr.MemoryKiB, pr.Time, pr.Threads); err != nil {
		return nil, err
	}
	hdr := make([]byte, pwHdrLen)
	copy(hdr, pwMagic)
	hdr[4] = pwVersion
	binary.BigEndian.PutUint32(hdr[5:9], pr.MemoryKiB)
	hdr[9], hdr[10] = pr.Time, pr.Threads
	if _, err := rand.Read(hdr[11:]); err != nil { // соль и nonce
		return nil, err
	}
	aead, err := chacha20poly1305.NewX(l.key(hdr[11:11+pwSaltLen], pr.MemoryKiB, pr.Time, pr.Threads))
	if err != nil {
		return nil, err
	}
	return aead.Seal(hdr, hdr[11+pwSaltLen:], plain, hdr), nil
}

// Open — любая неудача — ErrBackupWrongPassword (без различения причин).
func (l PasswordLayer) Open(sealed []byte) ([]byte, error) {
	if len(sealed) < pwHdrLen+chacha20poly1305.Overhead || string(sealed[:4]) != pwMagic || sealed[4] != pwVersion {
		return nil, ErrBackupWrongPassword
	}
	hdr := sealed[:pwHdrLen]
	m := binary.BigEndian.Uint32(hdr[5:9])
	t, p := hdr[9], hdr[10]
	// параметры — ДО вывода ключа: подмена «1 ТиБ памяти» не роняет машину
	if validateArgonParams(m, t, p) != nil {
		return nil, ErrBackupWrongPassword
	}
	aead, err := chacha20poly1305.NewX(l.key(hdr[11:11+pwSaltLen], m, t, p))
	if err != nil {
		return nil, ErrBackupWrongPassword
	}
	plain, err := aead.Open(nil, hdr[11+pwSaltLen:], sealed[pwHdrLen:], hdr)
	if err != nil {
		return nil, ErrBackupWrongPassword
	}
	return plain, nil
}

// BackupLayerOf — имя слоя файла копии (по заголовку, без расшифровки):
// чтобы спрашивать пароль только для зашифрованных копий.
func BackupLayerOf(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", notRead("файл не открыт: %v", err)
	}
	defer f.Close()
	head := make([]byte, 256)
	n, _ := f.Read(head)
	lines := bytes.SplitN(head[:n], []byte("\n"), 3)
	if len(lines) < 3 || !bytes.HasPrefix(lines[0], []byte(BackupMagic+" ")) || !bytes.HasPrefix(lines[1], []byte("layer ")) {
		return "", notRead("это не файл копии amnezia-admin")
	}
	return string(bytes.TrimPrefix(lines[1], []byte("layer "))), nil
}
