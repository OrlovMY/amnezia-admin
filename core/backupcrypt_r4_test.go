package core

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"testing"
)

// TestPasswordLayerUnique — SEC-01 р4: две записи одного текста одним
// паролем дают разные соль, nonce и шифртекст. Подмена «соль и nonce не
// заполняются» роняет тест.
func TestPasswordLayerUnique(t *testing.T) {
	l := pwLayer(testPassword)
	a, err1 := l.Seal([]byte("один и тот же текст"))
	b, err2 := l.Seal([]byte("один и тот же текст"))
	if err1 != nil || err2 != nil {
		t.Fatal(err1, err2)
	}
	salt := func(x []byte) []byte { return x[11 : 11+pwSaltLen] }
	nonce := func(x []byte) []byte { return x[11+pwSaltLen : pwHdrLen] }
	if bytes.Equal(salt(a), salt(b)) || bytes.Equal(nonce(a), nonce(b)) || bytes.Equal(a[pwHdrLen:], b[pwHdrLen:]) {
		t.Fatal("соль, nonce или шифртекст совпали у двух записей")
	}
	if bytes.Equal(salt(a), make([]byte, pwSaltLen)) || bytes.Equal(nonce(a), make([]byte, len(nonce(a)))) {
		t.Fatal("соль или nonce — нули")
	}
}

// TestPasswordNFC — SEC-01 Н-6: пароль в NFD и в NFC открывает одну копию
// (тест различения: другой пароль — не открывает).
func TestPasswordNFC(t *testing.T) {
	nfc := "пароль-йод-ёлка-12" // «й», «ё» — одной кодовой точкой
	nfd := strings.NewReplacer("й", "й", "ё", "ё").Replace(nfc)
	if nfc == nfd {
		t.Fatal("тест ничего не значит: NFD совпал с NFC")
	}
	sealed, err := pwLayer(nfc).Seal([]byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pwLayer(nfd).Open(sealed); err != nil {
		t.Errorf("NFD-форма того же пароля не открыла копию: %v", err)
	}
	sealed2, _ := pwLayer(nfd).Seal([]byte("x"))
	if _, err := pwLayer(nfc).Open(sealed2); err != nil {
		t.Errorf("NFC-форма не открыла копию, записанную в NFD: %v", err)
	}
	if _, err := pwLayer(nfc + "!").Open(sealed); !errors.Is(err, ErrBackupWrongPassword) {
		t.Errorf("другой пароль открыл: %v", err)
	}
}

// TestPasswordLayerTimeBound — SEC-01 Н-7: t > 16 в заголовке — «параметры
// копии вне допустимого» (до вывода ключа), и через DecodeBackup.
func TestPasswordLayerTimeBound(t *testing.T) {
	l := pwLayer(testPassword)
	sealed, _ := l.Seal([]byte(`{}`))
	bad := append([]byte(nil), sealed...)
	bad[9] = backupMaxArgonTime + 1
	if _, err := l.Open(bad); !errors.Is(err, ErrBackupParams) {
		t.Fatalf("t=%d: %v", bad[9], err)
	}
	ok := append([]byte(nil), sealed...)
	ok[9] = backupMaxArgonTime // граница допустима (дальше — неверный пароль из-за другого ключа)
	if _, err := l.Open(ok); errors.Is(err, ErrBackupParams) {
		t.Errorf("t=%d отвергнуто как вне допустимого", ok[9])
	}
	sum := sha256.Sum256(bad)
	file := []byte(fmt.Sprintf("AABK 1\nlayer %s\nsha256 %s\n\n", PasswordLayerName, hex.EncodeToString(sum[:])))
	file = append(file, bad...)
	if _, err := DecodeBackup(file, l); !errors.Is(err, ErrBackupNotRead) || !strings.Contains(err.Error(), "параметры копии вне допустимого") {
		t.Errorf("через DecodeBackup: %v", err)
	}
}
