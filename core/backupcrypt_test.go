package core

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"amnezia-admin/internal/fakesrv"
)

var testArgon = ArgonParams{MemoryKiB: 64, Time: 1, Threads: 1}

const testPassword = "правильный-пароль-копии"

func pwLayer(pw string) PasswordLayer {
	return PasswordLayer{Password: NewSecret([]byte(pw)), Params: testArgon}
}

func encBackup(t *testing.T) (*Backup, []byte) {
	t.Helper()
	b, err := backupSession(t, fakesrv.New()).CollectBackup("t", backupNow, okResolver)
	if err != nil {
		t.Fatal(err)
	}
	data, err := EncodeBackup(b, pwLayer(testPassword))
	if err != nil {
		t.Fatal(err)
	}
	return b, data
}

// TestPasswordLayerRoundTrip — круг с паролем; слой назван в заголовке;
// манифест в файле не читается открытым текстом.
func TestPasswordLayerRoundTrip(t *testing.T) {
	b, data := encBackup(t)
	if !bytes.Contains(data, []byte("layer "+PasswordLayerName+"\n")) {
		t.Fatal("слой не назван в заголовке")
	}
	if bytes.Contains(data, []byte(`"containers"`)) || bytes.Contains(data, []byte("amnezia-awg")) {
		t.Fatal("манифест в файле открытым текстом")
	}
	got, err := DecodeBackup(data, PlainLayer{}, pwLayer(testPassword))
	if err != nil || len(got.Containers) != len(b.Containers) {
		t.Fatalf("не прочитана своим паролем: %v", err)
	}
}

// TestPasswordLayerWrongPassword — неверный пароль: «копия не прочитана:
// неверный пароль или файл повреждён», результата нет.
func TestPasswordLayerWrongPassword(t *testing.T) {
	_, data := encBackup(t)
	got, err := DecodeBackup(data, pwLayer("другой-пароль-копии"))
	if got != nil || !errors.Is(err, ErrBackupNotRead) || !errors.Is(err, ErrBackupWrongPassword) ||
		!strings.Contains(err.Error(), "копия не прочитана: неверный пароль или файл повреждён") {
		t.Fatalf("неверный пароль: %v (результат %v)", err, got != nil)
	}
}

// TestPasswordLayerEveryByte — порча КАЖДОГО байта файла (заголовок файла,
// заголовок слоя, шифртекст) — отказ без результата; в теле — то же
// сообщение, что у неверного пароля.
func TestPasswordLayerEveryByte(t *testing.T) {
	_, data := encBackup(t)
	bodyStart := bytes.Index(data, []byte("\n\n")) + 2
	for i := range data {
		bad := append([]byte(nil), data...)
		bad[i] ^= 0x01
		got, err := DecodeBackup(bad, PlainLayer{}, pwLayer(testPassword))
		if got != nil || !errors.Is(err, ErrBackupNotRead) {
			t.Fatalf("байт %d: прочитано (%v)", i, err)
		}
		if i >= bodyStart && !errors.Is(err, ErrBackupWrongPassword) {
			t.Fatalf("байт тела %d: сообщение отличается от неверного пароля: %v", i, err)
		}
	}
}

// TestPasswordLayerHeaderTamper — подменённые параметры или соль в заголовке
// слоя (при пересчитанной внешней сумме) — отказ; «бомба» памяти — отказ
// ДО вывода ключа.
func TestPasswordLayerHeaderTamper(t *testing.T) {
	l := pwLayer(testPassword)
	sealed, err := l.Seal([]byte(`{"x":1}`))
	if err != nil {
		t.Fatal(err)
	}
	for _, i := range []int{5, 9, 10, 11, 11 + pwSaltLen} {
		bad := append([]byte(nil), sealed...)
		bad[i] ^= 0x01
		if _, err := l.Open(bad); !errors.Is(err, ErrBackupWrongPassword) {
			t.Errorf("байт заголовка слоя %d: %v", i, err)
		}
	}
	bomb := append([]byte(nil), sealed...)
	binary.BigEndian.PutUint32(bomb[5:9], 1<<31)
	if _, err := l.Open(bomb); !errors.Is(err, ErrBackupWrongPassword) {
		t.Errorf("параметры памяти вне границ: %v", err)
	}
}

// TestBackupPasswordRules — пароль короче 12 символов не принимается (в
// символах, не байтах); пароль не печатается ни одним глаголом.
func TestBackupPasswordRules(t *testing.T) {
	if ValidateBackupPassword(NewSecret([]byte("короткий123"))) == nil {
		t.Error("11 символов приняты")
	}
	if ValidateBackupPassword(NewSecret([]byte("двенадцать12"))) != nil {
		t.Error("12 символов отвергнуты")
	}
	if _, err := pwLayer("short").Seal([]byte("x")); err == nil {
		t.Error("короткий пароль принят при шифровании")
	}
	l := pwLayer(testPassword)
	for _, v := range []any{l, &l, l.Password, []PasswordLayer{l}} {
		for _, verb := range allVerbs {
			if out := fmt.Sprintf(verb, v); strings.Contains(out, testPassword) || strings.Contains(out, "правильный") {
				t.Fatalf("пароль в выводе %s: %.80s", verb, out)
			}
		}
	}
	_, err := DecodeBackup([]byte("AABK 1\nlayer "+PasswordLayerName+"\nsha256 00\n\nxx"), l)
	if err == nil || strings.Contains(err.Error(), testPassword) {
		t.Errorf("пароль в тексте ошибки: %v", err)
	}
}

// TestBackupGoldenEncrypted — золотой зашифрованный файл формата 1
// читается паролем «golden-test-password» (будущие версии обязаны его
// читать). Обновление: AMNEZIA_BACKUP_GOLDEN=1.
func TestBackupGoldenEncrypted(t *testing.T) {
	p := filepath.Join("testdata", "v1-password.aabk")
	gl := PasswordLayer{Password: NewSecret([]byte("golden-test-password")), Params: testArgon}
	if os.Getenv("AMNEZIA_BACKUP_GOLDEN") == "1" {
		srv := fakesrv.New()
		srv.SetFile("/opt/amnezia/awg/wireguard_psk.key", []byte("golden-test-psk\n"))
		b, err := NewSessionWithRunner(srv, &ServerCreds{Host: "golden.example.test"}).CollectBackup("golden", backupNow, okResolver)
		if err != nil {
			t.Fatal(err)
		}
		data, _ := EncodeBackup(b, gl)
		if err := os.WriteFile(p, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if l, err := BackupLayerOf(p); err != nil || l != PasswordLayerName {
		t.Fatalf("слой золотого файла: %q %v", l, err)
	}
	b, err := ReadBackupFile(p, PlainLayer{}, gl)
	if err != nil {
		t.Fatalf("золотой зашифрованный файл не прочитан: %v", err)
	}
	if f := fileOfB(ctrOf(t, b, "amnezia-awg"), "wireguard_psk.key"); string(f.Data.Bytes()) != "golden-test-psk\n" {
		t.Errorf("содержимое золотого файла: %s", f.Status)
	}
	if _, err := ReadBackupFile(p, PlainLayer{}, PasswordLayer{Password: NewSecret([]byte("неверный-пароль!!"))}); !errors.Is(err, ErrBackupWrongPassword) {
		t.Errorf("золотой файл с неверным паролем: %v", err)
	}
}
