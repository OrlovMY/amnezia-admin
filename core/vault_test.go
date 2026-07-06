package core

import (
	"encoding/binary"
	"errors"
	"os"
	"runtime"
	"strings"
	"testing"
)

// testArgonParams — облегчённые параметры Argon2id для тестов (не 256 MiB/1с)
var testArgonParams = ArgonParams{MemoryKiB: 8192, Time: 1, Threads: 1}

func TestSealOpenRoundtrip(t *testing.T) {
	payload := VaultPayload{Label: "Test", Key: "vpn://abc", Created: "2024-01-01T00:00:00Z"}
	data, err := SealVault("goodPin12345", payload, testArgonParams, false)
	if err != nil {
		t.Fatalf("SealVault: %v", err)
	}
	got, err := OpenVault("goodPin12345", data)
	if err != nil {
		t.Fatalf("OpenVault: %v", err)
	}
	if got != payload {
		t.Errorf("got %+v, want %+v", got, payload)
	}
}

// TestPinIsNotTrimmed — регресс на "пин не тримится": пробел (\x20) теперь
// валидный символ пина, поэтому пин с ведущим/хвостовым пробелом должен
// расшифровывать только при ТОЧНОМ совпадении, а не после implicit trim.
func TestPinIsNotTrimmed(t *testing.T) {
	payload := VaultPayload{Label: "Test", Key: "vpn://abc", Created: "2024-01-01T00:00:00Z"}
	pinWithSpaces := " pass1234ab "
	if err := ValidatePin(pinWithSpaces); err != nil {
		t.Fatalf("ValidatePin(%q) = %v, want nil (пробел — валидный символ)", pinWithSpaces, err)
	}
	data, err := SealVault(pinWithSpaces, payload, testArgonParams, false)
	if err != nil {
		t.Fatalf("SealVault: %v", err)
	}

	// точное совпадение — открывается
	if _, err := OpenVault(pinWithSpaces, data); err != nil {
		t.Fatalf("OpenVault с точным пином: %v", err)
	}

	// тримленный вариант — НЕ должен подойти (иначе пин был бы неявно тримирован)
	trimmed := strings.TrimSpace(pinWithSpaces)
	if _, err := OpenVault(trimmed, data); err == nil {
		t.Fatal("OpenVault с тримленным пином не должен открыть файл, зашифрованный пином с пробелами")
	}

	// та же длина (12), пробел только с одной стороны — другой пин, тоже не подходит
	leadingOnly := " pass1234abc"  // пробел спереди, без пробела сзади
	trailingOnly := "pass1234abc " // пробел сзади, без пробела спереди
	if err := ValidatePin(leadingOnly); err != nil {
		t.Fatalf("ValidatePin(%q) = %v, want nil", leadingOnly, err)
	}
	if err := ValidatePin(trailingOnly); err != nil {
		t.Fatalf("ValidatePin(%q) = %v, want nil", trailingOnly, err)
	}
	if _, err := OpenVault(leadingOnly, data); err == nil {
		t.Fatal("пин без хвостового пробела не должен подходить к файлу, зашифрованному пином с пробелами с обеих сторон")
	}
	if _, err := OpenVault(trailingOnly, data); err == nil {
		t.Fatal("пин без ведущего пробела не должен подходить к файлу, зашифрованному пином с пробелами с обеих сторон")
	}
}

func TestOpenVaultWrongPin(t *testing.T) {
	payload := VaultPayload{Label: "Test", Key: "vpn://abc", Created: "2024-01-01T00:00:00Z"}
	data, err := SealVault("correctPin12", payload, testArgonParams, false)
	if err != nil {
		t.Fatalf("SealVault: %v", err)
	}
	_, err = OpenVault("wrongPin999", data)
	if err == nil {
		t.Fatal("expected error for wrong pin")
	}
	if err.Error() != ErrVaultBadPinOrCorrupt.Error() {
		t.Errorf("err = %q, want %q (текст неверного пина и порчи должен совпадать)", err.Error(), ErrVaultBadPinOrCorrupt.Error())
	}
}

func TestOpenVaultCorruption(t *testing.T) {
	payload := VaultPayload{Label: "Test", Key: "vpn://abc", Created: "2024-01-01T00:00:00Z"}
	pin := "correctPin12"
	base, err := SealVault(pin, payload, testArgonParams, false)
	if err != nil {
		t.Fatalf("SealVault: %v", err)
	}

	corrupt := func(name string, mutate func([]byte) []byte) {
		t.Run(name, func(t *testing.T) {
			cp := append([]byte(nil), base...)
			cp = mutate(cp)
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("паника при открытии повреждённого файла: %v", r)
				}
			}()
			_, err := OpenVault(pin, cp)
			if err == nil {
				t.Fatal("expected error for corrupted data")
			}
		})
	}

	corrupt("magic", func(b []byte) []byte { b[0] ^= 0xFF; return b })
	corrupt("version", func(b []byte) []byte { b[4] = 99; return b })
	corrupt("flags", func(b []byte) []byte { b[5] ^= 0xFF; return b })
	corrupt("argon params", func(b []byte) []byte { b[6] ^= 0xFF; return b })
	corrupt("salt", func(b []byte) []byte { b[12] ^= 0xFF; return b })
	corrupt("nonce", func(b []byte) []byte {
		// nonce начинается после fixed header (dpapiBlobLen=0, значит сразу после)
		b[vaultFixedHeaderLen] ^= 0xFF
		return b
	})
	corrupt("truncated tail", func(b []byte) []byte {
		if len(b) < 5 {
			return b
		}
		return b[:len(b)-5]
	})

	t.Run("empty file", func(t *testing.T) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("паника на пустом файле: %v", r)
			}
		}()
		_, err := OpenVault(pin, nil)
		if err == nil {
			t.Fatal("expected error for empty data")
		}
	})
}

func TestOpenVaultUnknownVersion(t *testing.T) {
	payload := VaultPayload{Label: "Test", Key: "vpn://abc", Created: "2024-01-01T00:00:00Z"}
	pin := "correctPin12"
	data, err := SealVault(pin, payload, testArgonParams, false)
	if err != nil {
		t.Fatalf("SealVault: %v", err)
	}
	cp := append([]byte(nil), data...)
	cp[4] = vaultVersion + 1
	_, err = OpenVault(pin, cp)
	if err == nil {
		t.Fatal("expected error for unknown (newer) version")
	}
	if err.Error() != ErrVaultNewerVersion.Error() {
		t.Errorf("err = %q, want %q", err.Error(), ErrVaultNewerVersion.Error())
	}
}

func TestValidatePin(t *testing.T) {
	// спецсимволы и пробел внутри РАЗРЕШЕНЫ (усиливают пин) — валидны, если
	// есть и буква, и цифра, и длина >= 12
	valid := []string{
		"abc123456789",  // ровно 12 символов
		"Password1234",  // 12
		"1234567890ab",  // 12
		"Passw0rd!!!!",  // 12, со спецсимволами
		`a1!"#$%^&*()_`, // 13, спецсимволы
		"P@ssw0rd!!!!",  // 12
		"a1 b2 c3 d4 e5", // 14, с пробелами внутри
	}
	for _, p := range valid {
		if err := ValidatePin(p); err != nil {
			t.Errorf("ValidatePin(%q) = %v, want nil", p, err)
		}
	}

	invalid := []string{
		"abc12345678",   // 11 символов, короче 12 (было валидно при пороге 10/11)
		"abc123456",     // 9 символов
		"abcdefghijkl",  // только буквы, 12 символов
		"123456789012",  // только цифры, 12 символов
		"пароль123456",  // кириллица запрещена
		"abc1234567\n8", // управляющий символ (\n)
		"abc1234567\t8", // управляющий символ (\t)
	}
	for _, p := range invalid {
		if err := ValidatePin(p); err == nil {
			t.Errorf("ValidatePin(%q) = nil, want error", p)
		}
	}
}

// TestGoldenVault проверяет обратную совместимость: файл testdata/v1.avlt
// был один раз создан SealVault с параметрами testArgonParams, пином
// "golden1234" и payload {Label: "Golden Server", Key: "vpn://golden-fixture-key", ...}.
// Этот тест только читает и открывает его — так фиксируется формат файла.
func TestGoldenVault(t *testing.T) {
	data, err := os.ReadFile("testdata/v1.avlt")
	if err != nil {
		t.Fatalf("не удалось прочитать golden-файл: %v", err)
	}
	got, err := OpenVault("golden1234", data)
	if err != nil {
		t.Fatalf("OpenVault(golden): %v", err)
	}
	want := VaultPayload{Label: "Golden Server", Key: "vpn://golden-fixture-key", Created: "2024-01-01T00:00:00Z"}
	if got != want {
		t.Errorf("got %+v, want %+v", got, want)
	}
	// version=1 никогда не должна давать ErrVaultNewerVersion, независимо от
	// исхода (верный пин выше уже проверен; здесь же проверяем и неверный)
	_, err = OpenVault("wrong-pin-99", data)
	if err == nil {
		t.Fatal("expected error for wrong pin on golden file")
	}
	if errors.Is(err, ErrVaultNewerVersion) {
		t.Errorf("v1-файл не должен давать ErrVaultNewerVersion, получено: %v", err)
	}
}

// TestOpenVaultMaliciousArgonParams проверяет, что заведомо неадекватные
// параметры Argon2 из заголовка (огромная память, нулевые time/threads)
// отклоняются ДО вызова argon2.IDKey — иначе argon2.IDKey попытается
// выделить и обнулить ~4 TiB памяти (0xFFFFFFFF KiB), что на практике либо
// зависает, либо валит процесс по OOM. Тест не должен реально выделять
// эту память — если валидация не сработает, тест эффективно повиснет/упадёт,
// что и является сигналом регресса.
func TestOpenVaultMaliciousArgonParams(t *testing.T) {
	payload := VaultPayload{Label: "Test", Key: "vpn://abc", Created: "2024-01-01T00:00:00Z"}
	pin := "correctPin12"
	base, err := SealVault(pin, payload, testArgonParams, false)
	if err != nil {
		t.Fatalf("SealVault: %v", err)
	}

	t.Run("huge memory", func(t *testing.T) {
		cp := append([]byte(nil), base...)
		binary.LittleEndian.PutUint32(cp[6:10], 0xFFFFFFFF)
		assertNoPanicError(t, pin, cp)
	})

	t.Run("zero time", func(t *testing.T) {
		cp := append([]byte(nil), base...)
		cp[10] = 0 // argonTime
		assertNoPanicError(t, pin, cp)
	})

	t.Run("zero threads", func(t *testing.T) {
		cp := append([]byte(nil), base...)
		cp[11] = 0 // argonThreads
		assertNoPanicError(t, pin, cp)
	})

	t.Run("all malicious at once", func(t *testing.T) {
		cp := append([]byte(nil), base...)
		binary.LittleEndian.PutUint32(cp[6:10], 0xFFFFFFFF)
		cp[10] = 0
		cp[11] = 0
		assertNoPanicError(t, pin, cp)
	})
}

func assertNoPanicError(t *testing.T, pin string, data []byte) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("паника на злонамеренных параметрах Argon2: %v", r)
		}
	}()
	_, err := OpenVault(pin, data)
	if err == nil {
		t.Fatal("expected error for malicious Argon2 params")
	}
	if err.Error() != ErrVaultBadPinOrCorrupt.Error() {
		t.Errorf("err = %q, want %q", err.Error(), ErrVaultBadPinOrCorrupt.Error())
	}
}

// TestOpenVaultCorruptedDpapiBlobLen проверяет, что раздутое поле
// dpapiBlobLen (65535) на коротком файле не приводит к панике при попытке
// прочитать несуществующий хвост данных.
func TestOpenVaultCorruptedDpapiBlobLen(t *testing.T) {
	payload := VaultPayload{Label: "Test", Key: "vpn://abc", Created: "2024-01-01T00:00:00Z"}
	pin := "correctPin12"
	base, err := SealVault(pin, payload, testArgonParams, false)
	if err != nil {
		t.Fatalf("SealVault: %v", err)
	}
	cp := append([]byte(nil), base...)
	// dpapiBlobLen — поле u16 сразу после salt, т.е. в byte-offset
	// vaultFixedHeaderLen-2 .. vaultFixedHeaderLen (см. формат в vault.go)
	binary.LittleEndian.PutUint16(cp[vaultFixedHeaderLen-2:vaultFixedHeaderLen], 65535)

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("паника при испорченном dpapiBlobLen: %v", r)
		}
	}()
	_, err = OpenVault(pin, cp)
	if err == nil {
		t.Fatal("expected error for corrupted dpapiBlobLen")
	}
}

// TestMachineBindRoundtrip — DPAPI работает только на Windows; на других ОС
// SealVault(machineBind=true) должен явно сообщать о недоступности.
func TestMachineBindRoundtrip(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("DPAPI доступен только на Windows")
	}
	payload := VaultPayload{Label: "Bound", Key: "vpn://bound", Created: "2024-01-01T00:00:00Z"}
	data, err := SealVault("boundPin1234", payload, testArgonParams, true)
	if err != nil {
		t.Fatalf("SealVault(machineBind): %v", err)
	}
	got, err := OpenVault("boundPin1234", data)
	if err != nil {
		t.Fatalf("OpenVault(machineBind): %v", err)
	}
	if got != payload {
		t.Errorf("got %+v, want %+v", got, payload)
	}
}

func TestMachineBindUnavailableOnNonWindows(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("тест только для не-Windows")
	}
	payload := VaultPayload{Label: "Bound", Key: "vpn://bound", Created: "2024-01-01T00:00:00Z"}
	_, err := SealVault("boundPin1234", payload, testArgonParams, true)
	if err == nil {
		t.Fatal("expected error: machine-bind недоступен на этой ОС")
	}
}
