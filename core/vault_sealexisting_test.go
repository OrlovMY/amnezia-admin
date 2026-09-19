package core

// Две стороны починки PR-A4 в одном месте: политика пина осталась там, где
// пин ЗАДАЁТСЯ, и ушла оттуда, где файл ПЕРЕЗАПИСЫВАЕТСЯ.
//
// ПОЧЕМУ ОТДЕЛЬНЫЙ ФАЙЛ ОТ vault_shortpin_test.go. Здесь вызывается
// SealVaultExisting, которой на предыдущей ревизии нет, — этот файл там не
// компилируется. Соседний файл с главным покраснением намеренно обходится
// старым API, чтобы падать по существу, а не ошибкой компиляции.

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// TestSealVaultStillRejectsNewShortPin — подмена, убирающая ValidatePin из
// SealVault, обязана уронить этот тест.
func TestSealVaultStillRejectsNewShortPin(t *testing.T) {
	cases := []struct {
		name string
		pin  string
	}{
		{"короткий", "short1"},
		{"ровно 11 символов", "abcdefgh123"},
		{"12 символов без цифр", "abcdefghijkl"},
		{"кириллица", "парольПароль1"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := SealVault(c.pin, VaultPayload{Key: "vpn://x"}, testArgonParams, false); err == nil {
				t.Fatalf("SealVault(%q) = nil, want ошибка политики пина", c.pin)
			}
		})
	}
}

// TestSealVaultExistingIgnoresPinPolicy — тот же короткий пин через
// SealVaultExisting обязан работать и давать файл, который открывается им
// же. Иначе различие двух путей существует только на словах.
func TestSealVaultExistingIgnoresPinPolicy(t *testing.T) {
	const pin = "short1"
	if err := ValidatePin(pin); err == nil {
		t.Fatalf("ValidatePin(%q) = nil — пин перестал быть «недопустимым для задания», тест потерял смысл", pin)
	}
	payload := VaultPayload{Label: "старое", Key: "vpn://x", HostKeyFingerprint: "SHA256:zzz"}
	data, err := SealVaultExisting(pin, payload, testArgonParams, false)
	if err != nil {
		t.Fatalf("SealVaultExisting(короткий пин) = %v, want nil", err)
	}
	got, _, err := OpenVaultInfo(pin, data)
	if err != nil {
		t.Fatalf("OpenVaultInfo: %v", err)
	}
	if got.Key != payload.Key || got.HostKeyFingerprint != payload.HostKeyFingerprint {
		t.Fatalf("содержимое не доехало: %+v", got)
	}
}

// TestSealVaultExistingRejectsEmptyPin — пустой пин на границе (ревью
// SEC-01). До PR-A4 последним рубежом против "" был ValidatePin внутри
// SealVault; после разведения путей его не стало, и инвариант держался
// только на порядке строк в вызывающем. Цена ошибки: файл, запечатанный
// пустым пином, потом молча открывается — OpenVault политику не применяет.
//
// Подмена, снимающая проверку pin == "" в SealVaultExisting, обязана уронить
// этот тест.
func TestSealVaultExistingRejectsEmptyPin(t *testing.T) {
	if _, err := SealVaultExisting("", VaultPayload{Key: "vpn://x"}, testArgonParams, false); err == nil {
		t.Fatal("SealVaultExisting(\"\") = nil, want ошибка: пустым пином хранилище запечатывать нельзя")
	}
	// Различение: дело именно в пустоте, а не в «коротком» вообще — пин из
	// одного символа по-прежнему проходит (перезапечатывание не применяет
	// политику создания пина).
	if _, err := SealVaultExisting("x", VaultPayload{Key: "vpn://x"}, testArgonParams, false); err != nil {
		t.Fatalf("SealVaultExisting(\"x\") = %v, want nil — запрет обязан касаться только пустого пина", err)
	}
}

// TestForgetHostKeyRejectsEmptyPin — доезд того же запрета боевым путём:
// пустой пин не должен доходить до записи файла. Здесь он не доходит даже до
// SealVaultExisting (файл не открывается), и это тоже результат: ни одна
// ветка не записывает хранилище.
func TestForgetHostKeyRejectsEmptyPin(t *testing.T) {
	vaultPath := loadShortPinVault(t)
	before, err := os.ReadFile(vaultPath)
	if err != nil {
		t.Fatalf("чтение до: %v", err)
	}
	if err := ForgetHostKey("", vaultPath, filepath.Join(t.TempDir(), "known_hosts"), "198.51.100.7:22"); err == nil {
		t.Fatal("ForgetHostKey с пустым пином = nil, want ошибка")
	}
	after, err := os.ReadFile(vaultPath)
	if err != nil {
		t.Fatalf("чтение после: %v", err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("хранилище изменилось при пустом пине — этого не должно случиться ни на одной ветке")
	}
}
