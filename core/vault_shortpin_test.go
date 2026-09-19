package core

// Тупик хранилища со старым коротким пином (PR-A4, пункт 1).
//
// ЧТО ВОСПРОИЗВОДИТСЯ. До ужесточения политики пин мог быть короче 12
// символов. Такой файл OpenVault принимает намеренно (см. комментарий в
// vault.go у места расшифровки), но SealVault до PR-A4 прогонял пин через
// ValidatePin — и потому файл ОТКРЫВАЛСЯ, но НИКОГДА НЕ ЗАПЕЧАТЫВАЛСЯ
// обратно. Следствие для владельца: «Забыть ключ сервера» и запись нового
// отпечатка для таких файлов не работали никогда, а обнаружилось бы это в
// худший момент — когда ключ сервера уже сменился.
//
// ПОЧЕМУ ХРАНИЛИЩЕ БЕРЁТСЯ ИЗ testdata, А НЕ СОБИРАЕТСЯ ЗДЕСЬ. Собрать его
// в тесте можно только вызовом SealVaultExisting, которой на предыдущей
// ревизии не существует, — тест не скомпилировался бы там, а ошибка
// компиляции падением не считается (правило проекта). Файл
// testdata/shortpin.avlt запечатан 10-символьным пином теми же дешёвыми
// параметрами Argon2, что и прочие фикстуры, и на предыдущей ревизии тест
// компилируется и КРАСНЕЕТ по существу.
//
// ГРАНИЦА. Тест проверяет путь ForgetHostKey (core). Второй путь
// перезапечатывания — reseal в cmd/gui — закрыт отдельным тестом
// cmd/gui/reseal_shortpin_test.go.

import (
	"os"
	"path/filepath"
	"testing"
)

// shortFixturePin — пин, которым запечатан testdata/shortpin.avlt: 10
// символов, то есть КОРОЧЕ нынешнего порога ValidatePin (12).
const shortFixturePin = "shortPin12"

func loadShortPinVault(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "shortpin.avlt"))
	if err != nil {
		t.Fatalf("фикстура testdata/shortpin.avlt: %v", err)
	}
	path := filepath.Join(t.TempDir(), "old.avlt")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatalf("копия фикстуры: %v", err)
	}
	return path
}

// TestShortPinFixtureIsActuallyShort — фикстура обязана быть тем, чем её
// объявляют: открываться коротким пином, который нынешняя политика
// отвергает. Без этой проверки основной тест мог бы позеленеть по ошибке
// (например, если фикстуру когда-нибудь перезапечатают длинным пином).
func TestShortPinFixtureIsActuallyShort(t *testing.T) {
	if err := ValidatePin(shortFixturePin); err == nil {
		t.Fatalf("ValidatePin(%q) = nil — пин фикстуры перестал быть «старым коротким», тест ниже потерял смысл", shortFixturePin)
	}
	path := loadShortPinVault(t)
	data, err := LoadVault(path)
	if err != nil {
		t.Fatalf("LoadVault: %v", err)
	}
	payload, _, err := OpenVaultInfo(shortFixturePin, data)
	if err != nil {
		t.Fatalf("OpenVaultInfo коротким пином: %v (открытие обязано принимать пин любой длины)", err)
	}
	if payload.HostKeyFingerprint == "" {
		t.Fatal("в фикстуре обязан быть записан отпечаток ключа хоста — иначе забывать нечего")
	}
}

// TestForgetHostKeyOldShortPin — главный сторож пункта 1.
//
// СТОРОЖ САМОЙ ПОЧИНКИ: подмена, возвращающая ValidatePin в путь
// перезапечатывания (SealVaultExisting или ForgetHostKey), обязана уронить
// именно этот тест.
func TestForgetHostKeyOldShortPin(t *testing.T) {
	vaultPath := loadShortPinVault(t)
	knownHosts := filepath.Join(t.TempDir(), "known_hosts")

	if err := ForgetHostKey(shortFixturePin, vaultPath, knownHosts, "198.51.100.7:22"); err != nil {
		t.Fatalf("ForgetHostKey при верном коротком пине = %v, want nil "+
			"(перезапечатывание не применяет политику создания пина)", err)
	}

	// Доезд, а не только код возврата: файл на диске обязан открываться тем
	// же пином и уже без отпечатка.
	data, err := LoadVault(vaultPath)
	if err != nil {
		t.Fatalf("LoadVault после ForgetHostKey: %v", err)
	}
	payload, _, err := OpenVaultInfo(shortFixturePin, data)
	if err != nil {
		t.Fatalf("перезапечатанный файл не открывается тем же пином: %v", err)
	}
	if payload.HostKeyFingerprint != "" {
		t.Fatalf("HostKeyFingerprint = %q, want пусто", payload.HostKeyFingerprint)
	}
	if payload.Key == "" || payload.Label == "" {
		t.Fatal("перезапечатывание потеряло содержимое хранилища")
	}
}
