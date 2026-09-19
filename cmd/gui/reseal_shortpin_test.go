package main

// Второй путь перезапечатывания (PR-A4, пункт 1): reseal в GUI — запись
// отпечатка ключа сервера в уже открытое хранилище.
//
// Тупик тот же, что в core: файл со старым коротким пином открывается, но до
// PR-A4 не запечатывался обратно — значит новый отпечаток в него не
// записывался НИКОГДА. Файл-фикстура общий с core-тестом
// (core/testdata/shortpin.avlt), пин — 10 символов.
//
// Файл намеренно обходится API, существующим и до починки (core.SealVault
// внутри reseal), чтобы падать по существу, а не ошибкой компиляции.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"amnezia-admin/core"
)

func TestResealOldShortPin(t *testing.T) {
	const pin = "shortPin12"
	if err := core.ValidatePin(pin); err == nil {
		t.Fatalf("ValidatePin(%q) = nil — фикстура перестала быть «старым коротким пином»", pin)
	}

	data, err := os.ReadFile(filepath.Join("..", "..", "core", "testdata", "shortpin.avlt"))
	if err != nil {
		t.Fatalf("фикстура: %v", err)
	}
	path := filepath.Join(t.TempDir(), "old.avlt")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatalf("копия фикстуры: %v", err)
	}
	payload, info, err := core.OpenVaultInfo(pin, data)
	if err != nil {
		t.Fatalf("OpenVaultInfo: %v", err)
	}

	p := pin
	vc := &vaultCtx{path: path, pin: &p, info: info, payload: payload}
	const newFP = "SHA256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
	if err := reseal(vc, newFP); err != nil {
		t.Fatalf("reseal при верном коротком пине = %v, want nil", err)
	}

	// Доезд: файл на диске действительно перезаписан и открывается тем же пином.
	back, err := core.LoadVault(path)
	if err != nil {
		t.Fatalf("LoadVault: %v", err)
	}
	got, _, err := core.OpenVaultInfo(pin, back)
	if err != nil {
		t.Fatalf("перезапечатанный файл не открывается тем же пином: %v", err)
	}
	if got.HostKeyFingerprint != newFP {
		t.Fatalf("HostKeyFingerprint = %q, want %q", got.HostKeyFingerprint, newFP)
	}
}

// TestResealRejectsEmptyPin — вторая половина запрета пустого пина (ревью
// SEC-01): reseal проверял только vc.pin == nil, а пин обнуляется сразу
// после использования, то есть пустая строка сюда доезжает штатным путём.
// ПОЧЕМУ ПРОВЕРЯЕТСЯ ТЕКСТ ОШИБКИ, А НЕ ПРОСТО «ошибка не nil». Защит две, и
// они дублируют друг друга намеренно: если снять проверку здесь, откажет
// граница в core.SealVaultExisting, и тест на «err != nil» остался бы
// зелёным — то есть сторожил бы не то место. Поэтому тест требует, чтобы
// отказал ИМЕННО reseal, своим текстом. Подмена, возвращающая условие к
// одному vc.pin == nil, обязана уронить этот тест.
func TestResealRejectsEmptyPin(t *testing.T) {
	empty := ""
	vc := &vaultCtx{path: filepath.Join(t.TempDir(), "нет.avlt"), pin: &empty}
	err := reseal(vc, "SHA256:ccc")
	if err == nil {
		t.Fatal("reseal с пустым пином = nil, want ошибка")
	}
	if !strings.Contains(err.Error(), "пин недоступен") {
		t.Fatalf("отказал не reseal, а кто-то ниже: %v — проверка пустого пина в reseal не работает", err)
	}
	// Файл не создан: ни одна ветка не записала хранилище.
	if _, err := os.Stat(vc.path); err == nil {
		t.Fatal("reseal с пустым пином создал файл хранилища")
	}
}
