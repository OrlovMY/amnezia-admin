package main

import (
	"bytes"
	"strings"
	"testing"

	"amnezia-admin/core"
)

// Ревью A4в, UX-01: блокирующие 2 и 3.
//
// ОБА ТЕСТА КРАСНЕЮТ НА ПРЕДЫДУЩЕЙ РЕВИЗИИ (42eafbd) ПОВЕДЕНЧЕСКИ: они зовут
// saveUserConfig, существовавшую там с той же сигнатурой, и смотрят только на
// напечатанный текст. Ни одного нового имени тут нет — падение не сборочное.

// TestSaveUserConfigTellsWhatToDoWhenSaveFails — блокирующее 2. К этому месту
// пользователь на сервере уже создан, а конфиг живёт только в памяти. Отказ
// без объяснения = потерянные ключи клиента.
func TestSaveUserConfigTellsWhatToDoWhenSaveFails(t *testing.T) {
	// Гасим все три источника каталога данных — на любой ОС получаем отказ.
	t.Setenv("LOCALAPPDATA", "")
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("HOME", "")

	u := &core.NewUser{Name: "Вася", IP: "10.8.1.7", Config: "СЕКРЕТНЫЙ-КЛЮЧ-КЛИЕНТА"}
	var buf bytes.Buffer
	err := saveUserConfig(&buf, u, "awg")
	if err == nil {
		t.Fatal("каталог определить нельзя, а сохранение отчиталось успехом")
	}
	out := buf.String()
	for _, want := range []string{
		"на сервере создан",    // пользователь уже есть — это главное
		"сохранить не удалось", // и конфига нет
		"rekey",                // чем чинить: команда названа точно
		"Перевыпустить конфиг", // и пункт интерактивного меню
		"работать не будет",    // и цена перевыпуска
	} {
		if !strings.Contains(out, want) {
			t.Errorf("в выводе нет %q — человек не знает, что делать. Вывод:\n%s", want, out)
		}
	}
	// И ни при каких обстоятельствах — сам конфиг: это приватный ключ
	// клиента. Решение печатать его принимает владелец, не программа.
	if strings.Contains(out, u.Config) || strings.Contains(err.Error(), u.Config) {
		t.Error("конфиг клиента напечатан в выводе или в тексте ошибки")
	}
}

// TestSaveUserConfigShowsMoveHintOnceOnFirstSave — блокирующее 3. Подсказка о
// смене места показывается РОВНО ОДИН РАЗ: при первом сохранении, когда
// каталога ещё не было.
func TestSaveUserConfigShowsMoveHintOnceOnFirstSave(t *testing.T) {
	fakeUserDataBaseCLI(t)
	t.Chdir(t.TempDir())

	u := &core.NewUser{Name: "Вася", IP: "10.8.1.7", Config: "[Interface]\n"}

	var first bytes.Buffer
	if err := saveUserConfig(&first, u, "awg"); err != nil {
		t.Fatalf("первое сохранение: %v", err)
	}
	if !strings.Contains(first.String(), "Прежние версии сохраняли") {
		t.Errorf("при первом сохранении нет подсказки о смене места. Вывод:\n%s", first.String())
	}

	var second bytes.Buffer
	if err := saveUserConfig(&second, u, "awg"); err != nil {
		t.Fatalf("второе сохранение: %v", err)
	}
	if strings.Contains(second.String(), "Прежние версии сохраняли") {
		t.Errorf("подсказка повторилась при втором сохранении — она одноразовая. Вывод:\n%s", second.String())
	}
}
