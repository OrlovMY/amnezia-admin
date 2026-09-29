package main

import (
	"bytes"
	"fmt"
	"os"
	"strings"
	"testing"

	"amnezia-admin/core"
)

// captureStdout перехватывает os.Stdout — printErr печатает именно туда.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	orig := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	os.Stdout = w
	done := make(chan string, 1)
	go func() {
		var b bytes.Buffer
		_, _ = b.ReadFrom(r)
		done <- b.String()
	}()
	fn()
	w.Close()
	os.Stdout = orig
	return <-done
}

// TestResolveInteractiveReachesHuman — тест ДОЕЗДА (CLAUDE.md): третье
// состояние должно возникать боевым путём и доходить до печати, а не
// существовать только внутри core. Проверяем ровно тот код, который вызывают
// пункты меню «удалить/переименовать/отключить/перевыпустить».
func TestResolveInteractiveReachesHuman(t *testing.T) {
	var many []core.ClientEntry
	for i := 1; i <= 12; i++ {
		name := fmt.Sprintf("user%d", i)
		if i == 1 {
			name = "12"
		}
		many = append(many, core.ClientEntry{
			ClientID: fmt.Sprintf("key%d", i),
			UserData: map[string]any{"clientName": name},
		})
	}
	dup := []core.ClientEntry{
		{ClientID: "pkA", UserData: map[string]any{"clientName": "Дубль"}},
		{ClientID: "pkB", UserData: map[string]any{"clientName": "Дубль"}},
	}

	t.Run("неоднозначность останавливает действие и печатает перечень", func(t *testing.T) {
		// printErr пишет в os.Stdout, а Note — в переданный writer;
		// собираем оба, иначе проверка смотрит только на половину вывода.
		var idx int
		var note bytes.Buffer
		out := captureStdout(t, func() {
			idx = resolveInteractive(&note, dup, "Дубль")
		}) + note.String()
		if idx >= 0 {
			t.Fatalf("idx = %d — действие по первому совпадению НЕ должно состояться", idx)
		}
		for _, want := range []string{"несколько", "pkA", "pkB"} {
			if !strings.Contains(out, want) {
				t.Errorf("вывод не содержит %q:\n%s", want, out)
			}
		}
		if strings.Contains(out, "не найден") {
			t.Errorf("неоднозначность выдана человеку за «не найдено»:\n%s", out)
		}
	})

	t.Run("не найдено — свой текст", func(t *testing.T) {
		var idx int
		var note bytes.Buffer
		out := captureStdout(t, func() {
			idx = resolveInteractive(&note, many, "нет-такого")
		}) + note.String()
		if idx >= 0 {
			t.Fatalf("idx = %d, want -1", idx)
		}
		if !strings.Contains(out, "не найден") {
			t.Errorf("вывод не содержит «не найден»:\n%s", out)
		}
		if strings.Contains(out, "несколько") {
			t.Errorf("«не найдено» выдано за неоднозначность:\n%s", out)
		}
	})

	t.Run("имя главнее номера — и человек об этом слышит", func(t *testing.T) {
		var buf bytes.Buffer
		idx := resolveInteractive(&buf, many, "12")
		if idx != 0 {
			t.Fatalf("idx = %d, want 0 (клиент с именем \"12\"), — имя главнее номера", idx)
		}
		note := buf.String()
		if note == "" {
			t.Fatal("человеку не сказали, кого поняли: пусто")
		}
		if !strings.Contains(note, "ИМЯ") {
			t.Errorf("в сообщении не сказано, что понято как имя: %q", note)
		}
	})

	t.Run("номер строки с решёткой — молча", func(t *testing.T) {
		var buf bytes.Buffer
		idx := resolveInteractive(&buf, many, "#5")
		if idx != 4 {
			t.Fatalf("idx = %d, want 4", idx)
		}
		if buf.String() != "" {
			t.Errorf("лишнее сообщение на однозначном вводе: %q", buf.String())
		}
	})
}

// TestResolveByFlagReachesHuman — доезд для ФЛАГОВОГО пути (A8 круг 2,
// ревью BE-01/QA-01 M13). Именно эту обёртку зовут del/rename/toggle/rekey
// и их -dry-run. У rename карточки подтверждения нет вовсе: если Note не
// напечатана здесь, человек не увидит ДО действия ничего.
func TestResolveByFlagReachesHuman(t *testing.T) {
	digits := []core.ClientEntry{
		{ClientID: "keyA", UserData: map[string]any{"clientName": "12"}},
		{ClientID: "keyB", UserData: map[string]any{"clientName": "Боб"}},
	}
	dup := []core.ClientEntry{
		{ClientID: "pkA", UserData: map[string]any{"clientName": "Дубль"}},
		{ClientID: "pkB", UserData: map[string]any{"clientName": "Дубль"}},
	}

	t.Run("имя из цифр: действие идёт, но человек слышит, кого поняли", func(t *testing.T) {
		var out bytes.Buffer
		idx, err := resolveByFlag(&out, digits, "12")
		if err != nil {
			t.Fatalf("resolveByFlag: %v — имя главнее номера", err)
		}
		if idx != 0 {
			t.Fatalf("idx = %d, want 0", idx)
		}
		if out.String() == "" {
			t.Fatal("во флаговом режиме ничего не напечатано: rename -name 12 переименует молча")
		}
		if !strings.Contains(out.String(), "ИМЯ") {
			t.Errorf("не сказано, что понято как имя: %q", out.String())
		}
	})

	t.Run("дубль имени: отказ с ключами и без номеров строк", func(t *testing.T) {
		var out bytes.Buffer
		idx, err := resolveByFlag(&out, dup, "Дубль")
		if err == nil {
			t.Fatalf("idx = %d, err = nil — действие по первому совпадению недопустимо", idx)
		}
		msg := err.Error()
		if !strings.Contains(msg, "несколько") || strings.Contains(msg, "не найден") {
			t.Errorf("неоднозначность не отличена от «не найдено»: %q", msg)
		}
		if strings.Contains(msg, "строка ") {
			t.Errorf("предложены номера списка, которого человек не видел: %q", msg)
		}
		for _, want := range []string{"-name pkA", "-name pkB"} {
			if !strings.Contains(msg, want) {
				t.Errorf("нет готовой подсказки %q: %q", want, msg)
			}
		}
	})

	t.Run("обычное имя — молча", func(t *testing.T) {
		var out bytes.Buffer
		idx, err := resolveByFlag(&out, digits, "Боб")
		if err != nil || idx != 1 {
			t.Fatalf("idx = %d, err = %v, want 1, nil", idx, err)
		}
		if out.String() != "" {
			t.Errorf("лишнее сообщение: %q", out.String())
		}
	})

	t.Run("число без совпадения по имени — запрет остаётся", func(t *testing.T) {
		var out bytes.Buffer
		if _, err := resolveByFlag(&out, digits, "2"); err == nil {
			t.Fatal("номер строки во флаговом режиме резолвиться не должен")
		}
	})
}

// TestResolveInteractiveHashForm — явная форма номера строки (решение
// владельца 26.09.2026): в интерактивном меню «#12» — ВСЕГДА номер строки,
// «12» — ВСЕГДА имя; переспроса нет. Идёт через resolveInteractive — ровно
// то, что зовут четыре пункта меню (седьмая ступень: не разбор в обход).
//
// Каждый случай проверяет и индекс, и ДОСЛОВНЫЕ опознаватели вывода:
// отказ «#abc» обязан говорить о номере строки, а не «не найден» — иначе
// «#abc» тихо истолкован как имя.
func TestResolveInteractiveHashForm(t *testing.T) {
	// 12 строк; на строке 1 — клиент с именем «12», на строке 3 — с именем «#2».
	var many []core.ClientEntry
	for i := 1; i <= 12; i++ {
		name := fmt.Sprintf("user%d", i)
		switch i {
		case 1:
			name = "12"
		case 3:
			name = "#2"
		}
		many = append(many, core.ClientEntry{ClientID: fmt.Sprintf("key%d", i), UserData: map[string]any{"clientName": name}})
	}
	cases := []struct {
		name, ident string
		wantIdx     int
		want, not   []string
	}{
		{"#12 — строка 12, не имя «12»", "#12", 11, nil, []string{"ИМЯ", "Ошибка"}},
		{"12 — имя «12» со строки 1, и сказано про #12", "12", 0, []string{"ИМЯ", "Строка 12 не выбрана", "#12"}, []string{"Ошибка"}},
		{"5 без имени «5» — не строка 5, подсказка про #5", "5", -1, []string{"Ошибка", "#5"}, []string{"не номер строки"}},
		{"#2 — строка 2, клиент с именем «#2» не выбран вслух", "#2", 1, []string{"НОМЕР СТРОКИ", "строка 3"}, []string{"Ошибка"}},
		{"#13 — строки нет", "#13", -1, []string{"строки #13 в списке нет", "#12"}, []string{"не найден"}},
		{"#0 — не номер", "#0", -1, []string{"не номер строки"}, []string{"не найден"}},
		{"#-1 — не номер", "#-1", -1, []string{"не номер строки"}, []string{"не найден"}},
		{"#abc — не номер, не имя", "#abc", -1, []string{"не номер строки"}, []string{"не найден"}},
		{"# — пусто после решётки", "#", -1, []string{"не номер строки"}, []string{"не найден"}},
	}
	// Канарейка на недозапуск: усохшая таблица зеленеет молча.
	if len(cases) < 9 {
		t.Fatalf("таблица усохла до %d случаев", len(cases))
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var idx int
			var note bytes.Buffer
			out := captureStdout(t, func() {
				idx = resolveInteractive(&note, many, tc.ident)
			}) + note.String()
			t.Logf("ввод %q → %d, вывод: %q", tc.ident, idx, out)
			if idx != tc.wantIdx {
				t.Errorf("ввод %q: idx = %d, want %d", tc.ident, idx, tc.wantIdx)
			}
			for _, w := range tc.want {
				if !strings.Contains(out, w) {
					t.Errorf("ввод %q: в выводе нет %q: %q", tc.ident, w, out)
				}
			}
			for _, w := range tc.not {
				if strings.Contains(out, w) {
					t.Errorf("ввод %q: в выводе лишнее %q: %q", tc.ident, w, out)
				}
			}
		})
	}
}

// TestResolveByFlagHashForm — во ФЛАГОВОМ режиме номеров строк нет, и «#2»
// номером строки не становится: это имя (если такое есть — с объявлением
// вслух) или отказ, говорящий, где форма «#N» работает.
func TestResolveByFlagHashForm(t *testing.T) {
	clients := []core.ClientEntry{
		{ClientID: "keyA", UserData: map[string]any{"clientName": "Анна"}},
		{ClientID: "keyB", UserData: map[string]any{"clientName": "Боб"}},
		{ClientID: "keyC", UserData: map[string]any{"clientName": "#1"}},
	}
	t.Run("#2 без такого имени — отказ про интерактивное меню", func(t *testing.T) {
		var out bytes.Buffer
		idx, err := resolveByFlag(&out, clients, "#2")
		if err == nil {
			t.Fatalf("idx = %d, err = nil — «#2» во флаговом режиме стал номером строки", idx)
		}
		t.Logf("отказ: %v", err)
		if !strings.Contains(err.Error(), "интерактивном меню") {
			t.Errorf("отказ не говорит, где работает «#N»: %v", err)
		}
	})
	t.Run("#1 — имя «#1», объявлено вслух", func(t *testing.T) {
		var out bytes.Buffer
		idx, err := resolveByFlag(&out, clients, "#1")
		if err != nil || idx != 2 {
			t.Fatalf("idx = %d, err = %v, want 2 (клиент с именем «#1»), nil", idx, err)
		}
		t.Logf("вывод: %q", out.String())
		if !strings.Contains(out.String(), "ИМЯ") {
			t.Errorf("не сказано, что «#1» понят как имя: %q", out.String())
		}
	})
}
