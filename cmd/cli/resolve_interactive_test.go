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

	t.Run("обычный номер — молча и как раньше", func(t *testing.T) {
		var buf bytes.Buffer
		idx := resolveInteractive(&buf, many, "5")
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
