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
		var out string
		var idx int
		out = captureStdout(t, func() {
			var buf bytes.Buffer
			idx = resolveInteractive(&buf, dup, "Дубль")
			out += buf.String()
		})
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
		out := captureStdout(t, func() {
			var buf bytes.Buffer
			idx = resolveInteractive(&buf, many, "нет-такого")
		})
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
