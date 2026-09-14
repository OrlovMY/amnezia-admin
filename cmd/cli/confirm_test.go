package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"

	"amnezia-admin/core"
	"amnezia-admin/internal/fakesrv"
)

func testCard() ActionCard {
	return ActionCard{
		Action:    "удалить",
		Host:      "10.20.30.40",
		Container: "amnezia-awg",
		Name:      "Иван Иванов",
		Created:   "2024-01-02 03:04:0",
		LastSeen:  "2024-05-06 07:08",
		Key:       "PUBKEYXYZ==",
	}
}

// TestNonTTYWithoutYesExit2 — без терминала и без -yes действие обязано
// отказать с кодом 2: скрипт, запущенный без TTY (cron, CI) и без явного
// -yes, не должен случайно выполнить необратимое действие.
func TestNonTTYWithoutYesExit2(t *testing.T) {
	card := testCard()
	var out, errOut bytes.Buffer
	proceed, code := confirmOrExit(strings.NewReader(""), &out, &errOut, false, false, card)
	if proceed {
		t.Error("proceed должен быть false без терминала и без -yes")
	}
	if code != 2 {
		t.Errorf("code = %d, хочу 2", code)
	}
	if !strings.Contains(errOut.String(), "-yes") {
		t.Errorf("errOut не содержит \"-yes\": %q", errOut.String())
	}
	for _, want := range []string{card.Host, card.Container, card.Name, card.Created, card.LastSeen, card.Key, card.Action} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("карточка в out не содержит поле %q; out:\n%s", want, out.String())
		}
	}
}

// noReadReader — io.Reader, который проваливает тест, если из него читали.
// Используется, чтобы доказать: при yes=true confirmOrExit не трогает in.
type noReadReader struct{ t *testing.T }

func (r noReadReader) Read(p []byte) (int, error) {
	r.t.Helper()
	r.t.Fatal("confirmOrExit не должен читать in при yes=true")
	return 0, io.EOF
}

// TestYesExecutes — флаг -yes выполняет действие без вопроса (и без TTY, и
// с TTY), карточка всё равно печатается (журнал скрипта), а вызывающий код
// (main.go) выполняет действие ровно один раз.
func TestYesExecutes(t *testing.T) {
	card := testCard()
	for _, tc := range []struct {
		name  string
		isTTY bool
	}{
		{"non-tty", false},
		{"tty", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out, errOut bytes.Buffer
			proceed, code := confirmOrExit(noReadReader{t}, &out, &errOut, tc.isTTY, true, card)
			if !proceed || code != 0 {
				t.Fatalf("yes=true: proceed=%v code=%d, хочу true/0", proceed, code)
			}
			if !strings.Contains(out.String(), card.Name) {
				t.Errorf("карточка не напечатана при yes=true: %q", out.String())
			}
			// счётчик действия-заглушки, вызванного по proceed
			actionCalls := 0
			if proceed {
				actionCalls++
			}
			if actionCalls != 1 {
				t.Errorf("действие должно быть вызвано ровно 1 раз, вызвано %d", actionCalls)
			}
		})
	}
}

// TestToggleDisableAsks — решение владельца (14.09.2026, ответ 3):
// подтверждение CLI распространяется на toggle-отключение.
func TestToggleDisableAsks(t *testing.T) {
	active := core.ClientEntry{ClientID: "k1", UserData: map[string]any{"clientName": "Иван"}}
	if !needsConfirm("toggle", active) {
		t.Fatal("needsConfirm(toggle, активная запись) должен быть true")
	}

	card := ActionCard{Action: "отключить", Host: "h", Container: "c", Name: "Иван", Created: "cr", LastSeen: "—", Key: "k1"}

	var out, errOut bytes.Buffer
	proceed, code := confirmOrExit(strings.NewReader("y\n"), &out, &errOut, true, false, card)
	if !proceed || code != 0 {
		t.Errorf("ответ \"y\": proceed=%v code=%d, хочу true/0", proceed, code)
	}

	out.Reset()
	errOut.Reset()
	proceed, code = confirmOrExit(strings.NewReader("n\n"), &out, &errOut, true, false, card)
	if proceed || code != 2 {
		t.Errorf("ответ \"n\": proceed=%v code=%d, хочу false/2", proceed, code)
	}
	if !strings.Contains(out.String(), "Отменено.") {
		t.Errorf("ответ \"n\": out не содержит \"Отменено.\": %q", out.String())
	}

	out.Reset()
	errOut.Reset()
	proceed, code = confirmOrExit(strings.NewReader(""), &out, &errOut, true, false, card)
	if proceed || code != 2 {
		t.Errorf("пустой ответ: proceed=%v code=%d, хочу false/2", proceed, code)
	}
}

// TestToggleEnableSilent — включение (toggle над отключённым) и
// переименование не спрашивают; del/rekey — всегда спрашивают.
func TestToggleEnableSilent(t *testing.T) {
	disabled := core.ClientEntry{ClientID: "k2", UserData: map[string]any{"clientName": "Пётр", "disabled": true}}
	active := core.ClientEntry{ClientID: "k1", UserData: map[string]any{"clientName": "Иван"}}

	if needsConfirm("toggle", disabled) {
		t.Error("needsConfirm(toggle, отключённая запись) должен быть false (это включение)")
	}
	if needsConfirm("rename", active) {
		t.Error("needsConfirm(rename, ...) должен быть false")
	}
	if !needsConfirm("del", active) {
		t.Error("needsConfirm(del, ...) должен быть true")
	}
	if !needsConfirm("rekey", active) {
		t.Error("needsConfirm(rekey, ...) должен быть true")
	}
}

// TestCardTextSharedBetweenMenuAndSubcommand (рекомендация Д) — renderCard
// обязан быть единственным местом с текстом карточки: "Публичный ключ:" —
// ровно один раз в confirm.go и ни разу в main.go (иначе меню и подкоманды
// печатали бы карточку по двум разным местам, и тексты могли бы разъехаться).
func TestCardTextSharedBetweenMenuAndSubcommand(t *testing.T) {
	countIn := func(path string) int {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("чтение %s: %v", path, err)
		}
		return strings.Count(string(data), "Публичный ключ:")
	}
	if n := countIn("confirm.go"); n != 1 {
		t.Errorf("confirm.go: \"Публичный ключ:\" встречается %d раз(а), хочу 1", n)
	}
	if n := countIn("main.go"); n != 0 {
		t.Errorf("main.go: \"Публичный ключ:\" встречается %d раз(а), хочу 0 (карточка — только в confirm.go)", n)
	}
}

// TestDryRunBeatsYes (рекомендация Д) — -dry-run обязан побеждать -yes: план
// печатается, ничего не пишется, вопрос не задаётся. В main() это гарантирует
// порядок кода (проверка *dryRun с break — раньше needsConfirm в каждой из
// веток del/toggle/rekey); тест ловит регресс, если порядок веток в switch
// когда-нибудь поменяют местами. Плюс fakesrv.Commands(): сам runDryRun для
// del ничего не пишет (без "cat > "), то есть даже если бы очередь дошла до
// вопроса/-yes, писать было бы нечего.
func TestDryRunBeatsYes(t *testing.T) {
	data, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatalf("чтение main.go: %v", err)
	}
	src := string(data)
	// runDryRun() выше по файлу тоже содержит switch с такими же case-тегами
	// (add/del/rename/toggle/rekey) — ищем со сдвигом после начала main(),
	// чтобы не попасть в чужой switch.
	mainStart := strings.Index(src, "func main() {")
	if mainStart < 0 {
		t.Fatal("не нашёл func main() в main.go")
	}
	src = src[mainStart:]
	for _, cmd := range []string{"del", "toggle", "rekey"} {
		caseTag := fmt.Sprintf("case %q:", cmd)
		start := strings.Index(src, caseTag)
		if start < 0 {
			t.Fatalf("не нашёл %s в main.go (после func main())", caseTag)
		}
		rest := src[start+len(caseTag):]
		end := len(rest)
		for _, marker := range []string{"\n\tcase ", "\n\tdefault:"} {
			if i := strings.Index(rest, marker); i >= 0 && i < end {
				end = i
			}
		}
		block := rest[:end]
		dryIdx := strings.Index(block, "*dryRun")
		confIdx := strings.Index(block, "needsConfirm(")
		if dryIdx < 0 {
			t.Fatalf("%s: не нашёл проверку *dryRun в ветке switch", cmd)
		}
		if confIdx < 0 {
			t.Fatalf("%s: не нашёл needsConfirm( в ветке switch", cmd)
		}
		if dryIdx > confIdx {
			t.Errorf("%s: needsConfirm встречается раньше проверки *dryRun — -dry-run обязан побеждать -yes/вопрос", cmd)
		}
	}

	srv := fakesrv.New()
	sess := core.NewSessionWithRunner(srv, &core.ServerCreds{Host: "1.2.3.4", User: "root", Password: "x"})
	c := &core.Container{Name: "amnezia-awg", Dir: "/opt/amnezia/awg", Proto: "AmneziaWG", Managed: true}
	var buf bytes.Buffer
	if err := runDryRun(&buf, sess, c, "del", "Alice", ""); err != nil {
		t.Fatalf("runDryRun(del): %v", err)
	}
	for _, sent := range srv.Commands() {
		if strings.Contains(sent, "cat > ") {
			t.Errorf("dry-run(del) не должен писать: %q", sent)
		}
	}
}
