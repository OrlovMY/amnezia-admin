package main

import (
	"os"
	"strings"
	"testing"

	"golang.org/x/term"
)

// TestColorDecisionTable — правило цвета, одинаковое для всех ОС.
func TestColorDecisionTable(t *testing.T) {
	for _, tc := range []struct {
		noColor string
		tty     bool
		want    bool
	}{
		{"", true, true},   // терминал — цвет есть
		{"", false, false}, // файл или конвейер — без цвета
		{"1", true, false}, // NO_COLOR уважается и в терминале
		{"1", false, false},
	} {
		if got := colorDecision(tc.noColor, tc.tty); got != tc.want {
			t.Errorf("colorDecision(NO_COLOR=%q, терминал=%v) = %v, want %v", tc.noColor, tc.tty, got, tc.want)
		}
	}
}

// TestNoColorWhenStdoutRedirected — ТЕСТ ДОЕЗДА на НАСТОЯЩЕЙ платформенной
// enableVT: под go test stdout — не терминал (конвейер к go test), и цвет
// обязан быть выключен на ЛЮБОЙ ОС. Тест без build-тега: на Linux/macOS он
// проверяет colors_other.go (прежний «return true» его роняет), на Windows —
// colors_windows.go. Если тестовый бинарник запущен прямо в терминале,
// проверять нечего — пропуск говорит об этом вслух, а не зеленеет молча.
func TestNoColorWhenStdoutRedirected(t *testing.T) {
	if term.IsTerminal(int(os.Stdout.Fd())) {
		t.Skip("stdout теста — терминал: проверка «не терминал → без цвета» здесь невозможна")
	}
	t.Setenv("NO_COLOR", "")
	if enableVT() {
		t.Fatal("stdout не терминал (файл/конвейер), а enableVT() включает цвет — " +
			"в файл уйдут управляющие коды вперемешку с данными")
	}
	if strings.Contains(color("1;33", "x"), "\x1b[") && !colorsEnabled {
		t.Fatal("color() красит при выключенном colorsEnabled")
	}
	if colorsEnabled {
		t.Fatal("colorsEnabled = true под go test: вывод list в тестах и в файле будет с ANSI-кодами")
	}
}

// TestColorInTerminal — обратная сторона: в НАСТОЯЩЕМ терминале цвет есть.
// Под go test и в CI stdout — конвейер, и тест пропускается с объяснением;
// выполняется, когда тестовый бинарник запущен в терминале (например, под
// `script` в Linux: так он и проверен при правке, см. отчёт).
func TestColorInTerminal(t *testing.T) {
	if !term.IsTerminal(int(os.Stdout.Fd())) {
		t.Skip("stdout теста — не терминал: проверка «терминал → цвет» здесь невозможна")
	}
	t.Setenv("NO_COLOR", "")
	if !enableVT() {
		t.Fatal("stdout — терминал, NO_COLOR не задан, а enableVT() выключает цвет")
	}
	t.Setenv("NO_COLOR", "1")
	if enableVT() {
		t.Fatal("NO_COLOR задан, а enableVT() включает цвет")
	}
}
