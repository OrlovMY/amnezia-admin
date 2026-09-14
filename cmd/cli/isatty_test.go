package main

import (
	"os"
	"testing"
)

// TestStdinIsTTYRejectsNonTerminalCharDevices — ревью PR-5, Medium-3: старая
// реализация (os.Stdin.Stat() + os.ModeCharDevice) путала /dev/null (NUL на
// Windows — тоже character special device) с настоящим терминалом. Проба
// ревьюера: пайп → false, /dev/null → false (было true до фикса), обычный
// файл → false. Терминал (true) здесь не проверяется — в тестовом
// окружении (go test) реального TTY на stdin обычно нет, а перехватить его
// программно нельзя (GetConsoleMode/term.IsTerminal смотрят на настоящий
// дескриптор консоли).
func TestStdinIsTTYRejectsNonTerminalCharDevices(t *testing.T) {
	origStdin := os.Stdin
	defer func() { os.Stdin = origStdin }()

	t.Run("regular_file", func(t *testing.T) {
		f, err := os.CreateTemp(t.TempDir(), "stdin-file")
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		os.Stdin = f
		if stdinIsTTY() {
			t.Error("обычный файл не должен считаться терминалом")
		}
	})

	t.Run("pipe", func(t *testing.T) {
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		defer r.Close()
		defer w.Close()
		os.Stdin = r
		if stdinIsTTY() {
			t.Error("пайп не должен считаться терминалом")
		}
	})

	t.Run("dev_null", func(t *testing.T) {
		f, err := os.OpenFile(os.DevNull, os.O_RDONLY, 0)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		os.Stdin = f
		if stdinIsTTY() {
			t.Error("/dev/null (NUL) не должен считаться терминалом — это character device, но не терминал")
		}
	})
}
