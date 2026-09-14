//go:build windows

package main

import (
	"os"

	"golang.org/x/sys/windows"
)

// stdinIsTTY сообщает, подключён ли stdin к реальному терминалу. Тот же
// принцип, что и enableVT (colors_windows.go): проверяем GetConsoleMode, а
// не тип файла — os.ModeCharDevice даёт true и для консоли, и для /dev/null
// (NUL на Windows — тоже character special device), из-за чего оператор в
// CI с перенаправлением в NUL получал бы вопрос вместо отказа с подсказкой
// про -yes (ревью PR-5, Medium-3; проба ревьюера: пайп → false, NUL → true
// по старой реализации, файл → false).
func stdinIsTTY() bool {
	h := windows.Handle(os.Stdin.Fd())
	var mode uint32
	return windows.GetConsoleMode(h, &mode) == nil
}
