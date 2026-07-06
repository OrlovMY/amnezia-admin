//go:build windows

package main

import (
	"os"

	"golang.org/x/sys/windows"
)

// enableVT включает ANSI-последовательности в консоли Windows (легаси
// conhost по умолчанию их не поддерживает, в отличие от Linux/macOS) и
// переключает кодовую страницу вывода в UTF-8, иначе кириллица выводится
// кракозябрами (CP866).
func enableVT() bool {
	windows.SetConsoleOutputCP(65001)
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	h := windows.Handle(os.Stdout.Fd())
	var mode uint32
	if err := windows.GetConsoleMode(h, &mode); err != nil {
		return false // вывод перенаправлен в файл/пайп — без цветов
	}
	if err := windows.SetConsoleMode(h, mode|windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING); err != nil {
		return false
	}
	return true
}
