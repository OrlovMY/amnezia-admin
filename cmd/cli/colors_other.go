//go:build !windows

package main

import (
	"os"

	"golang.org/x/term"
)

// enableVT — на Linux/macOS терминалы поддерживают ANSI нативно, настройки
// консоли не требуется. Но цвет включается ТОЛЬКО если stdout — терминал:
// прежняя редакция возвращала true всегда (кроме NO_COLOR), и
// `amnezia-admin list > файл` на Linux/macOS писал управляющие коды
// вперемешку с данными, а на Windows — чистый текст (там GetConsoleMode
// падает на перенаправленном выводе). Поведение расходилось между ОС; это
// вскрыл CI PR #20 (задание НЕЗНАНИЕ-ТРАФИК). Решение — общая colorDecision.
func enableVT() bool {
	return colorDecision(os.Getenv("NO_COLOR"), term.IsTerminal(int(os.Stdout.Fd())))
}
