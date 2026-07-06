package main

import (
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

// colorsEnabled — включаем ANSI-цвета, если консоль их поддерживает
var colorsEnabled = enableVT()

func enableVT() bool {
	// UTF-8 для легаси conhost, иначе кириллица выводится кракозябрами (CP866)
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

func color(code, s string) string {
	if !colorsEnabled {
		return s
	}
	return "\x1b[" + code + "m" + s + "\x1b[0m"
}

func cTitle(s string) string  { return color("1;36", s) } // жирный циан — заголовки
func cNum(s string) string    { return color("1;33", s) } // жирный жёлтый — пункты меню
func cHead(s string) string   { return color("1", s) }    // жирный — шапка таблицы
func cOK(s string) string     { return color("32", s) }   // зелёный — успех/онлайн
func cErr(s string) string    { return color("1;31", s) } // красный — ошибки
func cDim(s string) string    { return color("90", s) }   // серый — второстепенное
func cWarn(s string) string   { return color("1;33", s) } // жирный жёлтый — предупреждения
func cAccent(s string) string { return color("36", s) }   // циан — значения

// printErr — единообразный вывод ошибок
func printErr(err error) {
	fmt.Println(cErr("Ошибка: ") + err.Error())
}
