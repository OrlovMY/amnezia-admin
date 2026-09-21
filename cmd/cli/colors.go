package main

import (
	"fmt"
	"io"

	"amnezia-admin/core"
)

// colorsEnabled — включаем ANSI-цвета, если консоль их поддерживает.
// enableVT() платформенно-специфична (см. colors_windows.go/colors_other.go).
var colorsEnabled = enableVT()

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

// resolveInteractive — разрешение ввода внутри напечатанного интерактивного
// списка (A8). Печатает человеку, КОГО поняли (Resolution.Note — когда ввод
// годился и как номер строки, и как имя), либо почему выбрать нельзя
// (Resolution.Err — «не найдено» и «подходит несколько» суть разные тексты).
// Возвращает -1, если действовать нельзя: молчаливое действие по первому
// совпадению недопустимо, del/rename/toggle необратимы.
func resolveInteractive(w io.Writer, clients []core.ClientEntry, ident string) int {
	r := core.ResolveClient(clients, ident)
	if err := r.Err(clients); err != nil {
		printErr(err)
		return -1
	}
	if note := r.Note(); note != "" {
		fmt.Fprintln(w, cWarn(note))
	}
	return r.Index
}

// printErr — единообразный вывод ошибок
func printErr(err error) {
	fmt.Println(cErr("Ошибка: ") + err.Error())
}
