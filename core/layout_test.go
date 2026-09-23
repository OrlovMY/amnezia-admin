package core

// НЕ АНГЛИЙСКАЯ РАСКЛАДКА ПРИ ВВОДЕ ПИНА.
//
// Уточнение владельца 23.09.2026 дословно: «Может быть не только кириллица,
// но и любая локальная раскладка. А должна быть только английская». Поэтому
// признак — не «есть кириллица», а «есть символ, которого ValidatePin не
// допускает по набору символов». Перечня алфавитов здесь нет и быть не
// должно: перечень всегда неполон, а нам нужно ровно дополнение к тому, что
// разрешено.

import (
	"strings"
	"testing"
)

// TestNonEnglishLayoutSuspectCases — табличный разбор случаев, названных
// владельцем. Последняя строка — ОБЯЗАТЕЛЬНАЯ: подсказка, срабатывающая на
// верном вводе, хуже её отсутствия.
func TestNonEnglishLayoutSuspectCases(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want bool
	}{
		{"кириллица", "парольПароль1", true},
		{"одна кириллическая буква среди латиницы", "Abcdefgh123ф", true},
		{"греческий", "Abcdefgh123α", true},
		{"иврит", "Abcdefgh123א", true},
		{"диакритика европейских раскладок", "Abcdefgh123é", true},
		{"турецкая ı", "Abcdefgh123ı", true},
		{"полноширинная латинская Ａ", "Abcdefgh123Ａ", true},
		{"эмодзи", "Abcdefgh123🙂", true},
		{"управляющий символ", "Abcdefgh123\n", true},
		{"DEL (0x7F)", "Abcdefgh123\x7f", true},
		{"пустая строка", "", false},
		{"чистая латиница с цифрами и знаками", "Abcdefgh123!~ #", false},
		{"весь допустимый диапазон целиком", printableASCII(), false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := NonEnglishLayoutSuspect(c.in); got != c.want {
				t.Errorf("NonEnglishLayoutSuspect(<ввод скрыт>) = %v, ожидалось %v", got, c.want)
			}
		})
	}
}

func printableASCII() string {
	var b strings.Builder
	for r := rune(0x20); r <= 0x7E; r++ {
		b.WriteRune(r)
	}
	return b.String()
}

// TestLayoutSuspectFollowsValidatePin — ОДНО МЕСТО ИСТИНЫ.
//
// Подсказка про раскладку обязана быть ровно дополнением к набору символов,
// который допускает ValidatePin, — и ехать за ним, если набор когда-нибудь
// расширят. Проверяется не чтением кода, а прогоном: к заведомо верному пину
// приписывается по одному символу, и на каждом сверяется, что «ValidatePin
// отверг» и «подсказка сработала» — одно и то же событие.
//
// Подмена, которая расширит pinRe, не тронув подсказку (или наоборот),
// роняет этот тест.
func TestLayoutSuspectFollowsValidatePin(t *testing.T) {
	const base = "Abcdefgh1234" // 12 знаков, буква и цифра есть — сам по себе верен
	if err := ValidatePin(base); err != nil {
		t.Fatalf("проверка ПЕРЕСТАЛА ЧТО-ЛИБО ЗНАЧИТЬ: образцовый пин отвергнут: %v", err)
	}

	var sample []rune
	for r := rune(0); r < 0x300; r++ { // ASCII, управляющие, латиница с диакритикой
		sample = append(sample, r)
	}
	// И по представителю письменностей, до которых сплошной перебор не идёт.
	sample = append(sample, 'ф', 'Ж', 'α', 'א', 'ı', '漢', 'あ', 'Ａ', '🙂', '€', ' ')

	checked := 0
	for _, r := range sample {
		if r == 0 { // NUL в строку не кладём: это не про раскладку
			continue
		}
		pin := base + string(r)
		rejected := ValidatePin(pin) != nil
		suspect := NonEnglishLayoutSuspect(pin)
		if rejected != suspect {
			t.Fatalf("символ U+%04X: ValidatePin отвергает = %v, подсказка про раскладку = %v — "+
				"набор символов и подсказка разъехались, подсказка перестала быть "+
				"дополнением к правилу", r, rejected, suspect)
		}
		checked++
	}
	if checked < 700 {
		t.Fatalf("проверено всего %d символов — выборка схлопнулась, тест ничего не доказывает", checked)
	}
}

// TestLayoutSuspectIgnoringLineBreaks — ПОЛЕ АДМИНСКОГО КЛЮЧА (ревью UX-01).
//
// Ключ vpn://… длинный, его копируют из мессенджера и почты уже разбитым на
// строки, а поле ввода многострочное. Перенос строки — не признак раскладки,
// и называть его раскладкой значит дать уверенный неверный ответ там, где
// причина другая. Всё остальное — ровно как в общем признаке.
func TestLayoutSuspectIgnoringLineBreaks(t *testing.T) {
	const key = "vpn://aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789"
	cases := []struct {
		name string
		in   string
		want bool
	}{
		{"однострочный ключ", key, false},
		{"ключ, разбитый на строки", key[:20] + "\n" + key[20:], false},
		{"он же с возвратом каретки", key[:20] + "\r\n" + key[20:], false},
		{"только переносы", "\n\r\n", false},
		{"кириллица в разбитом ключе", key[:20] + "\n" + "кириллица" + key[20:], true},
		{"кириллица без переносов", "vpn://кириллица", true},
		{"табуляция", key + "\t", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := LayoutSuspectIgnoringLineBreaks(c.in); got != c.want {
				t.Errorf("LayoutSuspectIgnoringLineBreaks = %v, ожидалось %v", got, c.want)
			}
		})
	}
	// И связь с общим признаком: перенос строки — ЕДИНСТВЕННОЕ послабление.
	if !NonEnglishLayoutSuspect(key[:20] + "\n" + key[20:]) {
		t.Error("общий признак перестал считать перенос строки подозрительным — " +
			"тогда отдельная функция для ключа ничего не значит")
	}
}
