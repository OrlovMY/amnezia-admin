package guiview

import (
	"strings"
	"testing"
)

// Дословные ожидания НАБРАНЫ ЗДЕСЬ РУКАМИ, а не взяты из продукта: иначе
// испорченная или опустевшая подсказка прошла бы зелёной (то же правило, что
// у подписей меню в copy_test.go).
const (
	wantLayoutHintPin      = "Похоже, включена не английская раскладка: пин-код принимает только латинские буквы, цифры и знаки с английской клавиатуры."
	wantLayoutHintKey      = "Похоже, включена не английская раскладка: админский ключ состоит только из латинских букв, цифр и знаков с английской клавиатуры."
	wantLayoutSwitchFailed = "Не удалось переключить раскладку на английскую — переключите её сами."
)

func TestLayoutTextsVerbatim(t *testing.T) {
	for _, c := range []struct{ got, want, what string }{
		{LayoutHintPin, wantLayoutHintPin, "подсказка про раскладку у пин-кода"},
		{LayoutHintKey, wantLayoutHintKey, "подсказка про раскладку у ключа"},
		{LayoutSwitchFailed, wantLayoutSwitchFailed, "сообщение о неудавшемся переключении"},
	} {
		if c.got != c.want {
			t.Errorf("%s:\n  дано:    %q\n  ожидалось: %q", c.what, c.got, c.want)
		}
	}
}

// TestLayoutTextsCarryNoInput — СЕКРЕТЫ. Подсказка появляется над полем
// пароля и не имеет права показать ни одного введённого символа. Поэтому в
// ней нет ни подстановок (%s, %v, %q), ни места, куда что-то подставить:
// это константы, а не шаблоны.
func TestLayoutTextsCarryNoInput(t *testing.T) {
	for _, s := range []string{LayoutHintPin, LayoutHintKey, LayoutSwitchFailed} {
		if strings.Contains(s, "%") {
			t.Errorf("в тексте про раскладку есть подстановка: %q — в неё может попасть "+
				"введённый пин или ключ", s)
		}
		if strings.TrimSpace(s) == "" {
			t.Error("текст про раскладку пуст: человек не увидит ничего")
		}
	}
}

// TestLayoutHintIsNotAboutRussianOnly — уточнение владельца: раскладка может
// быть любой локальной, а не только русской. Текст про язык («русская»,
// «кириллица») означал бы, что грек или турок прочтёт неправду.
func TestLayoutHintIsNotAboutRussianOnly(t *testing.T) {
	for _, s := range []string{LayoutHintPin, LayoutHintKey} {
		low := strings.ToLower(s)
		for _, bad := range []string{"русск", "кирилл"} {
			if strings.Contains(low, bad) {
				t.Errorf("подсказка про раскладку говорит про %q: %q — а не английской "+
					"раскладка бывает любой (греческая, иврит, турецкая, азиатский ввод)", bad, s)
			}
		}
		if !strings.Contains(low, "англ") {
			t.Errorf("подсказка не называет нужной раскладки: %q", s)
		}
	}
}
