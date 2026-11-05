package main

import (
	"image/color"
	"unicode"
	"unicode/utf8"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"amnezia-admin/core"
)

// Сообщения GUI — выделяемые и копируемые (заказ владельца 05.11.2026).
//
// ЗАКРЫТЫЙ СПИСОК КОНСТРУКТОРОВ. Любая надпись в cmd/gui строится только
// здесь: msgLabel / msgLabelStyle (выделяемая подпись), withCopy (кнопка
// «Копировать» при сообщении), u.showInfo / u.showErrorText (диалоги
// сообщений). Прямой widget.NewLabel, dialog.ShowInformation/ShowError/
// NewInformation/NewConfirm и canvas.NewText вне этого файла — нарушение;
// сторож TestMessagesOnlySelectable (msg_guard_test.go) перечисляет
// РАЗРЕШЁННОЕ, а не запрещённое.
//
// КОПИРУЕТСЯ ПОКАЗАННОЕ. Кнопка «Копировать» берёт label.Text в момент
// нажатия — тот текст, что на экране, а не исходную строку: если граница
// маскировки (core.MaskText) уже заменила секрет на <скрыто>, в буфер уйдёт
// <скрыто>. Второго источника текста у кнопки нет по построению.

// msgLabel — выделяемая подпись. Перенос по словам — решение места вызова
// (как у widget.NewLabel): подпись с переносом схлопывается по ширине, и
// подписи полей формы («Адрес:») его не получают.
func msgLabel(text string) *widget.Label {
	l := widget.NewLabel(text)
	l.Selectable = true
	return l
}

// msgLabelStyle — выделяемая подпись с выравниванием и стилем (без переноса:
// такие подписи — заголовки и пути, они уже были однострочными).
func msgLabelStyle(text string, align fyne.TextAlign, style fyne.TextStyle) *widget.Label {
	l := widget.NewLabelWithStyle(text, align, style)
	l.Selectable = true
	return l
}

// copyButton — кнопка «Копировать» для подписи l.
func copyButton(l *widget.Label) *widget.Button {
	return widget.NewButtonWithIcon("Копировать", theme.ContentCopyIcon(), func() {
		fyne.CurrentApp().Clipboard().SetContent(l.Text)
	})
}

// withCopy — сообщение l и кнопка «Копировать» справа от него.
func withCopy(l *widget.Label) fyne.CanvasObject {
	return container.NewBorder(nil, nil, nil, container.NewVBox(copyButton(l)), l)
}

// infoDialogWidth — ширина диалога сообщения: текст переносится по словам,
// без ширины выделяемая подпись схлопнулась бы в столбик.
const infoDialogWidth = 460

// showInfo — диалог сообщения (замена dialog.ShowInformation): выделяемый
// текст и «Копировать». Текст проходит границу маскировки.
func (u *ui) showInfo(title, text string) dialog.Dialog {
	l := msgLabel(core.MaskText(text))
	l.Wrapping = fyne.TextWrapWord
	d := dialog.NewCustom(title, "Закрыть", withCopy(l), u.win)
	d.Resize(fyne.NewSize(infoDialogWidth, d.MinSize().Height))
	d.Show()
	return d
}

// showErrorText — диалог ошибки (замена dialog.ShowError). Первая буква
// заглавная — как делал dialog.ShowError (тексты ядра начинаются со
// строчной).
func (u *ui) showErrorText(err error) dialog.Dialog {
	s := err.Error()
	if r, n := utf8.DecodeRuneInString(s); n > 0 {
		s = string(unicode.ToUpper(r)) + s[n:]
	}
	return u.showInfo("Ошибка", s)
}

// newConfirm — подтверждение (замена dialog.NewConfirm) с выделяемым
// текстом; не показывается, вызывающий сам вызывает Show.
func (u *ui) newConfirm(title, text string, cb func(bool)) *dialog.ConfirmDialog {
	return dialog.NewCustomConfirm(title, "Да", "Нет", withCopy(wrapped(msgLabel(core.MaskText(text)))), cb, u.win)
}

// wrapped — перенос по словам для подписи l (для цепочек вызова).
func wrapped(l *widget.Label) *widget.Label {
	l.Wrapping = fyne.TextWrapWord
	return l
}

// compactTheme — текущая тема приложения без внутреннего отступа подписи.
// Тема берётся в момент запроса, а не при сборке: смена светлой/тёмной и
// боевая тема программы проходят насквозь.
type compactTheme struct{}

func (compactTheme) cur() fyne.Theme { return fyne.CurrentApp().Settings().Theme() }
func (t compactTheme) Color(n fyne.ThemeColorName, v fyne.ThemeVariant) color.Color {
	return t.cur().Color(n, v)
}
func (t compactTheme) Font(s fyne.TextStyle) fyne.Resource     { return t.cur().Font(s) }
func (t compactTheme) Icon(n fyne.ThemeIconName) fyne.Resource { return t.cur().Icon(n) }
func (t compactTheme) Size(n fyne.ThemeSizeName) float32 {
	if n == theme.SizeNameInnerPadding {
		return 0
	}
	return t.cur().Size(n)
}

// compactHint — выделяемая подсказка мелким шрифтом без внутренних
// отступов подписи: по высоте как прежний canvas.Text (CaptionTextSize), но
// текст выделяется.
func compactHint(l *widget.Label) fyne.CanvasObject {
	l.SizeName = theme.SizeNameCaptionText
	return container.NewThemeOverride(l, compactTheme{})
}
