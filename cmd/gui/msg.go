package main

import (
	"image/color"
	"unicode"
	"unicode/utf8"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
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

// msgText — подпись-сообщение: выделяемая, и МАСКИРОВКА В НЕЙ САМОЙ
// (ревью-1 M1). Любой текст, попавший в подпись — конструктором или
// SetText, — проходит core.MaskText в этой одной точке, поэтому и на
// экране, и в буфере («Копировать» берёт Text) секрет уже <скрыто>, где бы
// ни был вызов. Прямое присваивание .Text в cmd/gui запрещено сторожем
// TestMessagesOnlySelectable (иначе маску можно обойти).
type msgText struct {
	widget.Label
	// onText — слушатель смены текста (кнопка «Копировать» гаснет у
	// пустой строки, ревью-1 L1).
	onText func(string)
}

// SetText — единственный путь текста в подпись после сборки.
func (l *msgText) SetText(s string) {
	l.Label.SetText(core.MaskText(s))
	if l.onText != nil {
		l.onText(l.Text)
	}
}

func newMsgText(text string, align fyne.TextAlign, style fyne.TextStyle) *msgText {
	l := &msgText{}
	l.Text, l.Alignment, l.TextStyle = core.MaskText(text), align, style
	l.Selectable = true
	l.ExtendBaseWidget(l)
	return l
}

// msgLabel — выделяемая подпись. Перенос по словам — решение места вызова
// (как у widget.NewLabel): подпись с переносом схлопывается по ширине, и
// подписи полей формы («Адрес:») его не получают.
func msgLabel(text string) *msgText {
	return newMsgText(text, fyne.TextAlignLeading, fyne.TextStyle{})
}

// msgLabelStyle — выделяемая подпись с выравниванием и стилем (без переноса:
// такие подписи — заголовки и пути, они уже были однострочными).
func msgLabelStyle(text string, align fyne.TextAlign, style fyne.TextStyle) *msgText {
	return newMsgText(text, align, style)
}

// copyButton — кнопка «Копировать» для подписи l. Пустая подпись —
// кнопка скрыта: копировать нечего (ревью-1 L1).
func copyButton(l *msgText) *widget.Button {
	b := widget.NewButtonWithIcon("Копировать", theme.ContentCopyIcon(), func() {
		fyne.CurrentApp().Clipboard().SetContent(l.Text)
	})
	sync := func(s string) {
		if s == "" {
			b.Hide()
		} else {
			b.Show()
		}
	}
	prev := l.onText
	l.onText = func(s string) {
		if prev != nil {
			prev(s)
		}
		sync(s)
	}
	sync(l.Text)
	return b
}

// withCopy — сообщение l и кнопка «Копировать» справа от него.
// Кнопка не выше однострочной подписи (ревью-1 L1): значок в ней — высотой
// строки текста (lineIconTheme), а не 20 т. темы, иначе строка состояния
// вырастала на 0.9 т. (замер: подпись 35.1, кнопка 36.0).
func withCopy(l *msgText) fyne.CanvasObject {
	return container.NewBorder(nil, nil, nil,
		container.NewVBox(container.NewThemeOverride(copyButton(l), lineIconTheme{})), l)
}

// lineIconTheme — текущая тема со значком в строку высотой строки текста.
type lineIconTheme struct{}

func (lineIconTheme) cur() fyne.Theme { return fyne.CurrentApp().Settings().Theme() }
func (t lineIconTheme) Color(n fyne.ThemeColorName, v fyne.ThemeVariant) color.Color {
	return t.cur().Color(n, v)
}
func (t lineIconTheme) Font(s fyne.TextStyle) fyne.Resource     { return t.cur().Font(s) }
func (t lineIconTheme) Icon(n fyne.ThemeIconName) fyne.Resource { return t.cur().Icon(n) }
func (t lineIconTheme) Size(n fyne.ThemeSizeName) float32 {
	if n == theme.SizeNameInlineIcon {
		th := t.cur()
		return fyne.MeasureText("Ау", th.Size(theme.SizeNameText), fyne.TextStyle{}).Height
	}
	return t.cur().Size(n)
}

// withCopyBelow — сообщение l во всю ширину и «Копировать» под ним справа
// (диалоги сообщений: кнопка сбоку отнимала у текста треть ширины).
func withCopyBelow(l *msgText) fyne.CanvasObject {
	return container.NewBorder(nil, container.NewHBox(layout.NewSpacer(), copyButton(l)), nil, nil, l)
}

// infoDialogWidth — ширина диалога сообщения: текст переносится по словам,
// без ширины выделяемая подпись схлопнулась бы в столбик.
const infoDialogWidth = 520

// showInfo — диалог сообщения (замена dialog.ShowInformation): выделяемый
// текст и «Копировать». Текст проходит границу маскировки.
func (u *ui) showInfo(title, text string) dialog.Dialog {
	l := msgLabel(text)
	l.Wrapping = fyne.TextWrapWord
	d := dialog.NewCustom(title, "Закрыть", withCopyBelow(l), u.win)
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
	return dialog.NewCustomConfirm(title, "Да", "Нет", withCopyBelow(wrapped(msgLabel(text))), cb, u.win)
}

// wrapped — перенос по словам для подписи l (для цепочек вызова).
func wrapped(l *msgText) *msgText {
	l.Wrapping = fyne.TextWrapWord
	return l
}

// compactTheme — текущая тема приложения без внутреннего отступа подписи и
// с серым цветом текста (цвет подсказки-заглушки темы).
// Тема берётся в момент запроса, а не при сборке: смена светлой/тёмной и
// боевая тема программы проходят насквозь.
type compactTheme struct{}

func (compactTheme) cur() fyne.Theme { return fyne.CurrentApp().Settings().Theme() }
func (t compactTheme) Color(n fyne.ThemeColorName, v fyne.ThemeVariant) color.Color {
	if n == theme.ColorNameForeground {
		n = theme.ColorNamePlaceHolder // серый, как прежний canvas.Text подсказки
	}
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
func compactHint(l *msgText) fyne.CanvasObject {
	l.SizeName = theme.SizeNameCaptionText
	return container.NewThemeOverride(l, compactTheme{})
}

// resultBody — тело окна итога: текст (с заголовком head, если есть) в
// прокрутке, а кнопки — «Копировать» текста и действия actions — ВНЕ
// прокрутки, внизу. Кнопки видны всегда, при любых метриках шрифта: на
// macOS шрифт крупнее, и кнопка внутри прокрутки уходила за край окна
// (CI PR #72, TestBackupWindowsVisible 972×517).
func resultBody(head fyne.CanvasObject, l *msgText, actions ...fyne.CanvasObject) fyne.CanvasObject {
	var top fyne.CanvasObject = l
	if head != nil {
		top = container.NewVBox(head, l)
	}
	row := container.NewHBox(append(append([]fyne.CanvasObject{}, actions...), layout.NewSpacer(), copyButton(l))...)
	return container.NewBorder(nil, row, nil, nil, container.NewVScroll(top))
}
