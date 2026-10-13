package main

// Жалоба владельца 13.10: в «Конфиг готов» при серии QR (AmneziaWG 2) текст
// под кодом (info: путь сохранения, пояснение, подсказка) виден полосой в
// три строки с прокруткой, хотя окно выше. Высота диалога была 560 при
// любом окне. Теперь — по окну (configDialogSize), не меньше 560.

import (
	"fmt"
	"testing"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
)

// configInfoScroll — прокрутка текстовой части диалога: самая нижняя
// вертикальная прокрутка диалога (QR и подпись — над ней).
func configInfoScroll(t *testing.T, pop fyne.CanvasObject) *container.Scroll {
	t.Helper()
	d := fyne.CurrentApp().Driver()
	var best *container.Scroll
	var walk func(o fyne.CanvasObject)
	walk = func(o fyne.CanvasObject) {
		if o == nil || !o.Visible() {
			return
		}
		if s, ok := o.(*container.Scroll); ok && s.Direction == container.ScrollVerticalOnly {
			if best == nil || d.AbsolutePositionForObject(s).Y > d.AbsolutePositionForObject(best).Y {
				best = s
			}
		}
		for _, k := range childrenOf(o) {
			walk(k)
		}
	}
	walk(pop)
	if best == nil {
		t.Fatal("проверка ничего не значит: прокрутки текста в диалоге нет")
	}
	return best
}

// textLineHeight — прирост высоты надписи на одну строку.
func textLineHeight() float32 {
	one := widget.NewLabel("Ag").MinSize().Height
	two := widget.NewLabel("Ag\nAg").MinSize().Height
	return two - one
}

func findButton(t *testing.T, root fyne.CanvasObject, text string) *widget.Button {
	t.Helper()
	var b *widget.Button
	var walk func(o fyne.CanvasObject)
	walk = func(o fyne.CanvasObject) {
		if o == nil || !o.Visible() || b != nil {
			return
		}
		if x, ok := o.(*widget.Button); ok && x.Text == text {
			b = x
			return
		}
		for _, k := range childrenOf(o) {
			walk(k)
		}
	}
	walk(root)
	if b == nil {
		t.Fatalf("проверка ничего не значит: кнопки %q в диалоге нет", text)
	}
	return b
}

type configDialogMeasure struct {
	infoH, lines float32
}

// measureConfigDialog открывает форму на окне size, проверяет, что кнопки
// видны целиком внутри окна, и мерит видимую высоту текстовой прокрутки.
func measureConfigDialog(t *testing.T, form string, size fyne.Size) configDialogMeasure {
	t.Helper()
	u := osmotrUI(t, theme.VariantLight)
	s := formByName(t, form).open(t, u, func() { u.win.Resize(size) })
	c := u.win.Canvas()
	if got := c.Size(); got != size {
		t.Fatalf("окно %v, а не %v", got, size)
	}
	dr := fyne.CurrentApp().Driver()
	for _, text := range []string{"Сохранить ещё в…", "Скопировать путь", "Закрыть"} {
		b := findButton(t, s.root, text)
		p := dr.AbsolutePositionForObject(b)
		bs := b.Size()
		if p.X < 0 || p.Y < 0 || p.X+bs.Width > size.Width+0.5 || p.Y+bs.Height > size.Height+0.5 ||
			bs.Height < b.MinSize().Height-0.5 || bs.Width < b.MinSize().Width-0.5 {
			t.Errorf("кнопка %q не видна целиком: %v %v в окне %v", text, p, bs, size)
		}
	}
	sc := configInfoScroll(t, s.root)
	h := sc.Size().Height
	m := configDialogMeasure{infoH: h, lines: h / textLineHeight()}
	t.Logf("%s, окно %.0f×%.0f: видимая высота info %.1f т. = %.1f строк", form, size.Width, size.Height, m.infoH, m.lines)
	return m
}

const formAWG2Series = "(д) конфиг готов, AmneziaWG 2, серия QR"

// TestConfigDialogFollowsWindowHeight — тест доезда: на высоком окне
// текстовая часть видна существенно больше, чем при прежних 560.
// Подмена «вернуть 560» в configDialogSize роняет его.
func TestConfigDialogFollowsWindowHeight(t *testing.T) {
	small := measureConfigDialog(t, formAWG2Series, fyne.NewSize(1229, 620))
	tall := measureConfigDialog(t, formAWG2Series, fyne.NewSize(1229, 900))
	// Окно выросло на 280 т.; прокрутка обязана забрать почти всё.
	if tall.infoH-small.infoH < 200 {
		t.Errorf("на окне 1229×900 текст виден на %.1f т. (%.1f строк), на 1229×620 — %.1f т.: диалог не растёт с окном",
			tall.infoH, tall.lines, small.infoH)
	}
}

// TestConfigDialogFitsWindows — диалог не выходит за окно, кнопки видны
// целиком (проверка — в measureConfigDialog) на малых и большом окне.
func TestConfigDialogFitsWindows(t *testing.T) {
	for _, form := range []string{formAWG2Series, "(д) конфиг готов", "(м) конфигурация: найден, ключ сервера сверен"} {
		for _, size := range []fyne.Size{{Width: 857, Height: 517}, {Width: 972, Height: 517}, {Width: 1229, Height: 620}, {Width: 1229, Height: 900}} {
			t.Run(fmt.Sprintf("%s/%.0fx%.0f", form, size.Width, size.Height), func(t *testing.T) {
				measureConfigDialog(t, form, size)
			})
		}
	}
}

// TestConfigDialogSize — табличный: высота по окну, не меньше 560.
func TestConfigDialogSize(t *testing.T) {
	for _, c := range []struct{ win, want float32 }{
		{517, configDialogMinHeight}, {560, configDialogMinHeight}, {620, 620 - configDialogMargin},
		{900, 900 - configDialogMargin}, {1400, 1400 - configDialogMargin},
	} {
		u := osmotrUI(t, theme.VariantLight)
		u.win.Resize(fyne.NewSize(1229, c.win))
		got := configDialogSize(u.win.Canvas(), 480)
		if got.Height != c.want || got.Width != 480 {
			t.Errorf("окно высотой %.0f: %v, ждали 480×%.0f", c.win, got, c.want)
		}
	}
}
