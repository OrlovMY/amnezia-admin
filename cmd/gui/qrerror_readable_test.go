package main

// СТОРОЖ: надпись «Не удалось построить QR-код: …» читается ЦЕЛИКОМ
// (находка владельца 12.10.2026, снимок «Конфиг готов», AmneziaWG 2).
// На 699ab55 надпись с переносом по словам лежала в Center (без строки
// честности) или в левом краю Border (со строкой честности AWG2) — и
// получала минимальную ширину: одну букву, столбиком. Подмена «вернуть
// прежний контейнер» (Center / Border-лево) роняет этот тест ПОВЕДЕНИЕМ:
// ширина надписи падает до ~20 т.

import (
	"fmt"
	"strings"
	"testing"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/test"
	"fyne.io/fyne/v2/widget"

	"amnezia-admin/core"
)

// qrErrMinWidth — разумная ширина надписи: не меньше 300 т. (диалог 464
// без строки честности, 744 с ней). Столбик по букве — около 20 т.
const qrErrMinWidth = 300

// qrErrLabel — видимая надпись «Не удалось построить QR-код…».
func qrErrLabel(root fyne.CanvasObject) *widget.Label {
	var found *widget.Label
	var walk func(o fyne.CanvasObject)
	walk = func(o fyne.CanvasObject) {
		if found != nil || o == nil || !o.Visible() {
			return
		}
		if l, ok := o.(*widget.Label); ok && strings.HasPrefix(l.Text, "Не удалось построить QR-код") {
			found = l
			return
		}
		switch x := o.(type) {
		case *fyne.Container:
			for _, k := range x.Objects {
				walk(k)
			}
		case *container.Scroll:
			walk(x.Content)
		case fyne.Widget:
			for _, k := range test.WidgetRenderer(x).Objects() {
				walk(k)
			}
		}
	}
	walk(root)
	return found
}

func TestQRErrorReadable(t *testing.T) {
	for _, state := range []string{"QR не построен", "AmneziaWG 2, QR не построен"} {
		f := osmotrForm{name: state, open: openConfig(state)}
		for _, size := range osmotrSizes {
			for _, th := range osmotrThemes {
				t.Run(fmt.Sprintf("%s/%s/%s", state, size, th.name), func(t *testing.T) {
					u := osmotrUI(t, th.v)
					s := f.open(t, u, sizeWindow(u, size))
					osmotrFrame(s.root, s.mins)
					pop, ok := s.root.(*widget.PopUp)
					if !ok {
						t.Fatalf("проверка ничего не значит: корень %T", s.root)
					}
					l := qrErrLabel(pop)
					if l == nil {
						t.Fatal("проверка ничего не значит: надписи «QR не построен» в окне нет")
					}
					if !strings.Contains(l.Text, "слишком большой") || !strings.Contains(l.Text, fmt.Sprint(core.QRMaxBytes)) {
						t.Errorf("причина не названа размерами: %q", l.Text)
					}
					d := fyne.CurrentApp().Driver()
					lp, ls := d.AbsolutePositionForObject(l), l.Size()
					cp, cs := d.AbsolutePositionForObject(pop.Content), pop.Content.Size()
					t.Logf("надпись %.1f×%.1f (мин. %.1f×%.1f), y %.1f..%.1f, диалог y %.1f..%.1f",
						ls.Width, ls.Height, l.MinSize().Width, l.MinSize().Height, lp.Y, lp.Y+ls.Height, cp.Y, cp.Y+cs.Height)
					if ls.Width < qrErrMinWidth {
						t.Errorf("надпись узкая: %.1f т. < %d — переносится по буквам", ls.Width, qrErrMinWidth)
					}
					if ls.Height < l.MinSize().Height-0.5 || lp.Y < cp.Y-0.5 || lp.Y+ls.Height > cp.Y+cs.Height+0.5 {
						t.Errorf("надпись видна не целиком: %.1f..%.1f при диалоге %.1f..%.1f", lp.Y, lp.Y+ls.Height, cp.Y, cp.Y+cs.Height)
					}
				})
			}
		}
	}
}

// TestQRSlotErrorFullWidth — то же для окна «Показать QR» (savedconf):
// надпись в слоте QR занимает ширину слота, картинка — по центру.
func TestQRSlotErrorFullWidth(t *testing.T) {
	test.NewTempApp(t)
	big := strings.Repeat("x", core.QRMaxBytes+1)
	box := container.NewVBox(qrSlot(qrObject("x", big, "")))
	w := test.NewWindow(box)
	defer w.Close()
	w.Resize(fyne.NewSize(480, 400))
	box.Refresh()
	w.Resize(fyne.NewSize(480, 401)) // второй кадр: высота по новой ширине
	l := qrErrLabel(box)
	if l == nil {
		t.Fatal("проверка ничего не значит: надписи нет")
	}
	t.Logf("надпись %.1f×%.1f", l.Size().Width, l.Size().Height)
	if l.Size().Width < qrErrMinWidth {
		t.Errorf("надпись узкая: %.1f т. — переносится по буквам", l.Size().Width)
	}
}
