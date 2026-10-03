package main

// Финальный раунд (AU-UX М1): строка честности AmneziaWG 2 в «Конфиг готов»
// видна при открытии ЦЕЛИКОМ, без прокрутки, на обоих размерах окна и в обеих
// темах. По образцу TestQRFullyVisible: мерится числом — верх и низ подписи
// против видимой области прокрутки, в которой она лежит.

import (
	"fmt"
	"testing"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/test"
	"fyne.io/fyne/v2/widget"

	"amnezia-admin/core"
)

func TestAWG2NoteFullyVisible(t *testing.T) {
	f := formByName(t, "(д) конфиг готов, AmneziaWG 2")
	for _, size := range osmotrSizes {
		for _, th := range osmotrThemes {
			t.Run(fmt.Sprintf("%s/%s", size, th.name), func(t *testing.T) {
				u := osmotrUI(t, th.v)
				s := f.open(t, u, sizeWindow(u, size))
				osmotrFrame(s.root, s.mins)
				top, bottom, vTop, vBottom, where := awg2NoteSpan(t, s.root)
				t.Logf("строка честности %.1f..%.1f, видно %.1f..%.1f (%s)", top, bottom, vTop, vBottom, where)
				if top < vTop-0.5 || bottom > vBottom+0.5 {
					t.Errorf("строка честности не видна целиком при открытии: %.1f..%.1f, видно %.1f..%.1f (%s)", top, bottom, vTop, vBottom, where)
				}
			})
		}
	}
}

// awg2NoteSpan — вертикальные границы подписи AWG2ConfigNote и видимой
// области: прокрутки, если подпись в ней, иначе всего диалога.
func awg2NoteSpan(t *testing.T, root fyne.CanvasObject) (top, bottom, vTop, vBottom float32, where string) {
	t.Helper()
	var note *widget.Label
	var scroll *container.Scroll
	var walk func(o fyne.CanvasObject, sc *container.Scroll)
	walk = func(o fyne.CanvasObject, sc *container.Scroll) {
		if o == nil || !o.Visible() || note != nil {
			return
		}
		if s, ok := o.(*container.Scroll); ok {
			sc = s
		}
		if l, ok := o.(*widget.Label); ok && l.Text == core.AWG2ConfigNote {
			note, scroll = l, sc
			return
		}
		for _, k := range childrenOf(o) {
			walk(k, sc)
		}
	}
	walk(root, nil)
	if note == nil {
		t.Fatal("проверка ничего не значит: строки честности в окне нет")
	}
	d := fyne.CurrentApp().Driver()
	top = d.AbsolutePositionForObject(note).Y
	bottom = top + note.Size().Height
	area := root
	where = "диалог"
	if scroll != nil {
		area, where = scroll, "прокрутка"
	}
	vTop = d.AbsolutePositionForObject(area).Y
	vBottom = vTop + area.Size().Height
	return
}

// childrenOf — непосредственные дети объекта (как в walkObjects).
func childrenOf(o fyne.CanvasObject) []fyne.CanvasObject {
	switch x := o.(type) {
	case *fyne.Container:
		return x.Objects
	case fyne.Widget:
		return test.WidgetRenderer(x).Objects()
	}
	return nil
}
