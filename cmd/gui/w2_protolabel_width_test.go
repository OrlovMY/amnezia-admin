package main

// W2 раунд 2 (UX-01 Р4): выбранная подпись протокола помещается в поле
// списка на окне 1194×517 — для самой длинной подписи закрытого списка и для
// незнакомого контейнера с именем в 40 символов. Мерится числом: ширина
// текста подписи против ширины поля, и правый край поля — в пределах окна.

import (
	"strings"
	"testing"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"amnezia-admin/core"
	"amnezia-admin/internal/guiview"
)

func TestProtoLabelFits(t *testing.T) {
	cs := core.KnownContainers()
	if len(cs) < 16 {
		t.Fatalf("проверка ПЕРЕСТАЛА ЧТО-ЛИБО ЗНАЧИТЬ: контейнеров %d", len(cs))
	}
	longest := cs[0]
	for _, c := range cs {
		if len([]rune(guiview.ProtoLabel(c))) > len([]rune(guiview.ProtoLabel(longest))) {
			longest = c
		}
	}
	unknown := core.Container{Name: "amnezia-" + strings.Repeat("x", 40-len("amnezia-")), Support: core.SupportUnknown}
	if len(unknown.Name) != 40 {
		t.Fatalf("имя %d символов", len(unknown.Name))
	}
	for _, c := range []core.Container{longest, unknown} {
		label := guiview.ProtoLabel(c)
		u := focusTestUI(t)
		osmotrMain(u)
		u.containers = []core.Container{c}
		u.cur = &u.containers[0]
		u.showMainScreen()
		u.protoSelect.Selected = u.protoSelect.Options[0]
		u.protoSelect.Refresh()
		u.win.Resize(fyne.NewSize(1194.2, 517))
		sel := u.protoSelect
		var text fyne.CanvasObject
		walkObjects(sel, func(o fyne.CanvasObject) {
			switch x := o.(type) {
			case *canvas.Text:
				if x.Text == label {
					text = x
				}
			case *widget.RichText:
				if x.String() == label {
					text = x
				}
			}
		})
		if text == nil {
			t.Fatalf("подпись %q в поле не найдена", label)
		}
		// MinSize усечённого текста мала (многоточие) — меряем ПОЛНУЮ ширину строки
		need := fyne.MeasureText(label, theme.TextSize(), fyne.TextStyle{}).Width
		have := text.Size().Width
		pos := fyne.CurrentApp().Driver().AbsolutePositionForObject(sel)
		right, win := pos.X+sel.Size().Width, u.win.Canvas().Size().Width
		t.Logf("%q: текст %.1f т., отведено %.1f т., поле %.1f т., правый край %.1f из %.1f",
			label, need, have, sel.Size().Width, right, win)
		if have+0.5 < need {
			t.Errorf("подпись %q обрезана: текст %.1f т., отведено %.1f т.", label, need, have)
		}
		if right > win+0.5 {
			t.Errorf("поле с %q выходит за окно: правый край %.1f при ширине %.1f", label, right, win)
		}
	}
}
