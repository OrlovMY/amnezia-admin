package main

import (
	"strings"
	"testing"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/theme"

	"amnezia-admin/core"
	"amnezia-admin/internal/guiview"
)

// TestCopyButtonInMainRow — отзыв владельца на 32d66c4: «Копия» (без
// многоточия) — в одном ряду с остальными кнопками главного окна.
// Подмена «отдельная строка» роняет тест.
func TestCopyButtonInMainRow(t *testing.T) {
	u := osmotrUI(t, theme.VariantLight)
	osmotrMain(u)
	sizeWindow(u, "стартовый")()
	cp := buttonByText(t, u.win.Content(), "Копия")
	del := buttonByText(t, u.win.Content(), "Удалить")
	if findParent(u.win.Content(), cp) != findParent(u.win.Content(), del) {
		t.Error("«Копия» не в общем ряду кнопок")
	}
	pc := fyne.CurrentApp().Driver().AbsolutePositionForObject(cp)
	pd := fyne.CurrentApp().Driver().AbsolutePositionForObject(del)
	if pc.Y != pd.Y || pc.X <= pd.X {
		t.Errorf("«Копия» не рядом с «Удалить» в одном ряду: %v %v", pc, pd)
	}
}

// TestProtoSelectWidthByContent — список протоколов по ширине самого
// длинного пункта (не уже — пункт не усечён, не шире — не на всю строку) и
// заметно уже строки на 1229×620. Подмена «растягивать на всю строку»
// роняет тест.
func TestProtoSelectWidthByContent(t *testing.T) {
	u := osmotrUI(t, theme.VariantLight)
	osmotrMain(u)
	sizeWindow(u, "стартовый")()
	sel := u.protoSelect
	longest := float32(0)
	for _, o := range sel.Options {
		if w := fyne.MeasureText(o, theme.TextSize(), fyne.TextStyle{}).Width; w > longest {
			longest = w
		}
	}
	pad := 4*theme.InnerPadding() + theme.IconInlineSize() + 1
	w, row := sel.Size().Width, u.protoRow.Size().Width
	t.Logf("список %.1f т., самый длинный пункт %.1f т., строка %.1f т.", w, longest, row)
	if w+0.5 < longest || w > longest+pad+0.5 && w > sel.MinSize().Width+0.5 {
		t.Errorf("ширина списка %.1f не по содержимому (пункт %.1f, запас %.1f)", w, longest, pad)
	}
	if w > row/2 {
		t.Errorf("список на полстроки и шире: %.1f из %.1f", w, row)
	}
}

// TestProtoShortLabelReasonInStatus — в пункте списка причины нет; при
// выборе полная подпись с причиной — в строке состояния (текст не теряется).
func TestProtoShortLabelReasonInStatus(t *testing.T) {
	c := core.Container{Name: "amnezia-awg2", Dir: "/opt/amnezia/awg", Proto: "AmneziaWG", Reason: "на сервере незнакомый параметр «Zz»", Support: core.SupportKnownNo}
	short, full := guiview.ProtoShortLabel(c), guiview.ProtoLabel(c)
	if strings.Contains(short, c.Reason) || !strings.Contains(full, c.Reason) {
		t.Fatalf("короткая %q, полная %q", short, full)
	}
	if st := guiview.ViewState(c, nil, true, nil).Status; !strings.Contains(st, full) {
		t.Errorf("в строке состояния нет полной подписи с причиной: %q", st)
	}
}
