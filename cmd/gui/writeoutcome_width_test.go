package main

// A3б PR-3, раунд 4 (механизация AU-UX): запас ширины диалога исхода записи
// под заголовок. Заголовок диалога Fyne не переносится — удлинённый заголовок
// растягивает рамку (так нашёлся Т3-б: 581.8 т. при 472). Тест ловит это
// числом, а не глазом: для КАЖДОГО исхода настоящий диалог u.showError
// сохраняет рамку writeErrorDialogWidth − 8, и между шириной заголовка и
// рамкой остаётся не меньше titleHeadroom.

import (
	"errors"
	"testing"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/widget"

	"amnezia-admin/internal/writeoutcome"
)

// titleHeadroom — минимальный запас (т.) между заголовком и рамкой.
const titleHeadroom = 16

func TestWriteOutcomeTitleFits(t *testing.T) {
	all := writeoutcome.All()
	if len(all) < 12 {
		t.Fatalf("проверка ПЕРЕСТАЛА ЧТО-ЛИБО ЗНАЧИТЬ: текстов исходов %d", len(all))
	}
	var worst float32 = 1e9
	worstTitle := ""
	for _, tx := range all {
		u := focusTestUI(t)
		osmotrMain(u)
		u.win.Resize(fyne.NewSize(1194.2, 517))
		// Диалог строится тем же кодом, что и в бою; ошибка — любая: заголовок
		// берётся из текста, подставленного через перехват Describe невозможен,
		// поэтому строим диалог напрямую тем же способом, что showError.
		showWriteOutcomeDialog(u, tx, errors.New("подробности"))
		pop := topPopup(t, u.win.Canvas())
		frame := pop.Content.Size().Width
		var title *widget.Label
		walkObjects(pop, func(o fyne.CanvasObject) {
			if l, ok := o.(*widget.Label); ok && l.Text == tx.Title {
				title = l
			}
		})
		if title == nil {
			t.Fatalf("заголовок %q в диалоге не найден", tx.Title)
		}
		if want := float32(writeErrorDialogWidth - 8); frame > want+0.5 {
			t.Errorf("заголовок %q растянул диалог: рамка %.1f, задано %.1f", tx.Title, frame, want)
		}
		if room := frame - title.MinSize().Width; room < worst {
			worst, worstTitle = room, tx.Title
		}
	}
	t.Logf("наименьший запас %.1f т. — заголовок %q", worst, worstTitle)
	if worst < titleHeadroom {
		t.Errorf("запас ширины под заголовок %.1f т. (%q) меньше %d т.", worst, worstTitle, titleHeadroom)
	}
}
