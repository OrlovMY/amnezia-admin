package main

import (
	"fmt"
	"strings"
	"testing"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/theme"
)

// serverLabelScreen — главное окно с адресом host на размере size.
func serverLabelScreen(t *testing.T, host string, size fyne.Size) *ui {
	t.Helper()
	u := osmotrUI(t, theme.VariantLight)
	osmotrMain(u)
	waitGUIGoroutines(t)
	u.sess.Creds.Host = host
	cur := u.cur
	u.cur = nil
	u.showMainScreen()
	u.cur = cur
	waitGUIGoroutines(t)
	u.win.Resize(size)
	osmotrFrame(u.win.Content(), nil)
	return u
}

// TestServerLabelVisible — QA-01 р2 Н1: подпись сервера не только не
// мешает, но и ВИДНА: короткий адрес — целиком (ширина подписи не меньше
// ширины текста); длинный — обрезан по доступной ширине (подпись шире
// половины свободного места строки), а не до одного многоточия. Подмена
// «прежняя разметка HBox с распоркой» (подпись получает ширину «…»)
// роняет тест.
func TestServerLabelVisible(t *testing.T) {
	long := strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 61)
	for _, size := range []fyne.Size{{Width: 972, Height: 517}, {Width: 1229, Height: 620}} {
		t.Run(fmt.Sprintf("%vx%v короткий", size.Width, size.Height), func(t *testing.T) {
			u := serverLabelScreen(t, "203.0.113.10", size)
			sl := u.serverLabel
			need := fyne.MeasureText(sl.Text, theme.TextSize(), sl.TextStyle).Width
			if sl.Size().Width+0.5 < need {
				t.Errorf("короткий адрес обрезан: подпись %.1f т., текст %.1f т. (%q)", sl.Size().Width, need, sl.Text)
			}
		})
		t.Run(fmt.Sprintf("%vx%v длинный", size.Width, size.Height), func(t *testing.T) {
			u := serverLabelScreen(t, long, size)
			sl := u.serverLabel
			var left fyne.CanvasObject
			for _, o := range u.protoRow.Objects {
				if o != sl && o != u.serverCopy {
					left = o
				}
			}
			if left == nil {
				t.Fatal("нет левой части строки")
			}
			free := u.protoRow.Size().Width - left.Size().Width - u.serverCopy.Size().Width
			t.Logf("подпись %.1f т., свободно %.1f т.", sl.Size().Width, free)
			if sl.Size().Width < free/2 {
				t.Errorf("длинный адрес обрезан почти до многоточия: подпись %.1f т. при свободных %.1f т.", sl.Size().Width, free)
			}
		})
	}
}
