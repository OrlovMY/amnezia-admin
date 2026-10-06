package main

import (
	"fmt"
	"strings"
	"testing"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/test"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
)

// TestServerLabelLongName — решение ядра: имя сервера в 253 символа на
// 972×517 и 1229×620 — подпись не вылезает за окно и не пересекается с
// «Протокол:» и списком (обрезка многоточием); по нажатию полный адрес —
// в буфер обмена и в строку состояния. Подмена «без обрезки» роняет тест.
func TestServerLabelLongName(t *testing.T) {
	host := strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 61)
	if len(host) != 253 {
		t.Fatalf("имя %d", len(host))
	}
	for _, size := range []fyne.Size{{Width: 972, Height: 517}, {Width: 1229, Height: 620}} {
		t.Run(fmt.Sprintf("%vx%v", size.Width, size.Height), func(t *testing.T) {
			u := osmotrUI(t, theme.VariantLight)
			osmotrMain(u)
			waitGUIGoroutines(t)
			u.sess.Creds.Host = host
			// как в TestProtoLabelFits: без выбранного протокола, чтобы
			// построение экрана не запускало refresh в фоне (гонка под -race)
			cur := u.cur
			u.cur = nil
			u.showMainScreen()
			u.cur = cur
			waitGUIGoroutines(t)
			u.win.Resize(size)
			osmotrFrame(u.win.Content(), nil)
			sl := u.serverLabel
			win := u.win.Canvas().Size()
			ar := absRect(sl)
			r := struct{ x, y, w, h float32 }{ar.pos.X, ar.pos.Y, ar.size.Width, ar.size.Height}
			if r.x < -0.5 || r.x+r.w > win.Width+0.5 {
				t.Errorf("подпись сервера вылезает: %+v в окне %v", r, win)
			}
			var proto fyne.CanvasObject
			walkObjects(u.protoRow, func(o fyne.CanvasObject) {
				if l, ok := o.(*widget.Label); ok && l.Text == "Протокол:" {
					proto = l
				}
			})
			for name, o := range map[string]fyne.CanvasObject{"Протокол:": proto, "список": u.protoSelect} {
				if o == nil {
					t.Fatalf("нет %s", name)
				}
				aq := absRect(o)
				q := struct{ x, y, w, h float32 }{aq.pos.X, aq.pos.Y, aq.size.Width, aq.size.Height}
				if r.x < q.x+q.w-0.5 && q.x < r.x+r.w-0.5 && r.y < q.y+q.h-0.5 && q.y < r.y+r.h-0.5 {
					t.Errorf("подпись сервера перекрывает «%s»: %+v × %+v", name, r, q)
				}
			}
			if sl.Truncation != fyne.TextTruncateEllipsis {
				t.Error("обрезка многоточием выключена")
			}
			test.Tap(sl)
			if got := fyne.CurrentApp().Clipboard().Content(); got != "root@"+host {
				t.Errorf("по нажатию в буфер: %q", got)
			}
			if !strings.Contains(u.status.Text, host) {
				t.Errorf("полный адрес не в строке состояния: %q", u.status.Text)
			}
		})
	}
}
