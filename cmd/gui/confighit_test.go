package main

// «КОНФИГ ГОТОВ» С ПРОКРУТКОЙ (Д6) ПО БОЕВОМУ ПРАВИЛУ МЫШИ.
//
// Решение владельца 29.09.2026: текст и QR диалога — в прокрутке, кнопки
// действия — вне её. Два вопроса, оба про бой, а не про тестовый драйвер:
//
//  1. Кнопки «Сохранить .conf», «Скопировать путь», «Закрыть» ВИДНЫ целиком
//     в окне любого допустимого размера (стартовое и минимальное) — иначе
//     человек при минимальном окне их не найдёт.
//  2. Прокрутка не становится целью левого клика там, где видны кнопки и QR.
//     Цель ищется СПИСАННЫМ БОЕВЫМ предикатом (hittest_test.go,
//     findByBootPredicate): в Fyne 2.7.4 container.Scroll реализует только
//     fyne.Scrollable (колесо), а полосы прокрутки — Draggable/Mouseable;
//     ровно этот класс («объект с мышиным интерфейсом съедает клик») уже
//     стоил владельцу выделения строки.

import (
	"testing"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/driver/desktop"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
)

// configScene открывает «Конфиг готов» тем же путём, что прибор осмотра.
func configScene(t *testing.T, state, size string) (*ui, *widget.PopUp) {
	t.Helper()
	u := osmotrUI(t, theme.VariantLight)
	s := openConfig(state)(t, u, sizeWindow(u, size))
	osmotrFrame(s.root, s.mins)
	pop, ok := s.root.(*widget.PopUp)
	if !ok {
		t.Fatalf("проверка ничего не значит: корень сцены %T, а не диалог", s.root)
	}
	return u, pop
}

func absRect(o fyne.CanvasObject) rect {
	return rect{pos: fyne.CurrentApp().Driver().AbsolutePositionForObject(o), size: o.Size()}
}

// checkConfigClicks — общая часть главной проверки и канарейки.
func checkConfigClicks(t *testing.T, pop *widget.PopUp, buttons []string, errf func(string, ...any)) {
	t.Helper()
	frame := absRect(pop.Content)
	for _, name := range buttons {
		b := buttonByText(t, pop, name)
		r := absRect(b)
		if r.pos.Y < frame.pos.Y-0.5 || r.bottom() > frame.bottom()+0.5 || r.size.Height <= 0 {
			errf("кнопка «%s» видна не целиком: %v в рамке %v", name, r, frame)
			continue
		}
		c := fyne.NewPos(r.pos.X+r.size.Width/2, r.pos.Y+r.size.Height/2)
		if got := findByBootPredicate(pop, c); got != b {
			errf("левый клик по центру «%s» по боевому правилу достаётся %T, а не кнопке", name, got)
		}
	}
	var qr *canvas.Image
	var sc fyne.CanvasObject
	walkVisible(pop, func(o fyne.CanvasObject) {
		if i, ok := o.(*canvas.Image); ok && qr == nil {
			qr = i
		}
		if _, ok := o.(*container.Scroll); ok {
			sc = o
		}
		if _, ok := o.(mouseScroll); ok {
			sc = o
		}
	})
	if qr == nil || sc == nil {
		errf("проверка ничего не значит: QR %v, прокрутка %v", qr != nil, sc != nil)
		return
	}
	// Клик — в ВИДИМУЮ часть QR: пересечение с окном прокрутки (после
	// сохранения прокрутка доведена до конца, и QR виден частично).
	r, v := absRect(qr), absRect(sc)
	top, bottom := max(r.pos.Y, v.pos.Y), min(r.bottom(), v.bottom())
	if bottom-top < 1 {
		errf("проверка ничего не значит: QR не виден в прокрутке (%v, окно %v)", r, v)
		return
	}
	c := fyne.NewPos(r.pos.X+r.size.Width/2, (top+bottom)/2)
	// Под QR законная цель — сам модальный PopUp (его Tapped у модального
	// ничего не делает; так было и до прокрутки). Любая другая — перехват.
	if got := findByBootPredicate(pop, c); got != nil && got != fyne.CanvasObject(pop) {
		errf("левый клик по QR по боевому правилу достаётся %T — клик перехвачен", got)
	}
}

// TestConfigDialogClicksByBootRule — кнопки видны и получают клик, QR клик
// не перехватывает; оба состояния с разным набором кнопок, оба размера окна.
func TestConfigDialogClicksByBootRule(t *testing.T) {
	cases := []struct {
		state   string
		buttons []string
	}{
		{"", []string{"Сохранить .conf", "Закрыть"}},
		{"сохранён", []string{"Сохранить .conf", "Скопировать путь", "Закрыть"}},
	}
	for _, tc := range cases {
		for _, size := range osmotrSizes {
			t.Run(tc.state+"/"+size, func(t *testing.T) {
				_, pop := configScene(t, tc.state, size)
				checkConfigClicks(t, pop, tc.buttons, t.Errorf)
			})
		}
	}
}

// mouseScroll — прокрутка, которая ПЕРЕХВАТЫВАЕТ мышь (как ячейка с одним
// TappedSecondary в регрессе 23.09). Только для канарейки.
type mouseScroll struct{ *container.Scroll }

func (mouseScroll) MouseDown(*desktop.MouseEvent) {}
func (mouseScroll) MouseUp(*desktop.MouseEvent)   {}

// Канарейка: та же проверка обязана покраснеть, если прокрутка содержимого
// становится мышиной целью — клик по QR уходит ей.
func TestConfigDialogClicksCanaryMouseScroll(t *testing.T) {
	_, pop := configScene(t, "сохранён", "минимальный")
	var sc *container.Scroll
	walkVisible(pop, func(o fyne.CanvasObject) {
		if s, ok := o.(*container.Scroll); ok {
			sc = s
		}
	})
	if sc == nil {
		t.Fatal("канарейка ничего не значит: прокрутки в диалоге нет")
	}
	ms := mouseScroll{sc}
	replaceIn(t, pop, sc, ms)
	var errs []string
	checkConfigClicks(t, pop, []string{"Закрыть"}, func(f string, a ...any) {
		errs = append(errs, f)
		t.Logf("ПРОВЕРКА: "+f, a...)
	})
	if len(errs) == 0 {
		t.Error("проверка НЕ ПОКРАСНЕЛА на прокрутке, перехватывающей мышь")
	}
}

// TestConfigDialogNewTextInView — после сохранения и после отказа новое
// (последняя строка подсказки о новом месте / совета) видно в прокрутке, а
// не спрятано под её краем: при окне ниже 756 т. иначе человек его не увидит.
func TestConfigDialogNewTextInView(t *testing.T) {
	for _, tc := range []struct{ state, prefix string }{
		{"сохранён", "Это новое место."},
		{"отказ", `Пользователь "Телефон Анны" на сервере`},
	} {
		for _, size := range osmotrSizes {
			t.Run(tc.state+"/"+size, func(t *testing.T) {
				_, pop := configScene(t, tc.state, size)
				var sc *container.Scroll
				var l *widget.Label
				walkVisible(pop, func(o fyne.CanvasObject) {
					switch x := o.(type) {
					case *container.Scroll:
						sc = x
					case *widget.Label:
						if len(x.Text) >= len(tc.prefix) && x.Text[:len(tc.prefix)] == tc.prefix {
							l = x
						}
					}
				})
				if sc == nil || l == nil {
					t.Fatalf("проверка ничего не значит: прокрутка %v, подпись %v", sc != nil, l != nil)
				}
				v, r := absRect(sc), absRect(l)
				if r.pos.Y < v.pos.Y-0.5 || r.bottom() > v.bottom()+0.5 {
					t.Errorf("подпись «%s…» вне видимой части прокрутки: %v, видно %v", tc.prefix, r, v)
				}
			})
		}
	}
}
