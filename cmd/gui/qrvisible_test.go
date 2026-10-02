package main

// СТОРОЖ: QR виден ЦЕЛИКОМ при открытии окна (АУДИТ-МЕНЮ-QR-UX, Н1).
// Прибор меряет прокрутку одним атомом и срезанный QR не видел: окно было
// «ДЕЙСТВИТЕЛЬНО», а код — наполовину за краем, и отсканировать его нельзя.
// Для каждого окна с QR, на обоих размерах и в обеих темах: QR (картинка
// «*-qr.png») лежит внутри видимой части своей прокрутки, а если прокрутки
// над ним нет — внутри рамки диалога; видимая высота = 256.

import (
	"fmt"
	"strings"
	"testing"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/test"
	"fyne.io/fyne/v2/widget"
)

// qrForms — окна, где QR должен быть виден при открытии (без нажатий).
var qrForms = []string{
	"(д) конфиг готов",
	"(д) конфиг готов, сохранён",
	"(д) конфиг готов, отказ сохранения",
	"(д) конфиг готов, отказ с длинным путём",
	"(м) конфигурация: найден, ключ сервера сверен",
}

// qrAfterTap — окна, где QR показывается по кнопке: нажать, затем мерить.
var qrAfterTap = map[string]string{
	"(м) конфигурация: найден, чужой сервер":           "Всё равно показать QR",
	"(м) конфигурация: найден, ключ сервера не сверен": "Показать QR — ключ сервера не сверен",
}

// qrVisibleHeight — видимая высота QR и где он лежит.
func qrVisibleHeight(pop *widget.PopUp) (visible, full float32, where string, found bool) {
	var img *canvas.Image
	var parents []fyne.CanvasObject
	var walk func(o fyne.CanvasObject, path []fyne.CanvasObject)
	walk = func(o fyne.CanvasObject, path []fyne.CanvasObject) {
		if img != nil || o == nil || !o.Visible() {
			return
		}
		if im, ok := o.(*canvas.Image); ok && im.Resource != nil && strings.HasSuffix(im.Resource.Name(), "-qr.png") {
			img = im
			parents = append([]fyne.CanvasObject(nil), path...)
			return
		}
		var kids []fyne.CanvasObject
		switch x := o.(type) {
		case *fyne.Container:
			kids = x.Objects
		case *container.Scroll:
			kids = []fyne.CanvasObject{x.Content}
		case fyne.Widget:
			kids = test.WidgetRenderer(x).Objects()
		}
		for _, k := range kids {
			walk(k, append(path, o))
		}
	}
	walk(pop, nil)
	if img == nil {
		return 0, 0, "", false
	}
	d := fyne.CurrentApp().Driver()
	ip, is := d.AbsolutePositionForObject(img), img.Size()
	top, bottom := ip.Y, ip.Y+is.Height
	clipTop, clipBottom := float32(-1e9), float32(1e9)
	where = "рамка диалога"
	cp, cs := d.AbsolutePositionForObject(pop.Content), pop.Content.Size()
	clipTop, clipBottom = cp.Y, cp.Y+cs.Height
	for i := len(parents) - 1; i >= 0; i-- {
		if sc, ok := parents[i].(*container.Scroll); ok {
			sp := d.AbsolutePositionForObject(sc)
			clipTop, clipBottom = max(clipTop, sp.Y), min(clipBottom, sp.Y+sc.Size().Height)
			where = "прокрутка"
			break
		}
	}
	v := min(bottom, clipBottom) - max(top, clipTop)
	if v < 0 {
		v = 0
	}
	return v, is.Height, where, true
}

func TestQRFullyVisible(t *testing.T) {
	type job struct {
		name, tap string
	}
	var jobs []job
	for _, n := range qrForms {
		jobs = append(jobs, job{n, ""})
	}
	for n, b := range qrAfterTap {
		jobs = append(jobs, job{n, b})
	}
	for _, j := range jobs {
		f := formByName(t, j.name)
		for _, size := range osmotrSizes {
			for _, th := range osmotrThemes {
				t.Run(fmt.Sprintf("%s/%s/%s", j.name, size, th.name), func(t *testing.T) {
					u := osmotrUI(t, th.v)
					s := f.open(t, u, sizeWindow(u, size))
					osmotrFrame(s.root, s.mins)
					pop, ok := s.root.(*widget.PopUp)
					if !ok {
						t.Fatalf("проверка ничего не значит: корень %T", s.root)
					}
					if j.tap != "" {
						test.Tap(buttonByText(t, pop, j.tap))
						osmotrFrame(pop, nil)
					}
					v, full, where, found := qrVisibleHeight(pop)
					if !found {
						t.Fatal("проверка ничего не значит: QR в окне нет")
					}
					t.Logf("QR: видно %.1f из %.1f (%s)", v, full, where)
					if full < 256 || v < full-0.5 {
						t.Errorf("QR срезан: видно %.1f из %.1f (%s) — отсканировать нельзя", v, full, where)
					}
				})
			}
		}
	}
}
