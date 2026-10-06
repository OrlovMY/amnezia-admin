package main

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/test"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/widget"

	"amnezia-admin/core"
	"amnezia-admin/internal/fakesrv"
)

var uxSizes = []fyne.Size{{Width: 1229, Height: 620}, {Width: 972, Height: 517}}

// buttonsFullyVisible — все кнопки и галки верхнего окна целиком в окне
// программы (сторож видимости AU-UX H1).
func buttonsFullyVisible(t *testing.T, u *ui, form string) int {
	t.Helper()
	pop := topPopup(t, u.win.Canvas())
	osmotrFrame(pop, nil)
	win := u.win.Canvas().Size()
	// окно обязано помещаться по МИНИМАЛЬНОМУ размеру: иначе Fyne обрежет
	// его по окну программы, и часть содержимого (не прокручиваемая) уйдёт
	// за край, хотя кнопки останутся на месте.
	if m := pop.Content.MinSize(); m.Width > win.Width+0.5 || m.Height > win.Height+0.5 {
		t.Errorf("%s: окно не помещается: минимальный размер %v больше окна программы %v", form, m, win)
	}
	// AU-UX р2 Р2-1: заданный размер окна — не больше окна программы.
	if rs, ok := requestedSize[lastSizedDialog]; ok && (rs.Width > win.Width+0.5 || rs.Height > win.Height+0.5) {
		t.Errorf("%s: заданный размер окна %v больше окна программы %v", form, rs, win)
	}
	textFullyAvailable(t, pop, form)
	n := 0
	walkObjects(pop, func(o fyne.CanvasObject) {
		var name string
		switch b := o.(type) {
		case *widget.Button:
			name = b.Text
		case *escButton:
			name = b.Text
		default:
			return
		}
		if !o.Visible() {
			return
		}
		n++
		p := fyne.CurrentApp().Driver().AbsolutePositionForObject(o)
		s := o.Size()
		if p.X < -0.5 || p.Y < -0.5 || p.X+s.Width > win.Width+0.5 || p.Y+s.Height > win.Height+0.5 || s.Height < 1 {
			t.Errorf("%s: кнопка %q не видна целиком: %v %v в окне %v", form, name, p, s, win)
		}
	})
	return n
}

// TestBackupWindowsVisible — AU-UX H1: все пять окон копии на обоих
// размерах окна программы — кнопки видны целиком.
func TestBackupWindowsVisible(t *testing.T) {
	for _, size := range uxSizes {
		t.Run(fmt.Sprintf("%vx%v", size.Width, size.Height), func(t *testing.T) {
			u, _, _, p := guiMigration(t, "198.51.100.9")
			u.win.Resize(size)
			forms := []struct {
				name string
				open func()
			}{
				{"меню «Копия…»", func() { u.backupMenu() }},
				{"сохранение", func() { u.backupDialog() }},
				{"сохранение с паролем", func() { u.backupDialog().mode.SetSelected(backupWithPassword) }},
				{"сохранение без пароля", func() { u.backupDialog().mode.SetSelected(backupNoPassword) }},
				{"пароль зашифрованной копии", func() { u.passwordPrompt(func(core.Secret) {}) }},
				{"прогресс", func() {
					v := u.progressWindow("Сохранение копии сервера", func() {})
					v.apply(core.Progress{Stage: core.StageRead, Done: 5, Total: 16, Text: "прочитано файлов 5 из 16 — amnezia-awg (проход 1 из 2)"})
				}},
				{"итог копии", func() {
					dir, _ := core.UserBackupsDir()
					path, b, err := u.runBackupTo(dir, time.Now(), core.PlainLayer{})
					u.backupResult(path, b, err)
				}},
				{"восстановление", func() {
					b, compat, rp, planErr, err := u.restorePrepare(p)
					if err != nil {
						t.Fatal(err)
					}
					u.restoreWindow(b, compat, rp, planErr)
				}},
				{"восстановление, «Подробнее о копии» раскрыто", func() {
					b, compat, rp, planErr, err := u.restorePrepare(p)
					if err != nil {
						t.Fatal(err)
					}
					v := u.restoreWindow(b, compat, rp, planErr)
					v.details.Open(0) // свёрнутое доступно раскрытием — и тогда видно целиком
				}},
				{"итог восстановления", func() {
					// длинный итог: текст заведомо выше окна — проверяется,
					// что он в прокрутке, а не обрезан
					var outs []core.RestoreOutcome
					for i := 0; i < 25; i++ {
						outs = append(outs, core.RestoreOutcome{Container: fmt.Sprintf("amnezia-awg-%d", i), State: core.RestoreDone, Checked: core.RestoreCheckedWG})
					}
					u.restoreResult("/tmp/a.aabk", outs, nil)
				}},
			}
			for _, f := range forms {
				f.open()
				if n := buttonsFullyVisible(t, u, f.name); n == 0 {
					t.Errorf("%s: кнопок не найдено — сторож ничего не проверил", f.name)
				}
				for u.win.Canvas().Overlays().Top() != nil {
					u.win.Canvas().Overlays().Remove(u.win.Canvas().Overlays().Top())
				}
			}
		})
	}
}

// TestRestoreWindowFocusEsc — AU-UX H1: «Отмена» и «Заменить данные
// сервера» внизу рядом, фокус на «Отмена», Esc (через фокус) — отмена, ни
// одной записи.
func TestRestoreWindowFocusEsc(t *testing.T) {
	for _, size := range uxSizes {
		t.Run(fmt.Sprintf("%vx%v", size.Width, size.Height), func(t *testing.T) {
			u, _, tgt, p := guiMigration(t, "203.0.113.1")
			u.win.Resize(size)
			b, compat, rp, planErr, err := u.restorePrepare(p)
			if err != nil {
				t.Fatal(err)
			}
			v := u.restoreWindow(b, compat, rp, planErr)
			pop := topPopup(t, u.win.Canvas())
			osmotrFrame(pop, nil)
			cancel := xrayButton(t, pop, "Отмена")
			ok := xrayButton(t, pop, restoreApplyText)
			if ok != v.apply || ok.Importance != widget.DangerImportance {
				t.Error("кнопка замены — не опасного вида или не та")
			}
			if u.win.Canvas().Focused() != cancel {
				t.Errorf("фокус не на «Отмена»: %T", u.win.Canvas().Focused())
			}
			pc := fyne.CurrentApp().Driver().AbsolutePositionForObject(cancel)
			po := fyne.CurrentApp().Driver().AbsolutePositionForObject(ok)
			if pc.Y != po.Y || po.X <= pc.X {
				t.Errorf("кнопки не рядом в одном ряду: %v %v", pc, po)
			}
			buttonsFullyVisible(t, u, "восстановление")
			deliverKey(u.win.Canvas(), fyne.KeyEscape)
			waitGUIGoroutines(t)
			if u.win.Canvas().Overlays().Top() != nil || writesGUI(tgt) != 0 {
				t.Fatalf("Esc не отменил: оверлей %v, записей %d", u.win.Canvas().Overlays().Top(), writesGUI(tgt))
			}
		})
	}
}

func writesGUI(s *fakesrv.Server) int {
	n := 0
	for _, c := range s.Commands() {
		if strings.Contains(c, "flock -w") {
			n++
		}
	}
	return n
}

// TestRestoreWindowXRayChoice — AU-UX M1, р2 Р2-2: план с XRay —
// переключатель «одно из двух» без выбора по умолчанию; кнопка выключена до
// выбора.
func TestRestoreWindowXRayChoice(t *testing.T) {
	mk := func() *fakesrv.Server {
		s := fakesrv.NewXRay("master")
		for _, k := range []string{"xray_short_id.key", "xray_public.key", "xray_private.key"} {
			s.SetFile("/opt/amnezia/xray/"+k, []byte(fakesrv.RandUUID()))
		}
		return s
	}
	src, tgt := mk(), mk()
	b, _ := core.NewSessionWithRunner(src, &core.ServerCreds{Host: "203.0.113.1"}).CollectBackup("t", time.Now(), nil)
	u := backupUI(t, tgt, "203.0.113.1")
	compat, _ := u.sess.CheckTarget(b, backupResolve)
	rp, err := u.sess.PlanRestore(b, compat, true)
	if err != nil {
		t.Fatal(err)
	}
	v := u.restoreWindow(b, compat, rp, nil)
	if v.xrayRadio == nil || v.xrayRadio.Selected != "" || !v.apply.Disabled() {
		t.Fatalf("без выбора про XRay: переключатель %v, выбрано %q, выключена=%v", v.xrayRadio != nil, v.xrayRadio.Selected, v.apply.Disabled())
	}
	if len(v.xrayRadio.Options) != 2 || !strings.Contains(v.text+topOverlay(t, u), restoreXRayHint) {
		t.Errorf("переключатель/подсказка: %v", v.xrayRadio.Options)
	}
	v.xrayRadio.SetSelected(restoreXRayCheck)
	if v.apply.Disabled() {
		t.Error("выбран перезапуск — кнопка не включилась")
	}
	v.xrayRadio.SetSelected(restoreSkipXRay)
	if v.apply.Disabled() {
		t.Error("выбран перенос без XRay — кнопка не включилась")
	}
	v.xrayRadio.SetSelected("")
	if !v.apply.Disabled() {
		t.Error("выбор снят — кнопка осталась включена")
	}
}

// TestRestoreWindowRemovedFirst — AU-UX M2: удаляемые клиенты — первым
// разделом, до сводки копии; при СТОП — расхождения нумерованным списком.
func TestRestoreWindowRemovedFirst(t *testing.T) {
	u, _, tgt, p := guiMigration(t, "203.0.113.1")
	b, compat, rp, planErr, _ := u.restorePrepare(p)
	v := u.restoreWindow(b, compat, rp, planErr)
	rm := strings.Index(v.text, "Будут УДАЛЕНЫ клиенты нового сервера")
	if rm != 0 {
		t.Errorf("раздел удаляемых не первым (позиция %d):\n%s", rm, v.text)
	}
	wg, _ := tgt.File("/opt/amnezia/awg/wg0.conf")
	tgt.SetFile("/opt/amnezia/awg/wg0.conf", []byte(strings.Replace(string(wg), "ListenPort = 51820", "ListenPort = 40000", 1)))
	b, compat, rp, planErr, _ = u.restorePrepare(p)
	v = u.restoreWindow(b, compat, rp, planErr)
	if !strings.HasPrefix(v.text, "ПЕРЕЕЗД ОСТАНОВЛЕН") || !strings.Contains(v.text, "  1. amnezia-awg, порт:") {
		t.Errorf("СТОП — расхождения не списком первым:\n%s", v.text)
	}
}

// textFullyAvailable — AU-UX р2 Р2-1: каждая многострочная подпись либо
// внутри прокрутки, либо после раскладки не меньше нужного ей размера.
func textFullyAvailable(t *testing.T, root fyne.CanvasObject, form string) {
	t.Helper()
	n := 0
	var walk func(o fyne.CanvasObject, inScroll bool)
	walk = func(o fyne.CanvasObject, inScroll bool) {
		if o == nil || !o.Visible() {
			return
		}
		if _, ok := o.(*container.Scroll); ok {
			inScroll = true
		}
		if l, ok := o.(*widget.Label); ok && l.Wrapping != fyne.TextWrapOff && strings.TrimSpace(l.Text) != "" {
			n++
			if !inScroll && l.Size().Height+0.5 < l.MinSize().Height {
				t.Errorf("%s: текст обрезан и вне прокрутки (высота %.1f < нужной %.1f): %.60q", form, l.Size().Height, l.MinSize().Height, l.Text)
			}
		}
		switch x := o.(type) {
		case *fyne.Container:
			for _, c := range x.Objects {
				walk(c, inScroll)
			}
		case fyne.Widget:
			for _, c := range test.WidgetRenderer(x).Objects() {
				walk(c, inScroll)
			}
		}
	}
	walk(root, false)
	if n == 0 {
		t.Errorf("%s: многострочных подписей не найдено — сторож текста ничего не проверил", form)
	}
}
