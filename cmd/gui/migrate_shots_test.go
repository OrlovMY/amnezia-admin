package main

// Снимки окон переноса (UI-01): тестовый драйвер Fyne, GUI не запускается.
// PNG пишутся только при MIGRATE_SHOTS_DIR (в обычном прогоне файлов нет);
// измерения и проверки «без горизонтальной прокрутки, окно на канве»
// выполняются всегда.

import (
	"image/png"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"

	"amnezia-admin/internal/fakesrv"
)

// shot — снимок верхнего окна и замеры числами.
func (f *migFixture) shot(t *testing.T, name string, keyLines []string) {
	t.Helper()
	c := f.u.win.Canvas()
	top := c.Overlays().Top()
	if top == nil {
		t.Fatalf("%s: окна нет", name)
	}
	osmotrFrame(top, nil)
	cs := c.Size()
	var pop fyne.CanvasObject = top
	if p, ok := top.(*widget.PopUp); ok {
		pop = p.Content
	}
	drv := fyne.CurrentApp().Driver()
	ppos := drv.AbsolutePositionForObject(pop)
	psz := pop.Size()
	t.Logf("[%s] канва %.0fx%.0f; окно %.0fx%.0f в (%.0f,%.0f)", name, cs.Width, cs.Height, psz.Width, psz.Height, ppos.X, ppos.Y)
	if ppos.X < 0 || ppos.Y < 0 || ppos.X+psz.Width > cs.Width+0.5 || ppos.Y+psz.Height > cs.Height+0.5 {
		t.Errorf("[%s] окно выходит за канву", name)
	}
	walkObjects(top, func(o fyne.CanvasObject) {
		sc, ok := o.(*container.Scroll)
		if !ok {
			return
		}
		cm, ss := sc.Content.MinSize(), sc.Size()
		if ss.Width <= 0 || ss.Height <= 0 {
			return // скрытая строка (поля пароля не выбраны)
		}
		t.Logf("[%s] прокрутка: область %.0fx%.0f, содержимое min %.0fx%.0f (вертикальная нужна: %v)", name, ss.Width, ss.Height, cm.Width, cm.Height, cm.Height > ss.Height+0.5)
		if cm.Width > ss.Width+0.5 {
			t.Errorf("[%s] нужна ГОРИЗОНТАЛЬНАЯ прокрутка: содержимое %.0f шире области %.0f", name, cm.Width, ss.Width)
		}
	})
	walkObjects(top, func(o fyne.CanvasObject) {
		var txt string
		switch x := o.(type) {
		case *escButton:
			txt = "[" + x.Text + "]"
		case *widget.Label:
			txt = x.Text
		default:
			return
		}
		for _, k := range keyLines {
			if !strings.Contains(txt, k) {
				continue
			}
			p, s := drv.AbsolutePositionForObject(o), o.Size()
			in := p.X >= ppos.X-0.5 && p.Y >= ppos.Y-0.5 && p.X+s.Width <= ppos.X+psz.Width+0.5 && p.Y+s.Height <= ppos.Y+psz.Height+0.5
			t.Logf("[%s] «%s» (%.0f,%.0f) %.0fx%.0f, внутри окна: %v", name, firstN(k, 40), p.X, p.Y, s.Width, s.Height, in)
		}
	})
	if dir := os.Getenv("MIGRATE_SHOTS_DIR"); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		fp, err := os.Create(filepath.Join(dir, name+".png"))
		if err != nil {
			t.Fatal(err)
		}
		defer fp.Close()
		if err := png.Encode(fp, c.Capture()); err != nil {
			t.Fatal(err)
		}
	}
}

func firstN(s string, n int) string {
	r := []rune(s)
	if len(r) > n {
		return string(r[:n])
	}
	return s
}

// TestGUIMigrateShots — окно подтверждения, три итога и остановка по клону.
func TestGUIMigrateShots(t *testing.T) {
	keys := []string{"Источник (только чтение)", "Цель (сюда будет записано)", migrateNoDiskText, "[" + migrateApplyText + "]", "[Отмена]"}
	f := newMigFixture(t, migTestDstHost, "SHA256:srcfp0123456789abcdefghijklmnopqrstuvwxyzABCDE", "SHA256:dstfp0123456789abcdefghijklmnopqrstuvwxyzABCDE")
	f.start(t)
	f.shot(t, "1-окно-подтверждения", keys)
	f.u.migShown.mode.SetSelected(backupNoPassword)
	f.u.migShown.addrCheck.SetChecked(true)
	f.shot(t, "1b-окно-подтверждения-выбран-режим", append(keys, "недоступна", "Всё подтверждено"))

	// худший случай: адрес + XRay + пароль, окно 900x600
	x := newMigFixtureOn(t, xrayMigServer(), xrayMigServer(), migTestDstHost, realFpSrc, realFpDst)
	x.u.win.Resize(fyne.NewSize(900, 600))
	x.start(t)
	pin := []string{"недоступна", "Всё подтверждено", "[" + migrateApplyText + "]", "[Отмена]", "Источник (только чтение)"}
	x.shot(t, "6-худший-случай-900x600-начало", pin)
	x.u.migShown.addrCheck.SetChecked(true)
	x.u.migShown.xrayRadio.SetSelected(migrateXRayRestart)
	x.u.migShown.mode.SetSelected(backupWithPassword)
	x.shot(t, "6b-худший-случай-900x600-пароль", pin)
	x.u.migShown.pw.SetText("автокопия-пароль-12345")
	x.u.migShown.pw2.SetText("автокопия-пароль-12345")
	x.shot(t, "6c-худший-случай-900x600-готово", pin)

	res := []string{"ПЕРЕНЕСЕНО", "НЕ ПЕРЕНЕСЕНО", "НЕИЗВЕСТНО", "Старый сервер продолжает работать", "Автокопия НОВОГО сервера", "[Закрыть]"}
	for _, c := range []struct {
		name string
		prep func(*fakesrv.Server)
	}{
		{"2-итог-перенесено", func(*fakesrv.Server) {}},
		{"3-итог-не-перенесено", func(s *fakesrv.Server) { s.LockBusy = true }},
		{"4-итог-неизвестно", func(s *fakesrv.Server) { s.WriteFault = map[int]fakesrv.WriteFault{1: {Code: 124}} }},
	} {
		g := newMigFixture(t, migTestDstHost, "SHA256:srcfp", "SHA256:dstfp")
		g.start(t)
		c.prep(g.dst)
		g.confirm(t, "")
		g.shot(t, c.name, res)
	}
	h := newMigFixture(t, migTestDstHost, "SHA256:same", "SHA256:same")
	h.start(t)
	h.shot(t, "5-клон-узнать-не-удалось", []string{"узнать не удалось", "[Закрыть]"})
}
