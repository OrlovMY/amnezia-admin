package main

// Р2-1: обязательный выбор окна переноса стоит в закреплённой панели, вне
// прокрутки, и у погашенной кнопки всегда есть причина текстом.

import (
	"strings"
	"testing"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"

	"amnezia-admin/core"
	"amnezia-admin/internal/fakesrv"
)

func xrayMigServer() *fakesrv.Server {
	s := fakesrv.NewXRay("master")
	for _, k := range []string{"xray_short_id.key", "xray_public.key", "xray_private.key"} {
		s.SetFile("/opt/amnezia/xray/"+k, []byte(fakesrv.RandUUID()))
	}
	return s
}

// inScroll — объекты, лежащие внутри любой прокрутки под root.
func inScroll(root fyne.CanvasObject) map[fyne.CanvasObject]bool {
	set := map[fyne.CanvasObject]bool{}
	walkObjects(root, func(o fyne.CanvasObject) {
		if sc, ok := o.(*container.Scroll); ok {
			walkObjects(sc.Content, func(x fyne.CanvasObject) { set[x] = true })
		}
	})
	return set
}

// TestGUIMigratePinnedVisible — при окне 900x600 обязательные элементы
// (галка адреса, выбор XRay, выбор автокопии, поля пароля, причина) видимы,
// лежат в границах окна на канве и НЕ внутри прокрутки.
// Подмена: вернуть pinned в sections (в прокрутку) — роняет.
func TestGUIMigratePinnedVisible(t *testing.T) {
	f := newMigFixtureOn(t, xrayMigServer(), xrayMigServer(), migTestDstHost, "SHA256:a", "SHA256:b")
	f.u.win.Resize(fyne.NewSize(900, 600))
	f.start(t)
	v := f.u.migShown
	if v == nil || v.addrCheck == nil || v.xrayRadio == nil {
		t.Fatalf("сцена ничего не значит: окно %v", v != nil)
	}
	v.mode.SetSelected(backupWithPassword) // показать поля пароля
	top := f.u.win.Canvas().Overlays().Top()
	osmotrFrame(top, nil)
	cs := f.u.win.Canvas().Size()
	scroll := inScroll(top)
	drv := fyne.CurrentApp().Driver()
	must := map[string]fyne.CanvasObject{"галка адреса": v.addrCheck, "выбор XRay": v.xrayRadio, "выбор автокопии": v.mode,
		"пароль": v.pw, "повтор пароля": v.pw2, "причина": v.reason, "кнопка": v.apply}
	for name, o := range must {
		p, s := drv.AbsolutePositionForObject(o), o.Size()
		t.Logf("%s: (%.0f,%.0f) %.0fx%.0f, в прокрутке: %v", name, p.X, p.Y, s.Width, s.Height, scroll[o])
		if !o.Visible() || scroll[o] {
			t.Errorf("%s: виден=%v, внутри прокрутки=%v", name, o.Visible(), scroll[o])
		}
		if p.X < 0 || p.Y < 0 || p.X+s.Width > cs.Width+0.5 || p.Y+s.Height > cs.Height+0.5 {
			t.Errorf("%s вне канвы %.0fx%.0f", name, cs.Width, cs.Height)
		}
	}
}

// TestGUIMigrateDisabledReason — у погашенной кнопки всегда причина текстом,
// она меняется вживую; когда всё подтверждено — «можно переносить».
// Подмена: update не обновляет reason (или одна из причин стёрта) — роняет.
func TestGUIMigrateDisabledReason(t *testing.T) {
	f := newMigFixtureOn(t, xrayMigServer(), xrayMigServer(), migTestDstHost, "SHA256:a", "SHA256:b")
	f.start(t)
	v := f.u.migShown
	step := func(name, want string, wantEnabled bool) {
		t.Helper()
		if got := v.reason.Text; got != want {
			t.Errorf("%s: причина %q, ждали %q", name, got, want)
		}
		if v.apply.Disabled() == wantEnabled {
			t.Errorf("%s: кнопка выключена=%v", name, v.apply.Disabled())
		}
	}
	step("начало", migrateReasonAddr, false)
	v.addrCheck.SetChecked(true)
	step("адрес подтверждён", migrateReasonXRay, false)
	v.xrayRadio.SetSelected(restoreXRayCheck)
	step("XRay выбран", migrateReasonMode, false)
	v.mode.SetSelected(backupWithPassword)
	step("с паролем, пусто", strings.Replace(migrateReasonPwShort, "%d", "12", 1), false)
	v.pw.SetText("автокопия-пароль-12345")
	step("пароль есть, повтора нет", migrateReasonPwDiff, false)
	v.pw2.SetText("автокопия-пароль-12345")
	step("пароли совпали", migrateReasonReady, true)
	v.mode.SetSelected(backupNoPassword)
	step("без пароля", migrateReasonReady, true)
	v.addrCheck.SetChecked(false)
	step("адрес снят", migrateReasonAddr, false)
	if core.BackupPasswordMin != 12 {
		t.Fatalf("тест ждёт минимум пароля 12, а он %d", core.BackupPasswordMin)
	}
	// СТОП проверки цели — отдельная причина, кнопка выключена при любых галках
	src, dst := fakesrv.New(), fakesrv.New()
	src.SetFile("/opt/amnezia/awg/wireguard_psk.key", []byte("OLD-PSK\n"))
	dst.SetFile("/opt/amnezia/awg/wireguard_psk.key", []byte("NEW-PSK\n"))
	wg, _ := dst.File("/opt/amnezia/awg/wg0.conf")
	dst.SetFile("/opt/amnezia/awg/wg0.conf", []byte(strings.Replace(string(wg), "ListenPort = 51820", "ListenPort = 40000", 1)))
	g := newMigFixtureOn(t, src, dst, migTestDstHost, "SHA256:a", "SHA256:b")
	g.start(t)
	w := g.u.migShown
	if w == nil || w.reason.Text != migrateReasonStop {
		t.Fatalf("СТОП: окно %v, причина %q", w != nil, w.reason.Text)
	}
	w.addrCheck.SetChecked(true)
	w.mode.SetSelected(backupNoPassword)
	if !w.apply.Disabled() || w.reason.Text != migrateReasonStop {
		t.Error("при СТОП кнопка включена или причина сменилась")
	}
}
