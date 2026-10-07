package main

// Окно «найдена проблема на сервере» (diagnose.go) на fakesrv: тот же
// боевой путь diagnoseAfterConnect → core.Diagnose → окно → «Исправить» →
// core.ApplyFix → окно итога.

import (
	"strings"
	"testing"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/test"
	"fyne.io/fyne/v2/widget"

	"amnezia-admin/core"
	"amnezia-admin/internal/fakesrv"
	"amnezia-admin/internal/guiview"
)

func diagUI(t *testing.T, m *fakesrv.DiagModel) (*ui, *fakesrv.Server) {
	t.Helper()
	t.Cleanup(core.SetDiagWaits(0, 2))
	srv := fakesrv.New()
	srv.Names = []string{"amnezia-awg", "amnezia-wireguard"}
	srv.Diag = m
	sess := core.NewSessionWithRunner(srv, &core.ServerCreds{Host: "203.0.113.10", User: "root", Password: "x"})
	cs, err := sess.FindContainers()
	if err != nil {
		t.Fatal(err)
	}
	a := test.NewApp()
	t.Cleanup(a.Quit)
	u := &ui{win: test.NewWindow(nil), sess: sess, containers: cs, status: widget.NewLabel(""), selectedRow: -1, warnFreq: guiview.WarnOncePerRun}
	t.Cleanup(func() { u.win.Close() })
	u.cur = &u.containers[0]
	u.warnSess = guiview.AfterWarned(u.warnServerID())
	u.buildTable()
	u.win.SetContent(u.table)
	u.win.Resize(fyne.NewSize(1229, 620))
	t.Cleanup(func() { waitGUIGoroutines(t) })
	return u, srv
}

func diagFixRan(srv *fakesrv.Server) []string {
	var out []string
	for _, c := range srv.Commands() {
		if !strings.Contains(c, "aa-diag-") && (strings.Contains(c, "apparmor") || strings.HasPrefix(c, "docker restart") || strings.Contains(c, "xtables-nft-multi")) {
			out = append(out, c)
		}
	}
	return out
}

// TestDiagDialogFixAndCopy — проблема найдена: окно с «Исправить» / «Не
// сейчас», инструкцией и «Скопировать команды». В буфер уходят ровно те
// строки, что показаны, и ровно они исполняются по «Исправить»; итог —
// «исправлено» по повторной проверке. Окно — без активной прокрутки.
func TestDiagDialogFixAndCopy(t *testing.T) {
	u, srv := diagUI(t, &fakesrv.DiagModel{Profiles: []string{"wg-quick", "wg"}, Legacy: map[string]bool{"amnezia-awg": true}})
	u.diagnoseAfterConnect(u.sess, u.containers)
	waitGUIGoroutines(t)
	v := u.diagShown
	if v == nil || v.fix == nil || v.copy == nil || v.later == nil {
		t.Fatalf("окно проблемы не показано: %+v", v)
	}
	if v.fix.Text != diagFixText || v.later.Text != diagLaterText || v.copy.Text != diagCopyText {
		t.Errorf("кнопки: %q %q %q", v.fix.Text, v.later.Text, v.copy.Text)
	}
	if active, info := activeScroll(t, u); active {
		t.Errorf("окно с активной прокруткой на 1229×620 (%s)", info)
	}
	test.Tap(v.copy)
	clip := fyne.CurrentApp().Clipboard().Content()
	if clip != core.FixCommandsText(v.plan) || strings.TrimRight(clip, "\n") != v.cmds.Text {
		t.Fatalf("в буфере не то, что показано:\n%q\n%q", clip, v.cmds.Text)
	}
	if v.copied.Text != diagCopiedText {
		t.Errorf("нет сообщения о копировании: %q", v.copied.Text)
	}
	if ran := diagFixRan(srv); len(ran) != 0 {
		t.Fatalf("до «Исправить» выполнено %q", ran)
	}
	test.Tap(v.fix)
	waitGUIGoroutines(t)
	if got := strings.Join(diagFixRan(srv), "\n") + "\n"; got != clip {
		t.Fatalf("исполнено не то, что скопировано:\n%s\n---\n%s", got, clip)
	}
	if u.diagResult == nil {
		t.Fatal("итог не показан")
	}
	var txt []string
	walkObjects(topPopup(t, u.win.Canvas()), func(o fyne.CanvasObject) {
		if l, ok := o.(*widget.Label); ok {
			txt = append(txt, l.Text)
		}
	})
	all := strings.Join(txt, "\n")
	for _, w := range []string{"AppArmor в amnezia-awg: исправлено", "AppArmor в amnezia-wireguard: исправлено", "iptables в amnezia-awg: исправлено"} {
		if !strings.Contains(all, w) {
			t.Errorf("в итоге нет %q:\n%s", w, all)
		}
	}
}

// TestDiagDialogLaterDoesNothing — «Не сейчас»: окно закрыто, ни одной
// команды исправления.
func TestDiagDialogLaterDoesNothing(t *testing.T) {
	u, srv := diagUI(t, &fakesrv.DiagModel{Profiles: []string{"wg-quick"}})
	v := u.showDiagDialog(u.sess.Diagnose(u.containers))
	test.Tap(v.later)
	waitGUIGoroutines(t)
	if ran := diagFixRan(srv); len(ran) != 0 {
		t.Fatalf("«Не сейчас», а выполнено %q", ran)
	}
}

// TestDiagDialogThreeStates — различение: исправно — окна нет; «не удалось
// узнать» — окно с прямым текстом, БЕЗ «Исправить» и без команд; проблема
// — с «Исправить».
func TestDiagDialogThreeStates(t *testing.T) {
	t.Run("исправно", func(t *testing.T) {
		u, _ := diagUI(t, nil)
		if v := u.showDiagDialog(u.sess.Diagnose(u.containers)); v != nil {
			t.Fatal("окно на исправном сервере")
		}
	})
	t.Run("не удалось узнать", func(t *testing.T) {
		u, _ := diagUI(t, &fakesrv.DiagModel{Profiles: []string{"wg-quick"}, LogUnreadable: true, ProfUnreadable: true})
		v := u.showDiagDialog(u.sess.Diagnose(u.containers))
		if v == nil {
			t.Fatal("«не удалось узнать» скрыто — окна нет")
		}
		if v.fix != nil || v.copy != nil || v.later.Text != diagCloseText {
			t.Fatalf("при «не удалось узнать» предложено исправление: %+v", v)
		}
		var txt []string
		walkObjects(topPopup(t, u.win.Canvas()), func(o fyne.CanvasObject) {
			if l, ok := o.(*widget.Label); ok {
				txt = append(txt, l.Text)
			}
		})
		all := strings.Join(txt, "\n")
		if !strings.Contains(all, "не удалось узнать") || !strings.Contains(all, diagTitleUnknown) {
			t.Fatalf("%s", all)
		}
	})
	t.Run("проблема", func(t *testing.T) {
		u, _ := diagUI(t, &fakesrv.DiagModel{Profiles: []string{"wg-quick"}})
		if v := u.showDiagDialog(u.sess.Diagnose(u.containers)); v == nil || v.fix == nil {
			t.Fatal("нет «Исправить»")
		}
	})
}
