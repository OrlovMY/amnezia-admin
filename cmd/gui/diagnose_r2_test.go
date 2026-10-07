package main

// Круг 2 ревью PR #44: «Не сейчас» запоминается для сервера; окно
// проблемы ждёт закрытия «Сохранить ключ?»; в окне проблемы видны и строки
// «не удалось узнать» по другим контейнерам; прерванное исправление
// называет выполненные шаги.

import (
	"errors"
	"strings"
	"testing"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/test"
	"fyne.io/fyne/v2/widget"

	"amnezia-admin/internal/fakesrv"
)

func diagPopupText(t *testing.T, u *ui) string {
	t.Helper()
	var txt []string
	walkObjects(topPopup(t, u.win.Canvas()), func(o fyne.CanvasObject) {
		if l, ok := o.(*widget.Label); ok {
			txt = append(txt, l.Text)
		}
	})
	return strings.Join(txt, "\n")
}

// TestDiagLaterRemembered — «Не сейчас»: при повторной проверке того же
// сервера окна нет, а в строке состояния сказано, что проблема есть и окно
// скрыто.
func TestDiagLaterRemembered(t *testing.T) {
	u, _ := diagUI(t, &fakesrv.DiagModel{Profiles: []string{"wg-quick"}})
	u.diagnoseAfterConnect(u.sess, u.containers)
	waitGUIGoroutines(t)
	if u.diagShown == nil {
		t.Fatal("первое окно не показано")
	}
	test.Tap(u.diagShown.later)
	u.diagShown = nil
	u.diagnoseAfterConnect(u.sess, u.containers)
	waitGUIGoroutines(t)
	if u.diagShown != nil {
		t.Fatal("после «Не сейчас» окно показано снова")
	}
	if !strings.Contains(u.status.Text, diagNoteDismissed) {
		t.Fatalf("проблема скрыта молча: %q", u.status.Text)
	}
}

// TestDiagQueuedAfterSaveKey — окно проблемы не ложится поверх «Сохранить
// ключ?»: ждёт его закрытия.
func TestDiagQueuedAfterSaveKey(t *testing.T) {
	u, _ := diagUI(t, &fakesrv.DiagModel{Profiles: []string{"wg-quick"}})
	u.offerSaveKey("vpn://не-ключ-тест", "203.0.113.10", "SHA256:test")
	u.diagnoseAfterConnect(u.sess, u.containers)
	waitGUIGoroutines(t)
	if u.diagShown != nil {
		t.Fatal("окно проблемы показано поверх «Сохранить ключ?»")
	}
	// закрыть «Сохранить ключ?» его кнопкой «Не сохранять»
	var closeBtn *widget.Button
	walkObjects(topPopup(t, u.win.Canvas()), func(o fyne.CanvasObject) {
		if b, ok := o.(*widget.Button); ok && b.Text == "Не сохранять" {
			closeBtn = b
		}
	})
	if closeBtn == nil {
		t.Fatal("нет кнопки «Не сохранять»")
	}
	test.Tap(closeBtn)
	if u.diagShown == nil {
		t.Fatal("после закрытия «Сохранить ключ?» окно проблемы не показано")
	}
}

// TestDiagDialogShowsUnknownBeside — проблема в одном контейнере и «не
// удалось узнать» в другом: окно называет оба; исправление — только
// найденной проблемы.
func TestDiagDialogShowsUnknownBeside(t *testing.T) {
	u, _ := diagUI(t, &fakesrv.DiagModel{Profiles: []string{"wg-quick"}, ProbeFail: map[string]error{"amnezia-wireguard": errors.New("обрыв")}})
	v := u.showDiagDialog(u.sess.Diagnose(u.containers))
	if v == nil || v.fix == nil {
		t.Fatal("нет окна с «Исправить»")
	}
	all := diagPopupText(t, u)
	if !strings.Contains(all, "amnezia-wireguard — AppArmor: не удалось узнать") {
		t.Fatalf("незнание по второму контейнеру не названо:\n%s", all)
	}
	for _, c := range v.plan.AppArmor {
		if c == "amnezia-wireguard" {
			t.Fatal("в план попал контейнер с «не удалось узнать»")
		}
	}
}

// TestDiagFixPartialShown — прерванное исправление: окно итога называет
// выполненные шаги.
func TestDiagFixPartialShown(t *testing.T) {
	u, _ := diagUI(t, &fakesrv.DiagModel{Profiles: []string{"wg-quick"}, FailFix: "apparmor_parser"})
	v := u.showDiagDialog(u.sess.Diagnose(u.containers))
	test.Tap(v.fix)
	waitGUIGoroutines(t)
	if _, ok := u.diagResult.(dialog.Dialog); !ok {
		t.Fatal("итог не показан")
	}
	all := diagPopupText(t, u)
	if !strings.Contains(all, "Уже выполнено") || !strings.Contains(all, "ln -sf /etc/apparmor.d/wg-quick") || !strings.Contains(all, "НЕ исправлено") {
		t.Fatalf("%s", all)
	}
}
