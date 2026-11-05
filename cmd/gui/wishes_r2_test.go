package main

import (
	"runtime"
	"strings"
	"testing"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/test"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"amnezia-admin/core"
	"amnezia-admin/internal/fakesrv"
)

// Раунд 2 (ревью-1 PR #72): M1 маска в самой подписи, L1 «Копировать» у
// пустой строки, L2 «Подробнее» после паники.

// msgTextsIn — все подписи-сообщения под o.
func msgTextsIn(o fyne.CanvasObject) []*msgText {
	var out []*msgText
	walkObjects(o, func(o fyne.CanvasObject) {
		if m, ok := o.(*msgText); ok {
			out = append(out, m)
		}
	})
	return out
}

// TestCopyableLabelsMaskSecrets — M1: в каждую подпись экрана подключения,
// окна пина, сохранения ключа и главного окна (строка состояния) подаётся
// ошибка с vpn://… — и на экране, и в буфере после «Копировать» стоит
// «vpn://<скрыто>». Подмена «msgText.SetText без MaskText» роняет тест.
func TestCopyableLabelsMaskSecrets(t *testing.T) {
	secret := "vpn://" + strings.Repeat("QUFBQUFB", 12)
	const want = "vpn://<скрыто>"
	check := func(name string, root fyne.CanvasObject) {
		t.Helper()
		ls := msgTextsIn(root)
		if len(ls) == 0 {
			t.Fatalf("%s: подписей нет — проверка ничего не значит", name)
		}
		for _, l := range ls {
			l.SetText("ошибка: " + secret)
			if strings.Contains(l.Text, secret) || !strings.Contains(l.Text, want) {
				t.Errorf("%s: на экране %q", name, l.Text)
			}
		}
		copied := 0
		walkObjects(root, func(o fyne.CanvasObject) {
			if b, ok := o.(*widget.Button); ok && b.Text == "Копировать" && b.Visible() {
				fyne.CurrentApp().Clipboard().SetContent("")
				test.Tap(b)
				got := fyne.CurrentApp().Clipboard().Content()
				if strings.Contains(got, secret) || !strings.Contains(got, want) {
					t.Errorf("%s: в буфере %q", name, got)
				}
				copied++
			}
		})
		if copied == 0 {
			t.Errorf("%s: ни одной видимой «Копировать»", name)
		}
		t.Logf("%s: подписей %d, нажато «Копировать» %d", name, len(ls), copied)
	}

	u, _, _, _ := pinDialogReady(t)
	check("экран подключения", u.win.Canvas().Content())
	check("окно пина", topPopup(t, u.win.Canvas()))

	u2 := osmotrUI(t, theme.VariantLight)
	osmotrMain(u2)
	u2.win.Resize(fyne.NewSize(900, 600))
	check("главное окно (строка состояния)", u2.win.Canvas().Content())
	u2.offerSaveKey("vpn://не-настоящий", "203.0.113.10", "")
	check("сохранение ключа", topPopup(t, u2.win.Canvas()))
}

// TestStatusCopyHiddenWhenEmpty — L1: у пустой строки состояния
// «Копировать» скрыта; с текстом кнопка не делает строку выше (числа).
func TestStatusCopyHiddenWhenEmpty(t *testing.T) {
	u := osmotrUI(t, theme.VariantLight)
	osmotrMain(u)
	u.status.SetText("")
	u.win.Resize(fyne.NewSize(900, 600))
	btn := buttonByText(t, u.win.Content(), "Копировать")
	if btn.Visible() {
		t.Error("у пустой строки состояния «Копировать» видна")
	}
	emptyBottom := u.table.Position().Y + u.table.Size().Height
	u.status.SetText("Пользователей: 3")
	u.win.Resize(fyne.NewSize(900, 601))
	u.win.Resize(fyne.NewSize(900, 600))
	if !btn.Visible() {
		t.Error("у непустой строки «Копировать» скрыта")
	}
	fullBottom := u.table.Position().Y + u.table.Size().Height
	lh, bh := u.status.Size().Height, btn.Size().Height
	t.Logf("подпись %.1f, кнопка %.1f; низ таблицы: пусто %.1f, с текстом %.1f", lh, bh, emptyBottom, fullBottom)
	if bh > lh+0.5 || fullBottom < emptyBottom-0.5 {
		t.Errorf("кнопка увеличила строку состояния: подпись %.1f, кнопка %.1f, таблица %.1f → %.1f", lh, bh, emptyBottom, fullBottom)
	}
}

// TestProtoDetailsButtonBackAfterPanic — L2: аварийный выход из чтения
// (runtime.Goexit; настоящая паника по logPanic роняет программу целиком,
// defer срабатывает и тогда, но проверить это в тесте нельзя) не оставляет
// «Подробнее» выключенной, и окна с непрочитанным нет.
func TestProtoDetailsButtonBackAfterPanic(t *testing.T) {
	u := detailsUI(t, fakesrv.New(), "amnezia-awg")
	old := protoDetailsRead
	t.Cleanup(func() { protoDetailsRead = old })
	protoDetailsRead = func(*core.Session, *core.Container) core.ProtoDetails { runtime.Goexit(); return core.ProtoDetails{} }
	test.Tap(u.detailsBtn)
	waitGUIGoroutines(t)
	if u.detailsBtn.Disabled() {
		t.Error("после паники чтения «Подробнее» осталась выключенной")
	}
	if u.protoDetailsShown != nil {
		t.Error("после паники показано окно с непрочитанными данными")
	}
}
