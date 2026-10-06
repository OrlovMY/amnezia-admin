package main

import (
	"reflect"
	"testing"

	"amnezia-admin/core"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/test"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
)

// openProtoMenu раскрывает список протоколов нажатием (боевой путь) и
// возвращает пункты показанного меню — из наложения окна, а не из нашего
// кода: тест одинаково читает меню и встроенного widget.Select.
func openProtoMenu(t *testing.T, u *ui) ([]*fyne.MenuItem, []fyne.CanvasObject) {
	t.Helper()
	test.Tap(u.protoSelect)
	pop := topPopUpMenu(u)
	if pop == nil {
		t.Fatalf("после нажатия на список меню не раскрылось (наверху %T)", u.win.Canvas().Overlays().Top())
	}
	var items []*fyne.MenuItem
	var objs []fyne.CanvasObject
	for _, o := range pop.Items {
		f := reflect.ValueOf(o).Elem().FieldByName("Item")
		if !f.IsValid() {
			continue
		}
		items = append(items, f.Interface().(*fyne.MenuItem))
		objs = append(objs, o)
	}
	if len(items) != len(u.protoSelect.Options) {
		t.Fatalf("в меню %d пунктов, вариантов %d", len(items), len(u.protoSelect.Options))
	}
	return items, objs
}

// topPopUpMenu — верхнее наложение окна, если это раскрытое меню (Fyne
// оборачивает его в OverlayContainer с полем Content), иначе nil.
func topPopUpMenu(u *ui) *widget.PopUpMenu {
	ov := u.win.Canvas().Overlays().Top()
	if ov == nil {
		return nil
	}
	if p, ok := ov.(*widget.PopUpMenu); ok {
		return p
	}
	v := reflect.ValueOf(ov)
	if v.Kind() != reflect.Pointer || v.Elem().Kind() != reflect.Struct {
		return nil
	}
	f := v.Elem().FieldByName("Content")
	if !f.IsValid() || !f.CanInterface() {
		return nil
	}
	p, _ := f.Interface().(*widget.PopUpMenu)
	return p
}

func checkedOnly(t *testing.T, items []*fyne.MenuItem, want int) {
	t.Helper()
	for i, it := range items {
		if it.Checked != (i == want) {
			t.Errorf("пункт %d %q: отмечен=%v, ожидалось %v (выбран пункт %d)", i, it.Label, it.Checked, i == want, want)
		}
	}
}

// TestProtoMenuMarksCurrent — в раскрытом списке протоколов отмечен ровно
// текущий пункт; после выбора другого пункта из меню отметка переезжает.
// Подмены «не отмечать ничего» и «отмечать всегда первый» роняют тест.
func TestProtoMenuMarksCurrent(t *testing.T) {
	u := osmotrUI(t, theme.VariantLight)
	osmotrMain(u)
	// три протокола, текущий — второй (выбирается в mainScreen, как в бою)
	u.containers = []core.Container{
		{Name: "amnezia-awg", Dir: "/opt/amnezia/awg", Proto: "AmneziaWG", Support: core.SupportYes},
		{Name: "amnezia-wireguard", Dir: "/opt/amnezia/wireguard", Proto: "WireGuard", Support: core.SupportYes},
		{Name: "amnezia-xray", Dir: "/opt/amnezia/xray", Proto: "XRay", Support: core.SupportYes},
	}
	u.cur = &u.containers[1]
	// ворота держат чтение с сервера, чтобы увидеть блокировку списка; в
	// конце — всегда открыты и фоновые goSafe дождались (иначе висят до конца
	// процесса и роняют waitGUIGoroutines у следующих тестов)
	var gates []chan struct{}
	gated := func() {
		g := make(chan struct{})
		gates = append(gates, g)
		u.sess = core.NewSessionWithRunner(osmotrNoServer{gate: g}, u.sess.Creds)
	}
	open := func() {
		for _, g := range gates {
			select {
			case <-g:
			default:
				close(g)
			}
		}
		waitGUIGoroutines(t)
	}
	t.Cleanup(open)
	waitGUIGoroutines(t) // чтение из osmotrMain
	gated()
	u.showMainScreen()
	sizeWindow(u, "стартовый")()

	if got := u.protoSelect.SelectedIndex(); got != 1 {
		t.Fatalf("выбран %d, ожидался 1", got)
	}
	open() // стартовое чтение завершилось — список разблокирован боевым путём
	items, objs := openProtoMenu(t, u)
	checkedOnly(t, items, 1)

	// щелчок по пункту меню: выбор и закрытие меню
	gated()
	test.Tap(objs[2].(fyne.Tappable))
	if topPopUpMenu(u) != nil {
		t.Fatal("после выбора пункта меню не закрылось")
	}
	if got := u.protoSelect.SelectedIndex(); got != 2 {
		t.Fatalf("после выбора пункта 2 выбран %d", got)
	}
	// смена протокола запускает чтение с сервера в фоне — список на это время
	// заблокирован, как в бою
	if !u.protoSelect.Disabled() {
		t.Error("на время чтения с сервера список не заблокирован")
	}
	open()
	if u.protoSelect.Disabled() {
		t.Fatal("после чтения с сервера список остался заблокирован")
	}
	items, _ = openProtoMenu(t, u)
	checkedOnly(t, items, 2)
}

// TestProtoMenuDisabledDoesNotOpen — на время операции список заблокирован
// и не раскрывается (поведение widget.Select сохранено).
func TestProtoMenuDisabledDoesNotOpen(t *testing.T) {
	u := osmotrUI(t, theme.VariantLight)
	osmotrMain(u)
	u.protoSelect.Disable()
	test.Tap(u.protoSelect)
	if topPopUpMenu(u) != nil {
		t.Error("заблокированный список раскрылся")
	}
	// канарейка: разблокированный — раскрывается (иначе проверка выше немая)
	u.protoSelect.Enable()
	test.Tap(u.protoSelect)
	if topPopUpMenu(u) == nil {
		t.Error("разблокированный список не раскрылся — проверка блокировки ничего не доказывает")
	}
}
