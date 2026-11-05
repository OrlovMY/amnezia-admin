package main

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/test"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"amnezia-admin/core"
	"amnezia-admin/internal/fakesrv"
)

// Пожелания владельца 05.11.2026: копирование сообщений, «Подробнее» у
// протокола, широкое окно в одну строку, PgUp/PgDn/Home/End в таблице.

// labelsIn — все подписи под o (в порядке обхода).
func labelsIn(o fyne.CanvasObject) []*widget.Label {
	var out []*widget.Label
	walkObjects(o, func(o fyne.CanvasObject) {
		if l, ok := o.(*widget.Label); ok {
			out = append(out, l)
		}
	})
	return out
}

// TestCopyCopiesShownText — «Копировать» кладёт в буфер ровно показанное:
// секрет в исходном тексте (ключ vpn://) на экране замаскирован, и в буфер
// уходит маскированный вид, а не исходник.
func TestCopyCopiesShownText(t *testing.T) {
	u := testUI(t)
	secret := "vpn://" + strings.Repeat("QUFBQUFB", 12)
	u.showInfo("Сообщение", "Не удалось: ключ "+secret+" не подошёл.")
	pop := u.win.Canvas().Overlays().Top()
	var shown string
	for _, l := range labelsIn(pop) {
		if strings.Contains(l.Text, "Не удалось") {
			shown = l.Text
			if !l.Selectable {
				t.Error("текст сообщения не выделяемый")
			}
		}
	}
	if shown == "" || strings.Contains(shown, secret) {
		t.Fatalf("показан %q — секрет не замаскирован или текста нет", shown)
	}
	test.Tap(buttonByText(t, pop, "Копировать"))
	if got := fyne.CurrentApp().Clipboard().Content(); got != shown {
		t.Errorf("в буфере %q, на экране %q", got, shown)
	}
	if strings.Contains(fyne.CurrentApp().Clipboard().Content(), secret) {
		t.Error("секрет ушёл в буфер обмена")
	}

	// showErrorText — тот же путь; заглавная первая буква, как у Fyne.
	u.showErrorText(errors.New("план устарел: " + secret))
	pop = u.win.Canvas().Overlays().Top()
	test.Tap(buttonByText(t, pop, "Копировать"))
	got := fyne.CurrentApp().Clipboard().Content()
	if !strings.HasPrefix(got, "План устарел") || strings.Contains(got, secret) {
		t.Errorf("ошибка в буфере: %q", got)
	}
}

// TestStatusLineCopy — строка состояния главного окна выделяемая, и её
// «Копировать» берёт текст В МОМЕНТ НАЖАТИЯ (а не при сборке окна).
func TestStatusLineCopy(t *testing.T) {
	u := osmotrUI(t, theme.VariantLight)
	osmotrMain(u)
	u.win.Resize(fyne.NewSize(900, 600))
	if !u.status.Selectable {
		t.Error("строка состояния не выделяемая")
	}
	u.status.SetText("Пользователей: 3 · последняя строка")
	test.Tap(buttonByText(t, u.win.Content(), "Копировать"))
	if got := fyne.CurrentApp().Clipboard().Content(); got != u.status.Text {
		t.Errorf("в буфере %q, в строке состояния %q", got, u.status.Text)
	}
}

// detailsUI — главное окно поверх поддельного сервера srv, протокол ctr.
func detailsUI(t *testing.T, srv *fakesrv.Server, ctr string) *ui {
	t.Helper()
	serialUI(t)
	u := osmotrUI(t, theme.VariantLight)
	osmotrMain(u)
	u.sess = core.NewSessionWithRunner(srv, &core.ServerCreds{Host: "203.0.113.10", User: "root"})
	cs, err := u.sess.FindContainers()
	if err != nil {
		t.Fatal(err)
	}
	for i := range cs {
		if cs[i].Name == ctr {
			u.cur = &cs[i]
		}
	}
	if u.cur == nil {
		t.Fatalf("%s не найден", ctr)
	}
	return u
}

func detailsText(t *testing.T, u *ui) string {
	t.Helper()
	test.Tap(u.detailsBtn)
	waitGUIGoroutines(t)
	if u.protoDetailsShown == nil {
		t.Fatal("окно «Подробнее» не открылось")
	}
	var b strings.Builder
	for _, l := range labelsIn(u.win.Canvas().Overlays().Top()) {
		b.WriteString(l.Text + "\n")
	}
	return b.String()
}

// TestProtoDetailsWindow — «Подробнее» боевым путём (кнопка → чтение с
// сервера → окно): различение «прочитано» и «не удалось узнать»; при отказе
// чтения нет ни пустых значений, ни нуля.
func TestProtoDetailsWindow(t *testing.T) {
	ok := detailsText(t, detailsUI(t, fakesrv.New(), "amnezia-awg"))
	for _, want := range []string{"Порт: 51820", "Подсеть: 10.8.1.1/24", "Транспорт: udp",
		"Версия параметров: старый AWG", "Контейнер: amnezia-awg", "Файл конфигурации: /opt/amnezia/awg/wg0.conf"} {
		if !strings.Contains(ok, want) {
			t.Errorf("нет %q в\n%s", want, ok)
		}
	}
	srv := fakesrv.New()
	srv.FailRead = map[string]error{"/opt/amnezia/awg/wg0.conf": errors.New("i/o timeout")}
	bad := detailsText(t, detailsUI(t, srv, "amnezia-awg"))
	for _, want := range []string{"Порт: не удалось узнать: ", "Подсеть: не удалось узнать: ", "Версия параметров: не удалось узнать: "} {
		if !strings.Contains(bad, want) {
			t.Errorf("нет %q в\n%s", want, bad)
		}
	}
	if strings.Contains(bad, "Порт: \n") || strings.Contains(bad, "Порт: 0") || strings.Contains(bad, "51820") {
		t.Errorf("при отказе чтения показано значение:\n%s", bad)
	}
	x := detailsText(t, detailsUI(t, fakesrv.NewXRay("dev"), core.XRayContainer))
	if !strings.Contains(x, "Подсеть: не применяется") || !strings.Contains(x, "Транспорт: tcp/reality") || !strings.Contains(x, "Версия параметров: XRay") {
		t.Errorf("XRay:\n%s", x)
	}
}

// TestMainWideOneRow — замеры раскладки главного окна: узкое (900×600) —
// кнопки и строка протокола двумя строками, как прежде; широкое (≥1400) —
// одной строкой, и таблица поднимается на высоту строки. Числа — в журнал.
func TestMainWideOneRow(t *testing.T) {
	u := osmotrUI(t, theme.VariantLight)
	osmotrMain(u)
	type m struct {
		w, h                 float32
		btnY, protoY, protoX float32
		tableY, tableH       float32
	}
	measure := func(w, h float32) m {
		u.win.Resize(fyne.NewSize(w, h))
		return m{w, h, u.buttonsRow.Position().Y, u.protoRow.Position().Y, u.protoRow.Position().X,
			u.table.Position().Y, u.table.Size().Height}
	}
	narrow, start, wide, wider := measure(900, 600), measure(startWindowSize().Width, startWindowSize().Height), measure(1400, 600), measure(1920, 1000)
	for _, x := range []m{narrow, start, wide, wider} {
		t.Logf("окно %.0f×%.0f: кнопки y=%.1f; протокол x=%.1f y=%.1f; таблица y=%.1f h=%.1f; одной строкой=%v",
			x.w, x.h, x.btnY, x.protoX, x.protoY, x.tableY, x.tableH, x.protoY == x.btnY)
	}
	lay := mainLayout{server: u.serverLabel}
	objs := []fyne.CanvasObject{u.buttonsRow, u.protoRow}
	thr := lay.wideThreshold(objs)
	t.Logf("порог одной строки: %.1f (кнопки %.1f + отступ + строка протокола %.1f + полная подпись сервера)",
		thr, u.buttonsRow.MinSize().Width, u.protoRow.MinSize().Width)
	if narrow.protoY <= narrow.btnY || narrow.protoX != 0 {
		t.Errorf("900×600: строка протокола не под кнопками: %+v", narrow)
	}
	// В широком режиме подпись сервера не обрезана: её ширина не меньше
	// полного текста.
	u.win.Resize(fyne.NewSize(1920, 1000))
	full := fyne.MeasureText(u.serverLabel.Text, theme.TextSize(), u.serverLabel.TextStyle).Width
	t.Logf("1920: подпись сервера %.1f при полном тексте %.1f", u.serverLabel.Size().Width, full)
	if u.serverLabel.Size().Width < full {
		t.Errorf("подпись сервера обрезана в одной строке: %.1f < %.1f", u.serverLabel.Size().Width, full)
	}
	u.win.Resize(fyne.NewSize(900, 600))
	frame := 900 - u.win.Content().Size().Width // поля канвы вокруг содержимого
	at := measure(thr+frame, 600)
	below := measure(thr+frame-1, 600)
	if at.protoY != at.btnY || below.protoY == below.btnY {
		t.Errorf("порог %.1f не держится: на пороге одной строкой=%v, на пиксель уже=%v", thr, at.protoY == at.btnY, below.protoY == below.btnY)
	}
	wide = measure(fyne.Max(1400, thr+frame), 600)
	t.Logf("окно %.0f×600 (≥1400 и не уже порога): протокол x=%.1f y=%.1f; таблица y=%.1f h=%.1f",
		wide.w, wide.protoX, wide.protoY, wide.tableY, wide.tableH)
	for _, x := range []m{wide, wider} {
		if x.protoY != x.btnY || x.protoX <= 0 {
			t.Errorf("%.0f: не одной строкой: %+v", x.w, x)
		}
		if x.tableY >= narrow.tableY {
			t.Errorf("%.0f: таблица не поднялась (%.1f против %.1f)", x.w, x.tableY, narrow.tableY)
		}
	}
	// Ничего не налезает: строка протокола правее кнопок.
	if wide.protoX < u.buttonsRow.MinSize().Width {
		t.Errorf("строка протокола налезает на кнопки: x=%.1f < %.1f", wide.protoX, u.buttonsRow.MinSize().Width)
	}
	// Минимум окна не изменился от широкого режима.
	if mn := u.win.Content().MinSize(); mn.Width > 900 {
		t.Errorf("минимум окна %.1f шире 900", mn.Width)
	}
}

// tableFocusRow — строка фокуса таблицы, узнанная поведением: пробел
// выбирает строку фокуса (Table.TypedKey), выбор доходит до u.selectedRow.
func tableFocusRow(t *testing.T, u *ui) int {
	t.Helper()
	u.table.UnselectAll()
	u.selectedRow = -1
	u.table.TypedKey(&fyne.KeyEvent{Name: fyne.KeySpace})
	return u.selectedRow
}

// TestTableKeysPageHomeEnd — PgDn/PgUp на страницу, Home — в начало, End —
// в конец; на краях ход не выходит за список.
func TestTableKeysPageHomeEnd(t *testing.T) {
	u := osmotrUI(t, theme.VariantLight)
	osmotrMain(u)
	base := u.clients
	u.clients = nil
	for i := 0; i < 60; i++ {
		c := base[i%len(base)]
		u.clients = append(u.clients, core.ClientEntry{ClientID: fmt.Sprintf("%s%02d", c.ClientID[:40], i),
			UserData: map[string]any{"clientName": fmt.Sprintf("Клиент %02d", i)}})
	}
	u.table.Refresh()
	u.win.Resize(fyne.NewSize(900, 600))
	page := u.table.pageRows()
	t.Logf("строк 60, на странице %d (таблица высотой %.1f)", page, u.table.Size().Height)
	if page < 2 || page >= 60 {
		t.Fatalf("страница %d строк — таблица не измерена", page)
	}
	key := func(k fyne.KeyName) { u.table.TypedKey(&fyne.KeyEvent{Name: k}) }
	steps := []struct {
		k    fyne.KeyName
		want int
	}{
		{fyne.KeyEnd, 59},
		{fyne.KeyHome, 0},
		{fyne.KeyPageDown, page},
		{fyne.KeyPageDown, 2 * page},
		{fyne.KeyPageUp, page},
		{fyne.KeyPageUp, 0},
		{fyne.KeyPageUp, 0}, // на краю — не дальше
		{fyne.KeyEnd, 59},
		{fyne.KeyPageDown, 59},
		{fyne.KeyDown, 59},
		{fyne.KeyUp, 58}, // стрелки идут от новой позиции
	}
	for i, s := range steps {
		key(s.k)
		if got := tableFocusRow(t, u); got != s.want {
			t.Errorf("шаг %d (%s): строка %d, ждали %d", i, s.k, got, s.want)
		}
	}
}
