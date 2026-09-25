package main

import (
	"strings"
	"testing"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/test"
	"fyne.io/fyne/v2/widget"

	"amnezia-admin/core"
	"amnezia-admin/internal/fakesrv"
)

// Задание НЕЗНАНИЕ-ТРАФИК — ТЕСТ ДОЕЗДА в GUI РОВНО ТЕМ ПУТЁМ, КОТОРЫМ
// ДАННЫЕ ИДУТ В БОЮ (седьмая ступень): настоящий u.refresh() спрашивает
// fakesrv через core.Session, раскладывает ответ в u.peerStats/u.statsFailed,
// ячейку рисует u.table.UpdateCell (rowFor → guiview.CellText), а в буфер
// кладёт пункт контекстного меню. Ни одно поле ui не присваивается тестом
// после refresh — иначе проверялось бы присваивание, а не путь.

// trafficCol — колонка «Трафик ↓/↑» (tableHeaders).
const trafficCol = 4

// guiDesync — боевой рассинхрон на fakesrv (то же, что
// core/peerread_test.go:desyncForTest): штатно добавлен Carol, затем рекей
// первого клиента не применился, откат вернул файлы, но не рантайм.
// Возвращает имена включённых клиентов, которых нет в `wg show`, и имя
// присутствующего с нулевым трафиком.
func guiDesync(t *testing.T) (*fakesrv.Server, *core.Session, *core.Container, []string, string) {
	t.Helper()
	srv := fakesrv.New()
	sess := core.NewSessionWithRunner(srv, &core.ServerCreds{Host: "203.0.113.10", User: "root", Password: "x"})
	c := &core.Container{Name: "amnezia-awg", Dir: "/opt/amnezia/awg", Proto: "AmneziaWG", Managed: true}
	add, err := sess.PlanAddUser(c, "Carol")
	if err != nil {
		t.Fatalf("PlanAddUser: %v", err)
	}
	if _, err := sess.Apply(add); err != nil {
		t.Fatalf("Apply(Carol): %v", err)
	}
	clients, err := sess.LoadClients(c)
	if err != nil || len(clients) != 3 {
		t.Fatalf("LoadClients: %v, %d", err, len(clients))
	}
	var subject, bystander string
	var absent []string
	for _, cl := range clients {
		switch {
		case cl.Name() == "Carol":
		case subject == "":
			subject = cl.ClientID
			absent = append(absent, cl.Name())
		default:
			bystander = cl.ClientID
			absent = append(absent, cl.Name())
		}
	}
	p, err := sess.PlanRekey(c, subject)
	if err != nil {
		t.Fatalf("PlanRekey: %v", err)
	}
	srv.DropPeerOnSync = bystander
	srv.FailSyncconfFrom = 3
	if _, err := sess.Apply(p); err == nil {
		t.Fatal("Apply(рекей): ожидалась ошибка — рассинхрон не воспроизвёлся")
	}
	srv.DropPeerOnSync, srv.FailSyncconfFrom = "", 0
	return srv, sess, c, absent, "Carol"
}

// refreshedUI — окно с таблицей, заполненной НАСТОЯЩИМ refresh().
func refreshedUI(t *testing.T, sess *core.Session, c *core.Container) *ui {
	t.Helper()
	a := test.NewApp()
	t.Cleanup(a.Quit)
	u := &ui{
		win:         test.NewWindow(nil),
		sess:        sess,
		containers:  []core.Container{*c},
		status:      widget.NewLabel(""),
		selectedRow: -1,
	}
	t.Cleanup(func() { u.win.Close() })
	u.cur = &u.containers[0]
	u.buildTable()
	u.win.SetContent(u.table)
	u.refresh()
	waitGUIGoroutines(t)
	if len(u.clients) == 0 {
		t.Fatalf("тест перестал что-либо проверять: refresh не загрузил клиентов (статус %q)", u.status.Text)
	}
	return u
}

// shownAndCopied — что ячейка трафика строки name ПОКАЗЫВАЕТ (UpdateCell) и
// что «Копировать строку» кладёт в буфер.
func shownAndCopied(t *testing.T, u *ui, name string) (shown, copied string) {
	t.Helper()
	for row, cl := range u.clients {
		if cl.Name() != name {
			continue
		}
		cell := newTableCell()
		u.table.UpdateCell(widget.TableCellID{Row: row, Col: trafficCol}, cell)
		m := u.cellMenu(widget.TableCellID{Row: row, Col: trafficCol})
		if m == nil || len(m.Items) != 2 {
			t.Fatalf("строка %q: меню ячейки не построено", name)
		}
		m.Items[1].Action()
		return cell.Text, fyne.CurrentApp().Clipboard().Content()
	}
	t.Fatalf("строки %q в таблице нет", name)
	return "", ""
}

// TestTrafficAbsentReachesTableAndClipboard — клиент есть в clientsTable,
// включён, и его нет в ответе `wg show`: на экране и в буфере — «?», а не
// «0 B / 0 B». Присутствующий с нулевым трафиком Carol — честный ноль.
func TestTrafficAbsentReachesTableAndClipboard(t *testing.T) {
	_, sess, c, absent, present := guiDesync(t)
	u := refreshedUI(t, sess, c)
	if u.statsFailed {
		t.Fatal("тест перестал что-либо проверять: статистика не получена вовсе — проверяется не тот случай")
	}
	for _, name := range absent {
		shown, copied := shownAndCopied(t, u, name)
		if shown != "?" {
			t.Errorf("клиент %q отсутствует в статистике сервера, а ячейка трафика показывает %q, ожидалось \"?\"", name, shown)
		}
		if !strings.Contains(copied, "Трафик ↓/↑: ?") || strings.Contains(copied, "0 B / 0 B") {
			t.Errorf("«Копировать строку» для %q положило %q — ожидалось «Трафик ↓/↑: ?» и ни одного «0 B / 0 B»", name, copied)
		}
	}
	shown, copied := shownAndCopied(t, u, present)
	if shown != "0 B / 0 B" {
		t.Errorf("клиент %q есть в статистике с нулём, а ячейка показывает %q — честный ноль обязан остаться «0 B / 0 B»", present, shown)
	}
	if !strings.Contains(copied, "Трафик ↓/↑: 0 B / 0 B") {
		t.Errorf("«Копировать строку» для %q: %q — честный ноль потерян", present, copied)
	}
}

// TestTrafficDisabledReachesTable — ШТАТНЫЙ случай отсутствия: отключённый
// через настоящий PlanSetEnabled/Apply клиент в ответе `wg show` не
// появляется. До правки его трафик печатался «0 B / 0 B».
func TestTrafficDisabledReachesTable(t *testing.T) {
	srv := fakesrv.New()
	sess := core.NewSessionWithRunner(srv, &core.ServerCreds{Host: "203.0.113.10", User: "root", Password: "x"})
	c := &core.Container{Name: "amnezia-awg", Dir: "/opt/amnezia/awg", Proto: "AmneziaWG", Managed: true}
	clients, err := sess.LoadClients(c)
	if err != nil || len(clients) < 2 {
		t.Fatalf("LoadClients: %v, %d", err, len(clients))
	}
	p, err := sess.PlanSetEnabled(c, clients[0].ClientID, false)
	if err != nil {
		t.Fatalf("PlanSetEnabled: %v", err)
	}
	if _, err := sess.Apply(p); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	u := refreshedUI(t, sess, c)
	if shown, _ := shownAndCopied(t, u, clients[0].Name()); shown != "отключён" {
		t.Errorf("отключённый клиент: ячейка трафика %q, ожидалось \"отключён\"", shown)
	}
	if shown, _ := shownAndCopied(t, u, clients[1].Name()); shown != "0 B / 0 B" {
		t.Errorf("включённый клиент в статистике с нулём: %q, ожидалось \"0 B / 0 B\"", shown)
	}
}
