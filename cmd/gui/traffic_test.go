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
func guiDesync(t *testing.T) (*gatedRunner, *core.Session, *core.Container, []string, string) {
	t.Helper()
	srv := fakesrv.New()
	g := &gatedRunner{inner: srv}
	sess := core.NewSessionWithRunner(g, &core.ServerCreds{Host: "203.0.113.10", User: "root", Password: "x"})
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
	return g, sess, c, absent, "Carol"
}

// refreshedUI — окно с таблицей, заполненной НАСТОЯЩИМ refresh().
func refreshedUI(t *testing.T, sess *core.Session, c *core.Container) *ui {
	t.Helper()
	return refreshedUISorted(t, sess, c, nil)
}

// refreshedUISorted — то же, но до refresh выставляется сортировка (как
// после клика по заголовку): refresh применяет её через applySort.
func refreshedUISorted(t *testing.T, sess *core.Session, c *core.Container, prep func(*ui)) *ui {
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
	if prep != nil {
		prep(u)
	}
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
	// Сортировка «Трафик ↑» — способ искать неиспользуемых на удаление
	// (ревью QA-01): неизвестные обязаны встать В КОНЕЦ, а не первыми как
	// «наименьший трафик». Идёт боевым путём refresh → applySort.
	u := refreshedUISorted(t, sess, c, func(u *ui) {
		u.sortPrimary, u.sortPrimaryDir = core.SortByTraffic, core.Asc
		u.sortSecondary, u.sortSecondaryDir = core.SortNone, core.Asc
	})
	if got := u.clients[0].Name(); got != present {
		t.Errorf("«Трафик ↑»: первой строкой стоит %q, а не измеренный %q — клиент с неизвестным трафиком выдан за «наименьший»", got, present)
	}
	for _, cl := range u.clients[1:] {
		if cl.Name() == present {
			t.Errorf("«Трафик ↑»: измеренный %q стоит после неизвестных", present)
		}
	}
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

// deleteCardText — НАСТОЯЩИЙ диалог удаления строки name: u.deleteSelected()
// спрашивает сервер (GetHandshakes) в фоне, ответ выставляет метку. Текст
// снимается с виджетов показанного диалога, а не вызовом
// guiview.DeleteCardActivity в обход (ревью QA-01: прежний «доезд» до окна
// не доезжал).
func deleteCardText(t *testing.T, u *ui, g *gatedRunner, name string) []string {
	t.Helper()
	u.selectedRow = -1
	for row, cl := range u.clients {
		if cl.Name() == name {
			u.selectedRow = row
		}
	}
	if u.selectedRow < 0 {
		t.Fatalf("строки %q в таблице нет", name)
	}
	// Ответ сервера держится, пока диалог не показан: тестовый драйвер
	// исполняет fyne.Do прямо в фоновой горутине (как в осмотре, -race).
	g.gate = make(chan struct{})
	u.deleteSelected()
	pop := topPopup(t, u.win.Canvas())
	close(g.gate)
	waitGUIGoroutines(t)
	g.gate = nil
	var texts []string
	var walk func(o fyne.CanvasObject)
	walk = func(o fyne.CanvasObject) {
		switch w := o.(type) {
		case *widget.Label:
			texts = append(texts, w.Text)
			return
		case *fyne.Container:
			for _, ch := range w.Objects {
				walk(ch)
			}
			return
		case fyne.Widget:
			for _, ch := range test.WidgetRenderer(w).Objects() {
				walk(ch)
			}
		}
	}
	walk(pop)
	pop.Hide()
	return texts
}

func hasLabel(texts []string, want string) bool {
	for _, s := range texts {
		if s == want {
			return true
		}
	}
	return false
}

// TestDeleteDialogAbsentAndDisabled — ТЕСТ ДОЕЗДА до окна удаления: боевые
// исходы «нет в статистике» (рассинхрон) и «отключён» (настоящее
// отключение) приходят в метку показанного диалога.
func TestDeleteDialogAbsentAndDisabled(t *testing.T) {
	const (
		wantAbsent   = "Клиента нет в статистике сервера: сейчас сервер его не принимает.\nБыли ли подключения раньше — неизвестно."
		wantDisabled = "Клиент отключён: сервер его сейчас не принимает.\nБыли ли подключения до отключения — неизвестно."
		wantNone     = "Подключений не было."
	)
	g, sess, c, absent, present := guiDesync(t)
	u := refreshedUI(t, sess, c)
	if got := deleteCardText(t, u, g, absent[0]); !hasLabel(got, wantAbsent) {
		t.Errorf("диалог удаления клиента %q, которого нет в статистике: подписи %q, ожидалась %q", absent[0], got, wantAbsent)
	}
	if got := deleteCardText(t, u, g, present); !hasLabel(got, wantNone) {
		t.Errorf("диалог удаления %q (в ответе, не подключался): подписи %q, ожидалась %q", present, got, wantNone)
	}

	g2 := &gatedRunner{inner: fakesrv.New()}
	sess2 := core.NewSessionWithRunner(g2, &core.ServerCreds{Host: "203.0.113.10", User: "root", Password: "x"})
	clients, err := sess2.LoadClients(c)
	if err != nil {
		t.Fatal(err)
	}
	p, err := sess2.PlanSetEnabled(c, clients[0].ClientID, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sess2.Apply(p); err != nil {
		t.Fatal(err)
	}
	u2 := refreshedUI(t, sess2, c)
	if got := deleteCardText(t, u2, g2, clients[0].Name()); !hasLabel(got, wantDisabled) {
		t.Errorf("диалог удаления отключённого %q: подписи %q, ожидалась %q", clients[0].Name(), got, wantDisabled)
	}
}

// gatedRunner — fakesrv, у которого ответ на `wg show` можно придержать
// (gate), пока тест не соберёт показанный диалог. gate меняется только
// тестовой горутиной до запуска и после завершения фоновых операций.
type gatedRunner struct {
	inner *fakesrv.Server
	gate  chan struct{}
}

func (g *gatedRunner) Run(cmd string, stdin []byte) (string, error) {
	if g.gate != nil && strings.Contains(cmd, "wg show wg0 dump") {
		<-g.gate
	}
	return g.inner.Run(cmd, stdin)
}
