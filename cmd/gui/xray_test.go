package main

// AL-01: XRay в GUI — тест доезда настоящим refresh()/диалогами на fakesrv.

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"testing"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/test"
	"fyne.io/fyne/v2/widget"

	"amnezia-admin/core"
	"amnezia-admin/internal/fakesrv"
	"amnezia-admin/internal/guiview"
)

var reUUIDGUI = regexp.MustCompile(`[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)

func xrayUI(t *testing.T) (*ui, *fakesrv.Server) {
	t.Helper()
	t.Cleanup(core.SetXRayWaits(0, 0))
	srv := fakesrv.NewXRay("dev")
	sess := core.NewSessionWithRunner(srv, &core.ServerCreds{Host: "203.0.113.10", User: "root", Password: "x"})
	cs, err := sess.FindContainers()
	if err != nil || len(cs) != 1 || !cs[0].Managed() {
		t.Fatalf("%+v %v", cs, err)
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
	u.refresh()
	waitGUIGoroutines(t)
	if len(u.clients) != 3 {
		t.Fatalf("тест перестал что-либо проверять: строк %d (статус %q)", len(u.clients), u.status.Text)
	}
	t.Cleanup(func() { waitGUIGoroutines(t) })
	return u, srv
}

func xrayRowOf(t *testing.T, u *ui, name string) int {
	t.Helper()
	for i, cl := range u.clients {
		if cl.Name() == name {
			return i
		}
	}
	t.Fatalf("строки %q нет", name)
	return -1
}

func xrayWritesGUI(srv *fakesrv.Server) int {
	n := 0
	for _, c := range srv.Commands() {
		if strings.Contains(c, "flock") || strings.HasPrefix(c, "docker restart") || strings.Contains(c, "/backup") {
			n++
		}
	}
	return n
}

// TestXRayGUITable — таблица: «—» вместо трафика и активности, отпечаток
// вместо UUID, служебная строка последней, пояснение в статусе.
func TestXRayGUITable(t *testing.T) {
	u, _ := xrayUI(t)
	var all []string
	for row := range u.clients {
		for col := 0; col < len(tableHeaders); col++ {
			cell := newTableCell()
			u.table.UpdateCell(widget.TableCellID{Row: row, Col: col}, cell)
			all = append(all, cell.Text)
		}
		r, _ := u.rowFor(row)
		all = append(all, guiview.CopyRow(r))
	}
	s := strings.Join(all, " | ")
	if reUUIDGUI.MatchString(s) || strings.Contains(s, "0 B") || strings.Contains(s, "?") {
		t.Errorf("UUID, ложный ноль или «?» в таблице XRay: %s", s)
	}
	last, _ := u.rowFor(len(u.clients) - 1)
	if !last.XRayService || guiview.CellText(last, 1) != core.XRayServiceName || guiview.CellText(last, 3) != "без действий" {
		t.Errorf("служебная строка: %+v", last)
	}
	alice, _ := u.rowFor(xrayRowOf(t, u, "Alice"))
	if guiview.CellText(alice, 3) != "—" || guiview.CellText(alice, 4) != "—" || len([]rune(guiview.CellText(alice, 5))) != 9 {
		t.Errorf("строка Alice: %q %q %q", guiview.CellText(alice, 3), guiview.CellText(alice, 4), guiview.CellText(alice, 5))
	}
	if !strings.Contains(u.status.Text, core.XRayStatsNote) {
		t.Errorf("статус: %q", u.status.Text)
	}
}

// TestXRayGUIRestartWarning — окно изменений: «Применить» показывает
// предупреждение о перезапуске; «Отмена» — ни одной записи; подтверждение —
// ровно один перезапуск. Переименование — без предупреждения.
func TestXRayGUIRestartWarning(t *testing.T) {
	u, srv := xrayUI(t)
	alice := u.clients[xrayRowOf(t, u, "Alice")].ClientID
	plan, err := u.sess.PlanDelete(u.cur, alice)
	if err != nil {
		t.Fatal(err)
	}
	u.showDiffWindow("удаление", plan, func(*core.NewUser) {})
	diff := topPopup(t, u.win.Canvas())
	texts := strings.Join(visibleTexts(diff), " | ")
	if reUUIDGUI.MatchString(texts) || strings.Contains(texts, "privateKey") {
		t.Errorf("предпросмотр с секретами: %s", texts)
	}
	before := xrayWritesGUI(srv)
	test.Tap(buttonByText(t, diff, "Применить"))
	warn := topPopup(t, u.win.Canvas())
	wt := strings.Join(visibleTexts(warn), " | ")
	if !strings.Contains(wt, core.XRayRestartTitle) || !strings.Contains(wt, "узнать нельзя") {
		t.Fatalf("нет предупреждения о перезапуске: %s", wt)
	}
	ok := buttonByText(t, warn, core.XRayRestartConfirm)
	if ok.Importance != widget.DangerImportance {
		t.Error("кнопка перезапуска — не опасного вида")
	}
	test.Tap(buttonByText(t, warn, "Отмена"))
	waitGUIGoroutines(t)
	if xrayWritesGUI(srv) != before || srv.XRayRestarts() != 0 {
		t.Fatalf("отказ записал: %d→%d, перезапусков %d", before, xrayWritesGUI(srv), srv.XRayRestarts())
	}
	test.Tap(buttonByText(t, diff, "Применить"))
	test.Tap(buttonByText(t, topPopup(t, u.win.Canvas()), core.XRayRestartConfirm))
	waitGUIGoroutines(t)
	if srv.XRayRestarts() != 1 {
		t.Fatalf("перезапусков %d, ждали 1", srv.XRayRestarts())
	}

	// переименование — без предупреждения и без перезапуска
	bob := u.clients[xrayRowOf(t, u, "Bob")].ClientID
	p2, err := u.sess.PlanRename(u.cur, bob, "Боб")
	if err != nil {
		t.Fatal(err)
	}
	u.showDiffWindow("переименование", p2, func(*core.NewUser) {})
	test.Tap(buttonByText(t, topPopup(t, u.win.Canvas()), "Применить"))
	waitGUIGoroutines(t)
	if srv.XRayRestarts() != 1 {
		t.Fatalf("переименование перезапустило XRay: %d", srv.XRayRestarts())
	}
	var list []core.ClientEntry
	b, _ := srv.File("/opt/amnezia/xray/clientsTable")
	_ = json.Unmarshal(b, &list)
	if len(list) != 1 || list[0].Name() != "Боб" {
		t.Fatalf("clientsTable: %+v", list)
	}
}

// TestXRayGUIDeleteCard — одно окно удаления (AU-UX M2): карточка без UUID
// и без «подключений не было», «Что изменится», предупреждение о перезапуске;
// служебная строка — без действий.
func TestXRayGUIDeleteCard(t *testing.T) {
	u, srv := xrayUI(t)
	u.selectedRow = xrayRowOf(t, u, "Alice")
	u.deleteSelected()
	waitGUIGoroutines(t)
	card := strings.Join(visibleTexts(topPopup(t, u.win.Canvas())), " | ")
	if !strings.Contains(card, guiview.XRayDeleteActivity) || reUUIDGUI.MatchString(card) || strings.Contains(card, "не было") ||
		!strings.Contains(card, "соединения ВСЕХ пользователей XRay") || !strings.Contains(card, "Что изменится") {
		t.Errorf("карточка: %s", card)
	}
	test.Tap(buttonByText(t, topPopup(t, u.win.Canvas()), "Отмена"))
	u.selectedRow = len(u.clients) - 1
	before := xrayWritesGUI(srv)
	u.deleteSelected()
	info := strings.Join(visibleTexts(u.win.Canvas().Overlays().Top()), " | ")
	if !strings.Contains(info, guiview.XRayServiceInfo) || xrayWritesGUI(srv) != before {
		t.Errorf("служебная строка: %s", info)
	}
	if m := u.cellMenu(widget.TableCellID{Row: len(u.clients) - 1, Col: 1}); m == nil || len(m.Items) != 1 {
		t.Errorf("меню служебной строки: %+v", m)
	}
}

// TestXRayGUIReadFailStale — AU-UX M3: сбой чтения XRay — прежний список
// этого XRay с пометкой «данные прошлого чтения», кнопки изменения выключены.
func TestXRayGUIReadFailStale(t *testing.T) {
	u, srv := xrayUI(t)
	srv.FailRead = map[string]error{"/opt/amnezia/xray/server.json": errors.New("i/o timeout")}
	u.refresh()
	waitGUIGoroutines(t)
	if len(u.clients) != 3 || u.canManage || !strings.Contains(u.status.Text, "данные прошлого чтения") || !strings.Contains(u.status.Text, "server.json") {
		t.Fatalf("строк %d, canManage %v, статус %q", len(u.clients), u.canManage, u.status.Text)
	}
}

// TestXRayGUIStaleViewStillWarns — AU-LOGIC High-2, доезд: список загружен,
// пока он открыт, UUID клиента вписан в server.json (запись «отключён»).
// Удаление в GUI решает по ПЛАНУ: предупреждение о перезапуске показано;
// «Отмена» — ни записи, ни перезапуска.
func TestXRayGUIStaleViewStillWarns(t *testing.T) {
	u, srv := xrayUI(t)
	alice := u.clients[xrayRowOf(t, u, "Alice")].ClientID
	// стенд: Alice отключена по записи боевым путём
	p, err := u.sess.PlanSetEnabled(u.cur, alice, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := u.sess.Apply(p); err != nil {
		t.Fatal(err)
	}
	u.refresh()
	waitGUIGoroutines(t)
	// после загрузки списка UUID снова появился в server.json (другая программа)
	conf, _ := srv.File("/opt/amnezia/xray/server.json")
	ids := append(fakesrv.XRayIDs(conf), alice)
	srv.SetFile("/opt/amnezia/xray/server.json", []byte(fakesrv.XRayWithClients(string(conf), ids...)))
	restarts, writes := srv.XRayRestarts(), xrayWritesGUI(srv)
	u.selectedRow = xrayRowOf(t, u, "Alice")
	// по виду списка Alice «отключена» (UUID нет) — прежде предупреждения
	// не было; по плану удаление меняет server.json → перезапуск
	u.deleteSelected()
	waitGUIGoroutines(t)
	top := strings.Join(visibleTexts(topPopup(t, u.win.Canvas())), " | ")
	if !strings.Contains(top, core.XRayRestartTitle) {
		t.Fatalf("нет предупреждения о перезапуске: %s", top)
	}
	test.Tap(buttonByText(t, topPopup(t, u.win.Canvas()), "Отмена"))
	waitGUIGoroutines(t)
	if srv.XRayRestarts() != restarts || xrayWritesGUI(srv) != writes {
		t.Fatalf("записано без подтверждения: перезапусков %d→%d", restarts, srv.XRayRestarts())
	}
}

// TestXRayGUIConfirmFocusEsc — AU-UX M1: обе кнопки внизу рядом и видны
// целиком на обоих размерах окна; фокус на «Отмена»; Esc — отмена, ничего
// не записано.
func TestXRayGUIConfirmFocusEsc(t *testing.T) {
	// размеры окна осмотра: стартовый 1229×620 и минимальный 972×517
	// (как у сторожей «виден целиком» — TestQRFullyVisible и др.)
	for _, size := range []fyne.Size{{Width: 1229, Height: 620}, {Width: 972, Height: 517}} {
		t.Run(fmt.Sprintf("%vx%v", size.Width, size.Height), func(t *testing.T) {
			u, srv := xrayUI(t)
			u.win.Resize(size)
			u.selectedRow = xrayRowOf(t, u, "Bob")
			u.deleteSelected()
			waitGUIGoroutines(t)
			pop := topPopup(t, u.win.Canvas())
			osmotrFrame(pop, nil)
			cancel := buttonByText(t, pop, "Отмена")
			ok := buttonByText(t, pop, core.XRayRestartConfirm)
			if ok.Importance != widget.DangerImportance {
				t.Error("кнопка перезапуска — не опасного вида")
			}
			if u.win.Canvas().Focused() != cancel {
				t.Errorf("фокус не на «Отмена»: %T", u.win.Canvas().Focused())
			}
			win := u.win.Canvas().Size()
			for _, b := range []*widget.Button{cancel, ok} {
				p := fyne.CurrentApp().Driver().AbsolutePositionForObject(b)
				if p.X < 0 || p.Y < 0 || p.X+b.Size().Width > win.Width+0.5 || p.Y+b.Size().Height > win.Height+0.5 || b.Size().Height < 1 {
					t.Errorf("кнопка %q не видна целиком: %v %v в окне %v", b.Text, p, b.Size(), win)
				}
			}
			pc := fyne.CurrentApp().Driver().AbsolutePositionForObject(cancel)
			po := fyne.CurrentApp().Driver().AbsolutePositionForObject(ok)
			if pc.Y != po.Y || po.X <= pc.X {
				t.Errorf("кнопки не рядом в одном ряду: %v %v", pc, po)
			}
			before := xrayWritesGUI(srv)
			u.win.Canvas().OnTypedKey()(&fyne.KeyEvent{Name: fyne.KeyEscape})
			waitGUIGoroutines(t)
			if u.win.Canvas().Overlays().Top() != nil || xrayWritesGUI(srv) != before || srv.XRayRestarts() != 0 {
				t.Fatalf("Esc не отменил: оверлей %v, записей %d→%d", u.win.Canvas().Overlays().Top(), before, xrayWritesGUI(srv))
			}
		})
	}
}

// TestXRayGUIOneWindowWithRace — AU-UX M2: предупреждение о гонке — разделом
// того же окна, а не вторым окном; подтверждение пишет ровно один раз.
func TestXRayGUIOneWindowWithRace(t *testing.T) {
	u, srv := xrayUI(t)
	u.warnSess = guiview.WarnSession{} // предупреждение о гонке ещё не показывалось
	u.selectedRow = xrayRowOf(t, u, "Bob")
	u.deleteSelected()
	waitGUIGoroutines(t)
	pop := topPopup(t, u.win.Canvas())
	texts := strings.Join(visibleTexts(pop), " | ")
	if !strings.Contains(texts, guiview.WarningTitle()) || !strings.Contains(texts, core.XRayRestartTitle) {
		t.Fatalf("не одно окно: %s", texts)
	}
	test.Tap(buttonByText(t, pop, core.XRayRestartConfirm))
	waitGUIGoroutines(t)
	if srv.XRayRestarts() != 1 {
		t.Fatalf("перезапусков %d", srv.XRayRestarts())
	}
}
