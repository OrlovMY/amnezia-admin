package main

import (
	"errors"
	"fmt"
	"image/png"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/storage"
	"fyne.io/fyne/v2/test"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"amnezia-admin/core"
	"amnezia-admin/internal/statsview"
)

// Окно «Статистика» (задание GUI-STATS). Подмены, которые обязаны ронять:
// «нет данных → 0 B» в statsCellText; сортировка без ранга исходов;
// таблица, сохраняющая прежние цифры после неудачного перечитывания;
// запись на сервер без «Да».

const tDay0 = int64(20400) // 2025-11-08 UTC

// tStatsLog — Alice: 3000/5000, подключалась; Bob: измеренный ноль;
// Carl: неполные (≥); Abe — в снимках нет (нет данных).
func tStatsLog() *core.TrafficLog {
	hs := core.DayStart(tDay0).Add(10 * time.Hour).Unix()
	daily := fmt.Sprintf("D 1 %d amnezia-awg KA= 3000 5000 %d 5\n", tDay0, hs) +
		fmt.Sprintf("D 1 %d amnezia-awg KB= 0 0 0 5\n", tDay0) +
		fmt.Sprintf("D 1 %d amnezia-awg KC= 100000 1 0 5 1\n", tDay0) +
		fmt.Sprintf("N 1 %d amnezia-awg 5\n", tDay0)
	return core.ParseTrafficLog(daily, true, "", false)
}

func tStatsClients() []core.ClientEntry {
	return []core.ClientEntry{
		{ClientID: "KD=", UserData: map[string]any{"clientName": "Abe"}},
		{ClientID: "KB=", UserData: map[string]any{"clientName": "Bob"}},
		{ClientID: "KA=", UserData: map[string]any{"clientName": "Alice"}},
		{ClientID: "KC=", UserData: map[string]any{"clientName": "Carl"}},
	}
}

func tStatsLines(t *testing.T, l *core.TrafficLog, r core.DayRange) []statsLine {
	t.Helper()
	c := core.Container{Name: "amnezia-awg", Proto: "AmneziaWG", Support: core.SupportYes}
	rows, _ := statsview.Rows([]statsview.ContainerClients{{C: c, Read: true, Clients: tStatsClients()}}, l)
	var ls []statsLine
	for _, row := range rows {
		ls = append(ls, statsLine{row: row, cell: l.Cell(row.Key, r, core.CollectorInstalled)})
	}
	return ls
}

func lineOf(t *testing.T, ls []statsLine, name string) statsLine {
	t.Helper()
	for _, l := range ls {
		if l.row.Name == name {
			return l
		}
	}
	t.Fatalf("строки %s нет", name)
	return statsLine{}
}

// TestStatsCellsThreeStates — различение: измерено / измеренный ноль /
// не меньше / нет данных. «Нет данных» — словами в каждом столбце, не 0 B.
func TestStatsCellsThreeStates(t *testing.T) {
	ls := tStatsLines(t, tStatsLog(), core.AllTime)
	want := map[string][]string{
		"Alice": {"3.0 KB", "5.0 KB", "8.0 KB", "2025-11-08 10:00"},
		"Bob":   {"0 B", "0 B", "0 B", "не подключался"},
		"Carl":  {"≥ ", "≥ ", "≥ ", "не подключался"},
		"Abe":   {"нет данных", "нет данных", "нет данных", "нет данных"},
	}
	for name, w := range want {
		ln := lineOf(t, ls, name)
		for i, col := range []int{statsColRx, statsColTx, statsColTotal, statsColSeen} {
			got := statsCellAt(ln, col)
			if !strings.Contains(got, w[i]) {
				t.Errorf("%s, %s: %q, ждали %q", name, statsColTitles[col], got, w[i])
			}
			if name == "Abe" && strings.Contains(got, "B") {
				t.Errorf("Abe — нет данных, а показано %q (ложный ноль)", got)
			}
		}
	}
	// Период без снимков — у всех «нет данных», ни одного «0 B».
	for _, ln := range tStatsLines(t, tStatsLog(), core.DayRange{From: tDay0 + 10, To: tDay0 + 20}) {
		if got := statsCellAt(ln, statsColTotal); got != "нет данных" {
			t.Errorf("период без снимков, %s: %q", ln.row.Name, got)
		}
	}
}

// TestStatsSortRanksFixed — «нет данных» ниже измеренного нуля, «не меньше»
// — между, в любом столбце и в любую сторону.
func TestStatsSortRanksFixed(t *testing.T) {
	for _, col := range []int{statsColRx, statsColTx, statsColTotal, statsColSeen} {
		for _, desc := range []bool{true, false} {
			ls := tStatsLines(t, tStatsLog(), core.AllTime)
			statsSortLines(ls, col, desc)
			pos := map[string]int{}
			for i, l := range ls {
				pos[l.row.Name] = i
			}
			if pos["Abe"] != len(ls)-1 {
				t.Errorf("%s desc=%v: «нет данных» не внизу: %v", statsColTitles[col], desc, pos)
			}
			if pos["Carl"] != len(ls)-2 {
				t.Errorf("%s desc=%v: «не меньше» не между измеренными и «нет данных»: %v", statsColTitles[col], desc, pos)
			}
		}
	}
	ls := tStatsLines(t, tStatsLog(), core.AllTime)
	statsSortLines(ls, statsColTotal, true)
	if ls[0].row.Name != "Alice" || ls[1].row.Name != "Bob" {
		t.Errorf("по убыванию «Всего»: %s, %s", ls[0].row.Name, ls[1].row.Name)
	}
	statsSortLines(ls, statsColTotal, false)
	if ls[0].row.Name != "Bob" || ls[1].row.Name != "Alice" {
		t.Errorf("по возрастанию «Всего»: %s, %s", ls[0].row.Name, ls[1].row.Name)
	}
}

// TestCollectorTextStates — статус сборщика: все исходы различимы, и
// «неизвестно» не выдаётся за «не установлен» или «работает».
func TestCollectorTextStates(t *testing.T) {
	next := time.Date(2026, 11, 6, 14, 35, 0, 0, time.UTC)
	cases := []struct {
		st   core.CollectorStatus
		want string
	}{
		{core.CollectorStatus{State: core.CollectorInstalled, Collect: core.CollectWorking, SnapshotAge: 3 * time.Minute}, "сбор работает"},
		{core.CollectorStatus{State: core.CollectorInstalled, Collect: core.CollectPending, NextRun: next}, "ожидается до 14:35 UTC"},
		{core.CollectorStatus{State: core.CollectorInstalled, Collect: core.CollectStopped, CollectWhy: "служба упала"}, "НЕ работает: служба упала"},
		{core.CollectorStatus{State: core.CollectorInstalled, Collect: core.CollectUnknown, CollectWhy: "systemctl молчит"}, "неизвестно: systemctl молчит"},
		{core.CollectorStatus{State: core.CollectorNotInstalled}, "не установлен"},
		{core.CollectorStatus{State: core.CollectorPartial, Detail: []string{"нет таймера"}}, "не полностью"},
		{core.CollectorStatus{Err: errors.New("ssh: обрыв")}, "узнать не удалось: ssh: обрыв"},
		{core.CollectorStatus{}, "узнать не удалось: причина неизвестна"},
	}
	for _, c := range cases {
		if got := collectorText(c.st); !strings.Contains(got, c.want) {
			t.Errorf("%+v: %q, ждали %q", c.st, got, c.want)
		}
	}
}

// ---------- окно ----------

type statsFake struct {
	st        core.CollectorStatus
	after     core.CollectorStatus
	log       *core.TrafficLog
	err       error
	installs  atomic.Int32
	removes   atomic.Int32
	statusAsk atomic.Int32
}

func stubStats(t *testing.T, f *statsFake) {
	t.Helper()
	oS, oT, oC, oI, oU, oN := statsReadStatus, statsReadTraffic, statsLoadClients, statsInstall, statsUninstall, statsNow
	t.Cleanup(func() {
		statsReadStatus, statsReadTraffic, statsLoadClients, statsInstall, statsUninstall, statsNow = oS, oT, oC, oI, oU, oN
	})
	statsReadStatus = func(*core.Session) core.CollectorStatus {
		f.statusAsk.Add(1)
		if f.installs.Load()+f.removes.Load() > 0 {
			return f.after
		}
		return f.st
	}
	statsReadTraffic = func(*core.Session) (*core.TrafficLog, error) { return f.log, f.err }
	statsLoadClients = func(*core.Session, *core.Container) ([]core.ClientEntry, error) { return tStatsClients(), nil }
	statsInstall = func(*core.Session) error { f.installs.Add(1); return nil }
	statsUninstall = func(*core.Session) error { f.removes.Add(1); return nil }
	statsNow = func() time.Time { return core.DayStart(tDay0).Add(20 * time.Hour) }
}

// openStats — главное окно, нажатие «Статистика», чтение дождалось.
func openStats(t *testing.T, f *statsFake) *statsView {
	t.Helper()
	serialUI(t)
	stubStats(t, f)
	u := osmotrUI(t, theme.VariantLight)
	osmotrMain(u)
	test.Tap(u.statsBtn)
	waitGUIGoroutines(t)
	if u.statsView == nil {
		t.Fatal("окно статистики не открылось")
	}
	t.Cleanup(u.statsView.win.Close)
	return u.statsView
}

func viewRow(t *testing.T, v *statsView, name string) []string {
	t.Helper()
	rows, cols := v.tableSize()
	for r := 0; r < rows; r++ {
		var cells []string
		for c := 0; c < cols; c++ {
			cells = append(cells, v.cellText(widget.TableCellID{Row: r, Col: c}))
		}
		if cells[statsColName] == name {
			return cells
		}
	}
	t.Fatalf("в таблице окна нет строки %s", name)
	return nil
}

// TestStatsWindowNoDataNotZero — доезд: боевой путь кнопка → чтение в
// горутине → таблица. У Abe «нет данных», не «0 B»; он ниже Bob.
func TestStatsWindowNoDataNotZero(t *testing.T) {
	v := openStats(t, &statsFake{st: core.CollectorStatus{State: core.CollectorInstalled, Collect: core.CollectWorking}, log: tStatsLog()})
	abe := viewRow(t, v, "Abe")
	for _, c := range abe[statsColRx:] {
		if c != "нет данных" {
			t.Errorf("Abe в окне: %q (ждали «нет данных»)", c)
		}
	}
	if got := viewRow(t, v, "Bob")[statsColTotal]; got != "0 B" {
		t.Errorf("Bob — измеренный ноль: %q", got)
	}
	if got := viewRow(t, v, "Carl")[statsColTotal]; !strings.HasPrefix(got, "≥ ") {
		t.Errorf("Carl — неполные: %q", got)
	}
	if n := len(v.lines); v.lines[n-1].row.Name != "Abe" {
		t.Errorf("последняя строка %s, ждали Abe (нет данных)", v.lines[n-1].row.Name)
	}
	if !strings.Contains(v.status.Text, "сбор работает") {
		t.Errorf("статус: %q", v.status.Text)
	}
	if !strings.Contains(v.notes.Text, "учтены сутки (UTC) с 2025-11-08") || !strings.Contains(v.notes.Text, "«≥»") {
		t.Errorf("пометки: %q", v.notes.Text)
	}
	// Сортировка нажатием заголовка: «Всего» по возрастанию — Abe всё равно внизу.
	v.sortBy(statsColTotal)
	if v.lines[0].row.Name != "Bob" || v.lines[len(v.lines)-1].row.Name != "Abe" {
		t.Errorf("по возрастанию: первая %s, последняя %s", v.lines[0].row.Name, v.lines[len(v.lines)-1].row.Name)
	}
	// Период «Неделя» (данные — сегодня) и «свой интервал» без данных.
	v.periodSel.SetSelected(statsPeriodCustom)
	v.fromEntry.SetText("2030-01-01")
	for _, n := range []string{"Alice", "Bob", "Abe"} {
		if got := viewRow(t, v, n)[statsColTotal]; got != "нет данных" {
			t.Errorf("интервал без снимков, %s: %q", n, got)
		}
	}
	v.fromEntry.SetText("2030-13-01")
	if r, _ := v.tableSize(); r != 0 || !strings.Contains(v.notes.Text, "Период задан неверно") {
		t.Errorf("неверная дата: строк %d, пометки %q", r, v.notes.Text)
	}
}

// TestStatsWindowReadFailNotStale — признак 4: после удачного чтения
// неудачное перечитывание УБИРАЕТ цифры и говорит почему.
func TestStatsWindowReadFailNotStale(t *testing.T) {
	f := &statsFake{st: core.CollectorStatus{State: core.CollectorInstalled, Collect: core.CollectWorking}, log: tStatsLog()}
	v := openStats(t, f)
	if r, _ := v.tableSize(); r == 0 {
		t.Fatal("первое чтение не дало строк — проверка ничего не значит")
	}
	f.err = errors.New("ssh: обрыв")
	f.log = nil
	test.Tap(v.refreshBtn)
	waitGUIGoroutines(t)
	if r, _ := v.tableSize(); r != 0 {
		t.Errorf("после неудачного чтения в таблице %d строк (прежние цифры)", r)
	}
	if !strings.Contains(v.notes.Text, "прочитать не удалось: ssh: обрыв") {
		t.Errorf("пометки: %q", v.notes.Text)
	}
	if !v.csvBtn.Disabled() {
		t.Error("«Выгрузить CSV…» включена без данных")
	}
}

// TestStatsWindowNotInstalled — сборщика нет: объяснение, не таблица из
// «не собиралось»; «Установить» включена, «Снять» — нет.
func TestStatsWindowNotInstalled(t *testing.T) {
	v := openStats(t, &statsFake{st: core.CollectorStatus{State: core.CollectorNotInstalled}, log: core.ParseTrafficLog("", false, "", false)})
	if r, _ := v.tableSize(); r != 0 || !strings.Contains(v.notes.Text, "сборщик на сервере не установлен") {
		t.Errorf("строк %d, пометки %q", r, v.notes.Text)
	}
	if v.installBtn.Disabled() || !v.removeBtn.Disabled() {
		t.Errorf("кнопки: установить выкл=%v, снять выкл=%v", v.installBtn.Disabled(), v.removeBtn.Disabled())
	}
}

// TestStatsInstallOnlyAfterYes — окно подтверждения показывает ПОЛНЫЙ
// текст записываемого; «Нет» ничего не пишет, «Да» — один раз.
func TestStatsInstallOnlyAfterYes(t *testing.T) {
	f := &statsFake{
		st:    core.CollectorStatus{State: core.CollectorNotInstalled},
		after: core.CollectorStatus{State: core.CollectorInstalled, Collect: core.CollectPending},
		log:   core.ParseTrafficLog("", false, "", false),
	}
	v := openStats(t, f)
	test.Tap(v.installBtn)
	pop := topPopup(t, v.win.Canvas())
	var shown string
	for _, l := range msgTextsIn(pop) {
		shown += l.Text
	}
	for _, fl := range core.StatsInstallFiles() {
		if !strings.Contains(shown, fl.Path) || !strings.Contains(shown, strings.TrimSpace(fl.Content)) {
			t.Errorf("в подтверждении нет полного текста %s", fl.Path)
		}
	}
	if f.installs.Load() != 0 {
		t.Fatal("записано до ответа")
	}
	test.Tap(buttonByText(t, pop, "Нет"))
	waitGUIGoroutines(t)
	if f.installs.Load() != 0 {
		t.Fatal("«Нет» записало на сервер")
	}
	test.Tap(v.installBtn)
	test.Tap(buttonByText(t, topPopup(t, v.win.Canvas()), "Да"))
	waitGUIGoroutines(t)
	if f.installs.Load() != 1 {
		t.Fatalf("после «Да» установок %d", f.installs.Load())
	}
	if !strings.Contains(v.status.Text, "первый снимок ожидается") {
		t.Errorf("статус после установки: %q", v.status.Text)
	}
	// Снятие — тот же договор.
	test.Tap(v.removeBtn)
	test.Tap(buttonByText(t, topPopup(t, v.win.Canvas()), "Нет"))
	waitGUIGoroutines(t)
	if f.removes.Load() != 0 {
		t.Fatal("«Нет» сняло сборщик")
	}
}

// TestStatsCSVFormat — формат как у `stats -csv`: «нет данных» — пустые
// цифры и слово в «Состоянии», не 0; права 0600.
func TestStatsCSVFormat(t *testing.T) {
	l := tStatsLog()
	c := core.Container{Name: "amnezia-awg", Proto: "AmneziaWG", Support: core.SupportYes}
	rows, _ := statsview.Rows([]statsview.ContainerClients{{C: c, Read: true, Clients: tStatsClients()}}, l)
	data, n, err := statsview.CSV(rows, l, core.CollectorInstalled, statsview.Periods(l, core.AllTime, "за всё время", ""))
	if err != nil || n != 4 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	s := string(data)
	if !strings.HasPrefix(s, statsview.UTF8BOM+"Период;Протокол;Клиент;Публичный ключ;Принято, байт;Отправлено, байт;Всего, байт;Последнее подключение (UTC);Состояние\r\n") {
		t.Errorf("заголовок: %q", strings.SplitN(s, "\r\n", 2)[0])
	}
	for _, want := range []string{";Abe;KD=;;;;;нет данных\r\n", ";Bob;KB=;0;0;0;;измерено\r\n", ";Alice;KA=;3000;5000;8000;2025-11-08 10:00;измерено\r\n", ";Carl;KC=;100000;1;100001;;неполные (не меньше)\r\n"} {
		if !strings.Contains(s, want) {
			t.Errorf("нет строки %q в\n%s", want, s)
		}
	}
	// Разбивка по дням: период — сутки.
	if ps := statsview.Periods(l, core.AllTime, "x", statsBy(statsGroupDay)); len(ps) != 1 || ps[0].Name != "2025-11-08" {
		t.Errorf("разбивка по дням: %+v", ps)
	}

	// Запись: права 0600 через тот же шов, что у конфигов.
	dir := t.TempDir()
	p := filepath.Join(dir, "s.csv")
	var mode os.FileMode
	old := chmodChosen
	t.Cleanup(func() { chmodChosen = old })
	chmodChosen = func(name string, m os.FileMode) error { mode = m; return old(name, m) }
	w, err := storage.Writer(storage.NewFileURI(p))
	if err != nil {
		t.Fatal(err)
	}
	msg := statsCSVResult(w, data, n)
	got, _ := os.ReadFile(p)
	if string(got) != s || mode != 0o600 || !strings.Contains(msg, "CSV записан") {
		t.Errorf("записано %d байт из %d, права %o, итог %q", len(got), len(s), mode, msg)
	}
	chmodChosen = func(string, os.FileMode) error { return errors.New("отказ") }
	w, _ = storage.Writer(storage.NewFileURI(p))
	if msg := statsCSVResult(w, data, n); !strings.Contains(msg, "права НЕ ограничены") {
		t.Errorf("отказ chmod молча: %q", msg)
	}
}

// TestStatsShots — снимки для отчёта (только при OSMOTR_DIR) и замеры:
// окно 900×600 и широкое; таблица не вылезает за окно.
func TestStatsShots(t *testing.T) {
	v := openStats(t, &statsFake{st: core.CollectorStatus{State: core.CollectorInstalled, Collect: core.CollectWorking, SnapshotAge: 2 * time.Minute}, log: tStatsLog()})
	dir := os.Getenv("OSMOTR_DIR")
	for _, sz := range []fyne.Size{{Width: 900, Height: 600}, {Width: 1400, Height: 700}} {
		v.win.Resize(sz)
		cs := v.win.Canvas().Size()
		tp, ts := v.table.Position(), v.table.Size()
		minW := v.win.Content().MinSize().Width
		t.Logf("окно %.0fx%.0f: канва %.0fx%.0f, таблица (%.0f,%.0f) %.0fx%.0f, минимум содержимого %.0f",
			sz.Width, sz.Height, cs.Width, cs.Height, tp.X, tp.Y, ts.Width, ts.Height, minW)
		if tp.X+ts.Width > cs.Width+0.5 || tp.Y+ts.Height > cs.Height+0.5 {
			t.Errorf("%v: таблица вылезает за окно", sz)
		}
		if minW > 900 {
			t.Errorf("минимум окна статистики %.0f шире 900", minW)
		}
		if dir != "" {
			f, err := os.Create(filepath.Join(dir, fmt.Sprintf("статистика-%.0fx%.0f.png", sz.Width, sz.Height)))
			if err != nil {
				t.Fatal(err)
			}
			if err := png.Encode(f, v.win.Canvas().Capture()); err != nil {
				t.Fatal(err)
			}
			f.Close()
		}
	}
}
