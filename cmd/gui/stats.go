package main

// Окно «Статистика» (задание GUI-STATS): то же, что `amnezia-admin stats`
// (cmd/cli/stats.go), но в окне. Данные копит сборщик на сервере
// (core/trafficstats*.go).
//
// ТРИ СОСТОЯНИЯ (CLAUDE.md, инцидент ложного нуля 25.09): каждая цифра —
// core.TrafficCell; на экран она попадает только через statsCellText, и
// «нет данных» никогда не становится «0 B». Сортировка — тоже утверждение:
// «нет данных» всегда ниже измеренного нуля, «не меньше» — между ними,
// в какую сторону ни сортируй.
//
// ПРИЗНАК 4 (молчаливое сохранение прежнего): при перечитывании таблица
// сначала очищается; не удалось прочитать — таблица пуста и сказано почему,
// старые цифры не остаются на экране.

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/storage"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"amnezia-admin/core"
	"amnezia-admin/internal/statsview"
)

// Швы теста: чтение и запись на сервер. В бою — методы core.Session.
var (
	statsReadStatus  = func(s *core.Session) core.CollectorStatus { return s.StatsStatus() }
	statsReadTraffic = func(s *core.Session) (*core.TrafficLog, error) { return s.ReadTraffic() }
	statsLoadClients = func(s *core.Session, c *core.Container) ([]core.ClientEntry, error) { return s.LoadClients(c) }
	statsInstall     = func(s *core.Session) error { return s.StatsInstall() }
	statsUninstall   = func(s *core.Session) error { return s.StatsUninstall() }
	statsNow         = time.Now
)

// statsButtonLabel — подпись кнопки главного окна.
const statsButtonLabel = "Статистика"

// ---------- тексты: правила — в internal/statsview (одна копия с CLI) ----------

// guiHints — как окно называет действия в текстах общего пакета.
var guiHints = statsview.Hints{
	Install:   "«Установить сборщик…»",
	Uninstall: "«Снять сборщик…»",
	Export:    "«Выгрузить CSV…» с разбивкой по месяцам",
}

func collectorText(st core.CollectorStatus) string { return statsview.CollectorText(st, guiHints) }

// noteText — пометка общего пакета строкой окна: предупреждение — со
// знаком ⚠ (цвета в подписи нет).
func noteText(n statsview.Note) string {
	if n.Level == statsview.Warn {
		return "⚠ " + strings.TrimSpace(n.Text)
	}
	return strings.TrimSpace(n.Text)
}

// ---------- период и группировка ----------

// Пункты выбора периода.
const (
	statsPeriodAll    = "Всё время"
	statsPeriodMonth  = "Месяц (30 сут.)"
	statsPeriodWeek   = "Неделя (7 сут.)"
	statsPeriodDay    = "Сутки (сегодня)"
	statsPeriodCustom = "Свой интервал"
)

var statsPeriodOptions = []string{statsPeriodAll, statsPeriodMonth, statsPeriodWeek, statsPeriodDay, statsPeriodCustom}

// Пункты группировки.
const (
	statsGroupNone  = "Без разбивки"
	statsGroupDay   = "По дням"
	statsGroupMonth = "По месяцам"
)

var statsGroupOptions = []string{statsGroupNone, statsGroupDay, statsGroupMonth}

// statsRangeOf — период по выбору; сутки по UTC, «сегодня» — по now.
func statsRangeOf(choice, from, to string, now time.Time) (core.DayRange, string, error) {
	today := core.DayOf(now)
	switch choice {
	case statsPeriodAll, "":
		return core.AllTime, "за всё время", nil
	case statsPeriodMonth:
		r := core.DayRange{From: today - 29, To: today}
		return r, statsview.DayText(r.From) + " … " + statsview.DayText(r.To), nil
	case statsPeriodWeek:
		r := core.DayRange{From: today - 6, To: today}
		return r, statsview.DayText(r.From) + " … " + statsview.DayText(r.To), nil
	case statsPeriodDay:
		return core.DayRange{From: today, To: today}, statsview.DayText(today), nil
	}
	return statsview.ParseRange(strings.TrimSpace(from), strings.TrimSpace(to))
}

// statsBy — пункт разбивки как аргумент statsview.Periods.
func statsBy(group string) string {
	switch group {
	case statsGroupDay:
		return "day"
	case statsGroupMonth:
		return "month"
	}
	return ""
}

// ---------- строки таблицы и сортировка ----------

// statsLine — строка таблицы: период, клиент, его ячейка.
type statsLine struct {
	period string
	pi     int // номер периода (группы держатся вместе)
	row    statsview.Row
	cell   core.TrafficCell
}

// Столбцы таблицы (без «Период»: он есть только при разбивке).
const (
	statsColProto = iota
	statsColName
	statsColRx
	statsColTx
	statsColTotal
	statsColSeen
	statsColCount
)

var statsColTitles = [statsColCount]string{"Протокол", "Имя", "Принято", "Отправлено", "Всего", "Последнее подключение (UTC)"}

// statsLess — порядок двух строк по столбцу col. desc меняет направление
// ВНУТРИ одного исхода, но не порядок исходов: измеренные, затем «не
// меньше», затем «нет данных» — всегда (25.09: нарушение было в сортировке).
func statsLess(a, b statsLine, col int, desc bool) bool {
	if a.pi != b.pi {
		return a.pi < b.pi
	}
	byName := func() bool {
		if a.row.Name != b.row.Name {
			return a.row.Name < b.row.Name
		}
		return a.row.Key.PubKey < b.row.Key.PubKey
	}
	switch col {
	case statsColProto, statsColName:
		x, y := a.row.Name, b.row.Name
		if col == statsColProto {
			x, y = a.row.Proto, b.row.Proto
		}
		if x != y {
			return (x < y) != desc
		}
		return byName()
	}
	if c := statsview.Compare(a.cell, b.cell, statsNumCol[col], desc); c != 0 {
		return c < 0
	}
	return byName()
}

// statsNumCol — столбец окна → столбец цифр общего пакета.
var statsNumCol = map[int]statsview.Col{statsColRx: statsview.ColRx, statsColTx: statsview.ColTx, statsColTotal: statsview.ColTotal, statsColSeen: statsview.ColSeen}

func statsSortLines(ls []statsLine, col int, desc bool) {
	sort.SliceStable(ls, func(i, j int) bool { return statsLess(ls[i], ls[j], col, desc) })
}

// statsCellAt — текст ячейки столбца col.
func statsCellAt(ln statsLine, col int) string {
	switch col {
	case statsColProto:
		return ln.row.Proto
	case statsColName:
		return ln.row.Name
	case statsColRx:
		return statsview.CellText(ln.cell, statsview.Rx)
	case statsColTx:
		return statsview.CellText(ln.cell, statsview.Tx)
	case statsColTotal:
		return statsview.CellText(ln.cell, statsview.Total)
	case statsColSeen:
		return statsview.SeenText(ln.cell)
	}
	return ""
}

// statsInstallText — полный текст того, что будет записано на сервер.
func statsInstallText(st core.CollectorStatus) string {
	return "Сейчас: " + collectorText(st) + "\n" + statsview.InstallText(guiHints)
}

// statsUninstallText — что будет сделано при снятии.
func statsUninstallText(st core.CollectorStatus) string {
	return "Сейчас: " + collectorText(st) + "\n" + statsview.UninstallText()
}

// ---------- окно ----------

// statsView — окно «Статистика».
type statsView struct {
	u   *ui
	win fyne.Window
	// containers — снимок списка протоколов на момент открытия.
	containers []core.Container

	// Прочитанное. loaded=false — данных на экране нет (идёт чтение или
	// не удалось): таблица пуста, а не показывает прежнее.
	loaded bool
	// aborted — последнее чтение прервано (паника/обрыв в горутине): данных
	// нет, и это не «идёт чтение».
	aborted bool
	st      core.CollectorStatus
	log     *core.TrafficLog
	readErr error
	clients []statsview.ContainerClients

	rows      []statsview.Row
	rowNotes  []string
	lines     []statsLine
	grouped   bool
	sortCol   int
	sortDesc  bool
	rangeErr  error
	periodLbl string

	status     *msgText
	notes      *msgText
	table      *widget.Table
	periodSel  *widget.Select
	groupSel   *widget.Select
	fromEntry  *widget.Entry
	toEntry    *widget.Entry
	customRow  *fyne.Container
	refreshBtn *widget.Button
	installBtn *widget.Button
	removeBtn  *widget.Button
	csvBtn     *widget.Button

	// shown — последний показанный диалог (для тестов).
	shown dialog.Dialog
}

// showStats — открыть (или поднять) окно «Статистика».
func (u *ui) showStats() {
	if u.sess == nil {
		u.showInfo(statsButtonLabel, "Нет подключения к серверу — статистику читать неоткуда.")
		return
	}
	if u.statsView != nil {
		u.statsView.win.RequestFocus()
		return
	}
	v := newStatsView(u)
	u.statsView = v
	v.win.SetOnClosed(func() {
		if u.statsView == v {
			u.statsView = nil
		}
	})
	v.win.Show()
	v.reload()
}

func newStatsView(u *ui) *statsView {
	v := &statsView{u: u, sortCol: statsColTotal, sortDesc: true}
	v.containers = append([]core.Container(nil), u.containers...)
	v.win = fyne.CurrentApp().NewWindow(statsButtonLabel + " — " + u.sess.Creds.Host)

	v.status = wrapped(msgLabel(""))
	v.notes = wrapped(msgLabel(""))
	v.refreshBtn = widget.NewButtonWithIcon("Обновить", theme.ViewRefreshIcon(), func() { v.reload() })
	v.installBtn = widget.NewButtonWithIcon("Установить сборщик…", theme.DownloadIcon(), func() { v.confirmInstall() })
	v.removeBtn = widget.NewButtonWithIcon("Снять сборщик…", theme.DeleteIcon(), func() { v.confirmUninstall() })
	v.csvBtn = widget.NewButtonWithIcon("Выгрузить CSV…", theme.DocumentSaveIcon(), func() { v.exportCSV() })

	v.fromEntry = widget.NewEntry()
	v.fromEntry.SetPlaceHolder("ГГГГ-ММ-ДД")
	v.toEntry = widget.NewEntry()
	v.toEntry.SetPlaceHolder("ГГГГ-ММ-ДД")
	v.fromEntry.OnChanged = func(string) { v.rebuild() }
	v.toEntry.OnChanged = func(string) { v.rebuild() }
	v.customRow = container.NewHBox(msgLabel("с"), container.NewGridWrap(fyne.NewSize(130, v.fromEntry.MinSize().Height), v.fromEntry),
		msgLabel("по"), container.NewGridWrap(fyne.NewSize(130, v.toEntry.MinSize().Height), v.toEntry), msgLabel("(UTC, включительно)"))
	v.customRow.Hide()
	v.periodSel = widget.NewSelect(statsPeriodOptions, func(s string) {
		if s == statsPeriodCustom {
			v.customRow.Show()
		} else {
			v.customRow.Hide()
		}
		v.rebuild()
	})
	v.periodSel.Selected = statsPeriodAll
	v.groupSel = widget.NewSelect(statsGroupOptions, func(string) { v.rebuild() })
	v.groupSel.Selected = statsGroupNone

	v.table = widget.NewTable(v.tableSize,
		func() fyne.CanvasObject { return msgLabel("") },
		func(id widget.TableCellID, o fyne.CanvasObject) { o.(*msgText).SetText(v.cellText(id)) })
	v.table.ShowHeaderRow = true
	v.table.CreateHeader = func() fyne.CanvasObject { return widget.NewButton("", nil) }
	v.table.UpdateHeader = func(id widget.TableCellID, o fyne.CanvasObject) {
		b := o.(*widget.Button)
		col := v.colAt(id.Col)
		b.SetText(v.headerText(col))
		b.OnTapped = func() { v.sortBy(col) }
	}
	v.applyColumns()

	top := container.NewVBox(
		withCopy(v.status),
		container.NewHBox(v.refreshBtn, v.installBtn, v.removeBtn, v.csvBtn),
		container.NewHBox(msgLabel("Период:"), statsSelectBox(v.periodSel), msgLabel("Разбивка:"), statsSelectBox(v.groupSel)),
		// Поля дат — отдельной строкой: в одной строке с «Период/Разбивка»
		// минимум окна был 949 > 900 (ревью GUI-STATS-1, M1).
		v.customRow,
	)
	notes := container.NewVScroll(withCopy(v.notes))
	notes.SetMinSize(fyne.NewSize(0, 110))
	v.win.SetContent(container.NewBorder(top, notes, nil, nil, v.table))
	v.win.Resize(fyne.NewSize(900, 600))
	v.setBusy(true)
	return v
}

// statsSelectBox — список шириной по самому длинному пункту (иначе Select
// усекает подпись многоточием: «Без разбив…» на снимке 900×600).
func statsSelectBox(sel *widget.Select) fyne.CanvasObject {
	w := float32(0)
	for _, o := range sel.Options {
		if tw := fyne.MeasureText(o, theme.TextSize(), fyne.TextStyle{}).Width; tw > w {
			w = tw
		}
	}
	return container.NewGridWrap(fyne.NewSize(w+theme.IconInlineSize()+6*theme.Padding(), sel.MinSize().Height), sel)
}

// colAt — столбец таблицы по номеру (при разбивке первый — «Период»).
func (v *statsView) colAt(c int) int {
	if v.grouped {
		return c - 1 // -1 — «Период»
	}
	return c
}

func (v *statsView) headerText(col int) string {
	if col < 0 {
		return "Период"
	}
	t := statsColTitles[col]
	if col == v.sortCol {
		if v.sortDesc {
			t += " ▼"
		} else {
			t += " ▲"
		}
	}
	return t
}

func (v *statsView) tableSize() (int, int) {
	n := statsColCount
	if v.grouped {
		n++
	}
	return len(v.lines), n
}

func (v *statsView) cellText(id widget.TableCellID) string {
	if id.Row < 0 || id.Row >= len(v.lines) {
		return ""
	}
	col := v.colAt(id.Col)
	if col < 0 {
		return v.lines[id.Row].period
	}
	return statsCellAt(v.lines[id.Row], col)
}

// applyColumns — ширины столбцов: по самому длинному тексту столбца.
func (v *statsView) applyColumns() {
	_, n := v.tableSize()
	ts := theme.TextSize()
	pad := 4*theme.Padding() + 14
	for c := 0; c < n; c++ {
		col := v.colAt(c)
		w := fyne.MeasureText(v.headerText(col)+" ▼", ts, fyne.TextStyle{}).Width
		for _, ln := range v.lines {
			txt := ln.period
			if col >= 0 {
				txt = statsCellAt(ln, col)
			}
			if tw := fyne.MeasureText(txt, ts, fyne.TextStyle{}).Width; tw > w {
				w = tw
			}
		}
		if col == statsColName && w > 320 {
			w = 320
		}
		v.table.SetColumnWidth(c, w+pad)
	}
}

func (v *statsView) sortBy(col int) {
	if col < 0 {
		return
	}
	if v.sortCol == col {
		v.sortDesc = !v.sortDesc
	} else {
		v.sortCol = col
		// Числа — сначала большие, имена — по алфавиту.
		v.sortDesc = col != statsColName && col != statsColProto
	}
	statsSortLines(v.lines, v.sortCol, v.sortDesc)
	v.table.Refresh()
}

// setBusy — во время чтения/записи кнопки выключены, таблица пуста.
func (v *statsView) setBusy(busy bool) {
	if busy {
		v.refreshBtn.Disable()
		v.installBtn.Disable()
		v.removeBtn.Disable()
		v.csvBtn.Disable()
		return
	}
	v.refreshBtn.Enable()
	if v.st.State == core.CollectorInstalled {
		v.installBtn.Disable()
	} else {
		v.installBtn.Enable()
	}
	if v.st.State == core.CollectorNotInstalled {
		v.removeBtn.Disable()
	} else {
		v.removeBtn.Enable()
	}
	if v.hasTable() {
		v.csvBtn.Enable()
	} else {
		v.csvBtn.Disable()
	}
}

// hasTable — прочитано, и строить таблицу есть из чего (как CLI: без
// сборщика и без данных — не таблица из «не собиралось», а объяснение).
func (v *statsView) hasTable() bool {
	return v.loaded && v.readErr == nil && v.log != nil &&
		!(v.log.Empty() && v.st.State == core.CollectorNotInstalled)
}

// reload — перечитать всё с сервера. Прежние цифры убираются с экрана
// сразу (признак 4: не показывать старое, не сказав, что оно старое).
func (v *statsView) reload() {
	v.loaded, v.aborted, v.log, v.readErr, v.clients = false, false, nil, nil, nil
	v.st = core.CollectorStatus{}
	v.status.SetText("Сборщик статистики: читаю с сервера…")
	v.rebuild()
	v.setBusy(true)
	sess, conts := v.u.sess, v.containers
	goSafe(func() {
		var (
			st      core.CollectorStatus
			l       *core.TrafficLog
			err     error
			clients []statsview.ContainerClients
			done    bool
		)
		defer func() {
			uiDo(func() {
				if done {
					v.st, v.log, v.readErr, v.clients, v.loaded = st, l, err, clients, true
					v.status.SetText("Сборщик статистики: " + collectorText(st))
				} else {
					v.aborted = true
					v.status.SetText("Сборщик статистики: чтение прервано — данных нет. Нажмите «Обновить».")
				}
				v.rebuild()
				v.setBusy(false)
			})
		}()
		st = statsReadStatus(sess)
		l, err = statsReadTraffic(sess)
		if err == nil {
			clients = statsview.ReadClients(conts, func(c *core.Container) ([]core.ClientEntry, error) { return statsLoadClients(sess, c) })
		}
		done = true
	})
}

// rebuild — пересчитать строки таблицы и пометки по прочитанному,
// выбранному периоду и разбивке (без обращения к серверу).
func (v *statsView) rebuild() {
	v.lines, v.rows, v.rowNotes, v.rangeErr, v.periodLbl = nil, nil, nil, nil, ""
	v.grouped = v.groupSel.Selected == statsGroupDay || v.groupSel.Selected == statsGroupMonth
	var notes []string
	switch {
	case !v.loaded && v.aborted:
		notes = append(notes, "Данных на экране нет: чтение прервано. Нажмите «Обновить».")
	case !v.loaded:
		notes = append(notes, "Данных на экране нет: идёт чтение с сервера.")
	case v.readErr != nil:
		notes = append(notes, "Статистику прочитать не удалось: "+v.readErr.Error()+" — таблица не строится (это не «0 B»).")
	case v.log == nil:
		notes = append(notes, "Статистику прочитать не удалось: сервер не вернул данных — таблица не строится.")
	case v.log.Empty() && v.st.State == core.CollectorNotInstalled:
		notes = append(notes, "Накопленной статистики нет: сборщик на сервере не установлен. Счётчики сервера обнуляются при перезапуске, "+
			"поэтому «за всё время» начнёт копиться только после установки («Установить сборщик…»).")
	default:
		if v.st.Full != "" {
			notes = append(notes, "⚠ "+statsview.FullText(v.st.Full, guiHints))
		}
		r, label, err := statsRangeOf(v.periodSel.Selected, v.fromEntry.Text, v.toEntry.Text, statsNow())
		if err != nil {
			v.rangeErr = err
			notes = append(notes, "Период задан неверно: "+err.Error()+" — таблица не строится.")
			break
		}
		v.periodLbl = label
		v.rows, v.rowNotes = statsview.Rows(v.clients, v.log)
		periods := statsview.Periods(v.log, r, label, statsBy(v.groupSel.Selected))
		for pi, p := range periods {
			for _, row := range v.rows {
				v.lines = append(v.lines, statsLine{period: p.Name, pi: pi, row: row, cell: v.log.Cell(row.Key, p.R, v.st.State)})
			}
		}
		statsSortLines(v.lines, v.sortCol, v.sortDesc)
		notes = append(notes, "Период: "+label+" (сутки по UTC). Принято — от клиента, отправлено — клиенту (со стороны сервера). "+
			"«≥» — не меньше (часть трафика потеряна при перезапуске); «нет данных» — не ноль.")
		if len(v.rows) == 0 {
			notes = append(notes, "Клиентов нет.")
		} else if v.grouped && len(periods) == 0 {
			notes = append(notes, "Учтённых суток в периоде нет — разбивать нечего.")
		}
		for _, n := range statsview.DataNotes(v.log, r) {
			notes = append(notes, noteText(n))
		}
		for _, n := range v.rowNotes {
			notes = append(notes, "⚠ "+n)
		}
		if n := statsview.XRayNote(v.containers); n != "" {
			notes = append(notes, n)
		}
	}
	v.notes.SetText(strings.Join(notes, "\n"))
	v.applyColumns()
	v.table.Refresh()
	if v.loaded {
		v.setBusy(false)
	}
}

// showText — диалог сообщения в окне статистики (выделяемый текст).
func (v *statsView) showText(title, text string) {
	l := wrapped(msgLabel(text))
	d := dialog.NewCustom(title, "Закрыть", withCopyBelow(l), v.win)
	d.Resize(fyne.NewSize(infoDialogWidth, d.MinSize().Height))
	v.shown = d
	d.Show()
}

// confirmWrite — подтверждение записи на сервер: полный текст в прокрутке,
// запись — только по «Да».
func (v *statsView) confirmWrite(title, text string, yes func()) {
	l := wrapped(msgLabel(text))
	sc := container.NewVScroll(withCopyBelow(l))
	d := dialog.NewCustomConfirm(title, "Да", "Нет", sc, func(ok bool) {
		if ok {
			yes()
		}
	}, v.win)
	cs := v.win.Canvas().Size()
	w, h := float32(820), float32(520)
	if cs.Width > 0 && cs.Width-40 < w {
		w = cs.Width - 40
	}
	if cs.Height > 0 && cs.Height-40 < h {
		h = cs.Height - 40
	}
	d.Resize(fyne.NewSize(w, h))
	v.shown = d
	d.Show()
}

func (v *statsView) confirmInstall() {
	st := v.st
	v.confirmWrite("Установить сборщик статистики?", statsInstallText(st), func() {
		v.write("Установка", statsInstall, core.CollectorInstalled)
	})
}

func (v *statsView) confirmUninstall() {
	st := v.st
	v.confirmWrite("Снять сборщик статистики?", statsUninstallText(st), func() {
		v.write("Снятие", statsUninstall, core.CollectorNotInstalled)
	})
}

// write — установка/снятие вне потока интерфейса; исход — по состоянию,
// перечитанному ПОСЛЕ записи (ошибка записи не значит «не записано»).
func (v *statsView) write(what string, do func(*core.Session) error, want core.CollectorState) {
	v.setBusy(true)
	v.status.SetText("Сборщик статистики: " + strings.ToLower(what) + " на сервере…")
	sess := v.u.sess
	goSafe(func() {
		var (
			err   error
			after core.CollectorStatus
			done  bool
		)
		defer func() {
			uiDo(func() {
				switch {
				case !done:
					v.showText(what, what+" прервана; что на сервере — неизвестно. Нажмите «Обновить».")
				case err != nil:
					v.showText(what, what+" не подтверждена: "+err.Error()+"\nСборщик сейчас: "+collectorText(after))
				case after.State != want:
					v.showText(what, what+" выполнена, но состояние не то, что ожидалось.\nСборщик сейчас: "+collectorText(after))
				default:
					v.showText(what, "Готово. Сборщик: "+collectorText(after))
				}
				v.reload()
			})
		}()
		err = do(sess)
		after = statsReadStatus(sess)
		done = true
	})
}

// exportCSV — «Выгрузить CSV…»: период и разбивка — как на экране, строки
// — все клиенты (порядок как у CLI), права файла 0600.
func (v *statsView) exportCSV() {
	if !v.hasTable() || v.rangeErr != nil {
		v.showText("Выгрузить CSV", "Выгружать нечего: данных на экране нет.")
		return
	}
	r, label, err := statsRangeOf(v.periodSel.Selected, v.fromEntry.Text, v.toEntry.Text, statsNow())
	if err != nil {
		v.showText("Выгрузить CSV", "Период задан неверно: "+err.Error())
		return
	}
	periods := statsview.Periods(v.log, r, label, statsBy(v.groupSel.Selected))
	data, n, err := statsview.CSV(v.rows, v.log, v.st.State, periods)
	if err != nil {
		v.showText("Выгрузить CSV", "CSV не собран: "+err.Error())
		return
	}
	fd := dialog.NewFileSave(func(w fyne.URIWriteCloser, err error) {
		if err != nil {
			v.showText("Выгрузить CSV", "CSV не записан: "+err.Error())
			return
		}
		if w == nil {
			return // отмена
		}
		v.status.SetText(statsCSVResult(w, data, n))
	}, v.win)
	fd.SetFileName("статистика.csv")
	fd.SetFilter(storage.NewExtensionFileFilter([]string{".csv"}))
	v.shown = fd
	fd.Show()
}

// statsCSVResult — записать CSV в выбранный файл (права 0600) и вернуть
// строку итога для строки состояния.
func statsCSVResult(w fyne.URIWriteCloser, data []byte, n int) string {
	where := w.URI().Path()
	_, werr := w.Write(data)
	cerr := w.Close()
	if werr == nil {
		werr = cerr
	}
	if werr != nil {
		return "CSV НЕ записан в " + where + ": " + werr.Error()
	}
	if w.URI().Scheme() == "file" {
		if err := chmodChosen(where, 0o600); err != nil {
			return fmt.Sprintf("CSV записан: %s, но права НЕ ограничены (%v)", where, err)
		}
	}
	s := fmt.Sprintf("CSV записан: %s (строк: %d; пустые цифры — «нет данных», не ноль).", where, n)
	if n == 0 {
		s += " Учтённых суток нет — в файле только заголовок."
	}
	return s
}
