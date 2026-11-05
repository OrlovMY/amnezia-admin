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
	"encoding/csv"
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

// ---------- тексты (смысл — как в cmd/cli/stats.go) ----------

// collectorText — состояние сборщика. «Работает» — только по исходу службы
// и свежему снимку (AU-1, С2), не по «таймер активен».
func collectorText(st core.CollectorStatus) string {
	switch st.State {
	case core.CollectorInstalled:
		switch st.Collect {
		case core.CollectWorking:
			return fmt.Sprintf("установлен, сбор работает (последний снимок %d мин назад, снимок раз в 5 минут)", int(st.SnapshotAge.Minutes()))
		case core.CollectStopped:
			return "установлен, но сбор НЕ работает: " + st.CollectWhy
		case core.CollectPending:
			if !st.NextRun.IsZero() {
				return "установлен, первый снимок ожидается до " + st.NextRun.UTC().Format("15:04") + " UTC"
			}
			return "установлен, первый снимок ожидается (время срабатывания таймера неизвестно)"
		}
		return "установлен; идёт ли сбор — неизвестно: " + st.CollectWhy
	case core.CollectorNotInstalled:
		return "не установлен (кнопка «Установить сборщик»)"
	case core.CollectorPartial:
		return "установлен не полностью или другой версии: " + strings.Join(st.Detail, "; ") +
			" (переустановить: «Установить сборщик»)"
	}
	why := strings.Join(st.Detail, "; ")
	if st.Err != nil {
		why = st.Err.Error()
	}
	if why == "" {
		why = "причина неизвестна"
	}
	return "узнать не удалось: " + why
}

// statsFullText — сборщик остановлен пределом объёма: что делать.
func statsFullText(why string) string {
	head := "Сборщик остановлен: достигнут предел объёма 100 МБ (" + why + "). Новые снимки не пишутся."
	if why == "raw" {
		return head + " Причина — ротация журнала не удаётся (место на диске, awk). Проверьте сервер, затем удалите метку: rm " +
			core.StatsDir + "/FULL — сбор продолжится."
	}
	return head + " Сохраните выгрузку («Выгрузить CSV…» с группировкой по месяцам), затем на сервере освободите место: " +
		"rm " + core.StatsDir + "/daily.log " + core.StatsDir + "/FULL — сбор начнётся заново (старые итоги будут потеряны)."
}

func statsDayText(d int64) string { return core.DayStart(d).Format("2006-01-02") }

// statsDataNotes — полнота данных за период (как statsDataNotes CLI):
// учтённые сутки, дыры между ними, «≥», повреждённые записи, устаревший
// журнал. Строки, а не печать.
func statsDataNotes(l *core.TrafficLog, r core.DayRange) []string {
	var out []string
	any := false
	for _, c := range l.Containers() {
		var days []int64
		for _, d := range l.CoveredDays(c) {
			if d >= r.From && d <= r.To {
				days = append(days, d)
			}
		}
		if len(days) == 0 {
			continue
		}
		any = true
		lo, hi := days[0], days[len(days)-1]
		out = append(out, fmt.Sprintf("%s: учтены сутки (UTC) с %s по %s, всего %d.", c, statsDayText(lo), statsDayText(hi), len(days)))
		have := map[int64]bool{}
		for _, d := range days {
			have[d] = true
		}
		var gaps []string
		n := 0
		for d := lo; d <= hi; d++ {
			if !have[d] {
				n++
				if len(gaps) < 5 {
					gaps = append(gaps, statsDayText(d))
				}
			}
		}
		if n > 0 {
			more := ""
			if n > len(gaps) {
				more = fmt.Sprintf(" и ещё %d", n-len(gaps))
			}
			out = append(out, fmt.Sprintf("⚠ %s: нет снимков за %d сут.: %s%s — цифры за них неполные, если в это время был перезапуск.",
				c, n, strings.Join(gaps, ", "), more))
		}
	}
	if !any {
		out = append(out, "Учтённых интервалов за период нет: нужно не меньше двух снимков в нём.")
	}
	if n := l.PartialIn(r); n > 0 {
		out = append(out, fmt.Sprintf("⚠ Интервалов с перезапуском после перерыва в сборе: %d — трафик до перезапуска в них потерян; "+
			"такие цифры помечены «≥» (не меньше).", n))
	}
	if !l.LastSnapshot.IsZero() {
		out = append(out, "Последний снимок: "+l.LastSnapshot.UTC().Format("2006-01-02 15:04")+" UTC")
	}
	if l.Corrupt > 0 {
		out = append(out, fmt.Sprintf("⚠ Пропущено повреждённых записей: %d — цифры могут быть неполными.", l.Corrupt))
	}
	if l.Failed > 0 {
		out = append(out, fmt.Sprintf("⚠ Снимков, в которых сервер не отдал счётчики: %d.", l.Failed))
	}
	if l.Torn {
		out = append(out, "Последний снимок ещё дописывается или оборван — не учтён.")
	}
	if l.RawStale {
		out = append(out, "⚠ Журнал снимков устарел (ротация на сервере была прервана) и не учтён: "+
			"цифры неполные — нет снимков после последней ротации. Сборщик исправит это при следующем запуске (до 5 минут).")
	}
	if l.Heuristic > 0 {
		out = append(out, fmt.Sprintf("Интервалов без признака перезапуска сервера/контейнера: %d (снимки старого формата). "+
			"В них перезапуск, после которого счётчик успел перерасти прежний, мог остаться незамеченным — цифры могут быть занижены.", l.Heuristic))
	}
	return out
}

// statsRow — клиент: ключ в данных сборщика, протокол, имя.
type statsRow struct {
	key   core.TrafficKey
	proto string
	name  string
}

// statsClients — клиенты контейнера (то, что окно прочитало с сервера).
type statsClients struct {
	c       core.Container
	clients []core.ClientEntry
	err     error
	read    bool // список читался (контейнер под управлением)
}

// statsRowsOf — все клиенты: из clientsTable каждого контейнера семейства
// WG и из данных сборщика (удалённые клиенты остаются в истории).
func statsRowsOf(cs []statsClients, l *core.TrafficLog) ([]statsRow, []string) {
	var notes []string
	rows := map[core.TrafficKey]*statsRow{}
	protoOf := map[string]string{}
	for _, sc := range cs {
		c := sc.c
		protoOf[c.Name] = c.Title()
		if !sc.read {
			continue
		}
		if sc.err != nil {
			notes = append(notes, fmt.Sprintf("⚠ Имена клиентов %s прочитать не удалось: %v — показаны ключи.", c.Title(), sc.err))
			continue
		}
		for _, cl := range sc.clients {
			k := core.TrafficKey{Container: c.Name, PubKey: cl.ClientID}
			rows[k] = &statsRow{key: k, proto: c.Title(), name: cl.Name()}
		}
	}
	if l != nil {
		for _, k := range l.Keys() {
			if rows[k] != nil {
				continue
			}
			p := protoOf[k.Container]
			if p == "" {
				p = k.Container
			}
			rows[k] = &statsRow{key: k, proto: p, name: "(нет в списке клиентов) " + statsShortKey(k.PubKey)}
		}
	}
	out := make([]statsRow, 0, len(rows))
	for _, r := range rows {
		out = append(out, *r)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].proto != out[j].proto {
			return out[i].proto < out[j].proto
		}
		if out[i].name != out[j].name {
			return out[i].name < out[j].name
		}
		return out[i].key.PubKey < out[j].key.PubKey
	})
	return out, notes
}

func statsShortKey(k string) string {
	if r := []rune(k); len(r) > 10 {
		return string(r[:10]) + "…"
	}
	return k
}

// statsCellNums — измеренные цифры (rank 0), нижняя граница (rank 1);
// иначе rank 2 и цифр нет.
func statsCellNums(c core.TrafficCell) (rx, tx int64, rank int) {
	if rx, tx, ok := c.Measured(); ok {
		return rx, tx, 0
	}
	if rx, tx, ok := c.LowerBound(); ok {
		return rx, tx, 1
	}
	return 0, 0, 2
}

// statsCellText — текст одной цифры. Число — только у измеренной ячейки;
// у частично потерянной — «≥ число»; иначе слово, никогда не «0 B».
func statsCellText(c core.TrafficCell, v func(rx, tx int64) int64) string {
	if rx, tx, ok := c.Measured(); ok {
		return core.HumanBytes(v(rx, tx))
	}
	if rx, tx, ok := c.LowerBound(); ok {
		return "≥ " + core.HumanBytes(v(rx, tx))
	}
	switch c.State {
	case core.TrafficNoData:
		return "нет данных"
	case core.TrafficNotInstalled:
		return "не собиралось"
	}
	return "?"
}

func statsSeenText(c core.TrafficCell) string {
	if _, _, rank := statsCellNums(c); rank == 2 {
		return statsCellText(c, nil)
	}
	if c.LastHandshake.IsZero() {
		return "не подключался"
	}
	return c.LastHandshake.UTC().Format("2006-01-02 15:04")
}

func statsRx(rx, _ int64) int64     { return rx }
func statsTx(_, tx int64) int64     { return tx }
func statsTotal(rx, tx int64) int64 { return rx + tx }

func statsStateText(c core.TrafficCell) string {
	switch c.State {
	case core.TrafficMeasured:
		return "измерено"
	case core.TrafficPartial:
		return "неполные (не меньше)"
	case core.TrafficNoData:
		return "нет данных"
	case core.TrafficNotInstalled:
		return "сборщик не установлен"
	}
	return "неизвестно"
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
		return r, statsDayText(r.From) + " … " + statsDayText(r.To), nil
	case statsPeriodWeek:
		r := core.DayRange{From: today - 6, To: today}
		return r, statsDayText(r.From) + " … " + statsDayText(r.To), nil
	case statsPeriodDay:
		return core.DayRange{From: today, To: today}, statsDayText(today), nil
	}
	r := core.AllTime
	parse := func(s string) (int64, error) {
		t, err := time.ParseInLocation("2006-01-02", strings.TrimSpace(s), time.UTC)
		if err != nil {
			return 0, fmt.Errorf("дата %q: нужен формат ГГГГ-ММ-ДД", strings.TrimSpace(s))
		}
		return core.DayOf(t), nil
	}
	from, to = strings.TrimSpace(from), strings.TrimSpace(to)
	if from != "" {
		d, err := parse(from)
		if err != nil {
			return r, "", err
		}
		r.From = d
	}
	if to != "" {
		d, err := parse(to)
		if err != nil {
			return r, "", err
		}
		r.To = d
	}
	if r.From > r.To {
		return r, "", fmt.Errorf("начало периода позже конца")
	}
	switch {
	case from == "" && to == "":
		return r, "за всё время", nil
	case to == "":
		return r, "с " + from, nil
	case from == "":
		return r, "по " + to, nil
	}
	return r, from + " … " + to, nil
}

type statsPeriod struct {
	label string
	r     core.DayRange
}

// statsPeriods — один период или сутки/месяцы между первыми и последними
// учтёнными сутками, обрезанные периодом (как CLI -by).
func statsPeriods(l *core.TrafficLog, r core.DayRange, label, group string) []statsPeriod {
	if group == "" || group == statsGroupNone {
		return []statsPeriod{{label, r}}
	}
	days := l.CoveredDays("")
	if len(days) == 0 {
		return nil
	}
	lo, hi := days[0], days[len(days)-1]
	if r.From > lo {
		lo = r.From
	}
	if r.To < hi {
		hi = r.To
	}
	var ps []statsPeriod
	for d := lo; d <= hi; d++ {
		if group == statsGroupDay {
			ps = append(ps, statsPeriod{statsDayText(d), core.DayRange{From: d, To: d}})
			continue
		}
		m := core.DayStart(d).Format("2006-01")
		if len(ps) > 0 && ps[len(ps)-1].label == m {
			ps[len(ps)-1].r.To = d
			continue
		}
		ps = append(ps, statsPeriod{m, core.DayRange{From: d, To: d}})
	}
	return ps
}

// ---------- строки таблицы и сортировка ----------

// statsLine — строка таблицы: период, клиент, его ячейка.
type statsLine struct {
	period string
	pi     int // номер периода (группы держатся вместе)
	row    statsRow
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
		if a.row.name != b.row.name {
			return a.row.name < b.row.name
		}
		return a.row.key.PubKey < b.row.key.PubKey
	}
	cmp := 0 // -1 a<b, 1 a>b по значению столбца
	switch col {
	case statsColProto, statsColName:
		x, y := a.row.name, b.row.name
		if col == statsColProto {
			x, y = a.row.proto, b.row.proto
		}
		if x != y {
			if (x < y) != desc {
				return true
			}
			return false
		}
		return byName()
	}
	ra, ta, ka := statsCellNums(a.cell)
	rb, tb, kb := statsCellNums(b.cell)
	if ka != kb {
		return ka < kb
	}
	if ka < 2 {
		var x, y int64
		switch col {
		case statsColRx:
			x, y = ra, rb
		case statsColTx:
			x, y = ta, tb
		case statsColTotal:
			x, y = ra+ta, rb+tb
		case statsColSeen:
			x, y = a.cell.LastHandshake.Unix(), b.cell.LastHandshake.Unix()
			if a.cell.LastHandshake.IsZero() {
				x = -1 << 62
			}
			if b.cell.LastHandshake.IsZero() {
				y = -1 << 62
			}
		}
		switch {
		case x < y:
			cmp = -1
		case x > y:
			cmp = 1
		}
	}
	if cmp != 0 {
		return (cmp < 0) != desc
	}
	return byName()
}

func statsSortLines(ls []statsLine, col int, desc bool) {
	sort.SliceStable(ls, func(i, j int) bool { return statsLess(ls[i], ls[j], col, desc) })
}

// statsCellAt — текст ячейки столбца col.
func statsCellAt(ln statsLine, col int) string {
	switch col {
	case statsColProto:
		return ln.row.proto
	case statsColName:
		return ln.row.name
	case statsColRx:
		return statsCellText(ln.cell, statsRx)
	case statsColTx:
		return statsCellText(ln.cell, statsTx)
	case statsColTotal:
		return statsCellText(ln.cell, statsTotal)
	case statsColSeen:
		return statsSeenText(ln.cell)
	}
	return ""
}

// ---------- CSV (формат — как `stats -csv`) ----------

const statsUTF8BOM = "\xef\xbb\xbf"

// statsCSVSafe — ячейка, которую Excel не примет за формулу: закрытый
// список первых символов (как csvSafe CLI).
func statsCSVSafe(s string) string {
	if s == "" {
		return s
	}
	r := []rune(s)[0]
	if r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9' ||
		r >= 'А' && r <= 'я' || r == 'Ё' || r == 'ё' {
		return s
	}
	return "'" + s
}

// statsCSV — содержимое файла и число строк данных. Пустые цифры — «нет
// данных», не ноль (столбец «Состояние» говорит это словами).
func statsCSV(rows []statsRow, l *core.TrafficLog, cs core.CollectorState, periods []statsPeriod) ([]byte, int, error) {
	var b strings.Builder
	b.WriteString(statsUTF8BOM)
	w := csv.NewWriter(&b)
	w.Comma = ';'
	w.UseCRLF = true
	_ = w.Write([]string{"Период", "Протокол", "Клиент", "Публичный ключ", "Принято, байт", "Отправлено, байт", "Всего, байт", "Последнее подключение (UTC)", "Состояние"})
	n := 0
	for _, p := range periods {
		for _, row := range rows {
			c := l.Cell(row.key, p.r, cs)
			rec := []string{p.label, row.proto, row.name, row.key.PubKey, "", "", "", "", statsStateText(c)}
			if rx, tx, rank := statsCellNums(c); rank < 2 {
				rec[4], rec[5], rec[6] = fmt.Sprint(rx), fmt.Sprint(tx), fmt.Sprint(rx+tx)
				if !c.LastHandshake.IsZero() {
					rec[7] = c.LastHandshake.UTC().Format("2006-01-02 15:04")
				}
			}
			for i := range rec {
				rec[i] = statsCSVSafe(rec[i])
			}
			_ = w.Write(rec)
			n++
		}
	}
	w.Flush()
	if err := w.Error(); err != nil {
		return nil, 0, err
	}
	return []byte(b.String()), n, nil
}

// statsInstallText — полный текст того, что будет записано на сервер
// (как `stats install` перед вопросом).
func statsInstallText(st core.CollectorStatus) string {
	var b strings.Builder
	b.WriteString("Сейчас: " + collectorText(st) + "\n")
	b.WriteString("Будет выполнено на сервере (от root): mkdir -p " + core.StatsDir +
		"; каждый файл пишется во временный <путь>.new, получает права и переносится на место (mv):\n")
	for _, f := range core.StatsInstallFiles() {
		fmt.Fprintf(&b, "\n── %s (права %s) ──\n%s", f.Path, f.Mode, f.Content)
	}
	b.WriteString("\nзатем: systemctl daemon-reload; systemctl enable --now " + core.StatsUnit + ".timer\n")
	b.WriteString("Сборщик раз в 5 минут читает счётчики wg/awg (только чтение) и дописывает снимок в " + core.StatsDir +
		"; объём — не более 100 МБ (старые снимки сворачиваются в суточные итоги). Снять: кнопка «Снять сборщик».")
	return b.String()
}

// statsUninstallText — что будет сделано при снятии.
func statsUninstallText(st core.CollectorStatus) string {
	return "Сейчас: " + collectorText(st) + "\n" +
		"Будет: systemctl disable --now " + core.StatsUnit + ".timer; удалены " +
		core.StatsTimerPath + ", " + core.StatsServicePath + ", " + core.StatsScriptPath + ".\n" +
		"Накопленные данные (" + core.StatsDir + "/snapshots.log, daily.log) ОСТАЮТСЯ; удалить их вручную: rm -r " + core.StatsDir
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
	loaded  bool
	st      core.CollectorStatus
	log     *core.TrafficLog
	readErr error
	clients []statsClients

	rows      []statsRow
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
		container.NewHBox(msgLabel("Период:"), statsSelectBox(v.periodSel), v.customRow, msgLabel("Разбивка:"), statsSelectBox(v.groupSel)),
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
	v.loaded, v.log, v.readErr, v.clients = false, nil, nil, nil
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
			clients []statsClients
			done    bool
		)
		defer func() {
			uiDo(func() {
				if done {
					v.st, v.log, v.readErr, v.clients, v.loaded = st, l, err, clients, true
					v.status.SetText("Сборщик статистики: " + collectorText(st))
				} else {
					v.status.SetText("Сборщик статистики: чтение прервано — данных нет. Нажмите «Обновить».")
				}
				v.rebuild()
				v.setBusy(false)
			})
		}()
		st = statsReadStatus(sess)
		l, err = statsReadTraffic(sess)
		if err == nil {
			for i := range conts {
				c := conts[i]
				if _, ferr := core.WGFamilyOf(&c); ferr != nil {
					continue
				}
				sc := statsClients{c: c}
				if c.Managed() {
					sc.read = true
					sc.clients, sc.err = statsLoadClients(sess, &c)
				}
				clients = append(clients, sc)
			}
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
			notes = append(notes, "⚠ "+statsFullText(v.st.Full))
		}
		r, label, err := statsRangeOf(v.periodSel.Selected, v.fromEntry.Text, v.toEntry.Text, statsNow())
		if err != nil {
			v.rangeErr = err
			notes = append(notes, "Период задан неверно: "+err.Error()+" — таблица не строится.")
			break
		}
		v.periodLbl = label
		v.rows, v.rowNotes = statsRowsOf(v.clients, v.log)
		periods := statsPeriods(v.log, r, label, v.groupSel.Selected)
		for pi, p := range periods {
			for _, row := range v.rows {
				v.lines = append(v.lines, statsLine{period: p.label, pi: pi, row: row, cell: v.log.Cell(row.key, p.r, v.st.State)})
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
		notes = append(notes, statsDataNotes(v.log, r)...)
		notes = append(notes, v.rowNotes...)
		for i := range v.containers {
			if core.IsXRay(&v.containers[i]) {
				notes = append(notes, "XRay: сервер не ведёт счётчиков трафика по клиентам — статистики по ним нет.")
				break
			}
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
	periods := statsPeriods(v.log, r, label, v.groupSel.Selected)
	data, n, err := statsCSV(v.rows, v.log, v.st.State, periods)
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
