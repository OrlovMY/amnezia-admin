package main

// `stats` — статистика трафика VPN по клиентам за всё время (задание
// TRAFFIC-STATS). Данные копит сборщик на сервере (core/trafficstats_script.go);
// здесь — установка/снятие с подтверждением, таблица и выгрузка CSV.
//
// Каждая цифра — core.TrafficCell с тремя исходами; ячейка печатается
// через statsCellText, и «нет данных» никогда не превращается в «0 B»
// (история ложного нуля трафика, 25.09). Сортировка — тоже: клиенты без
// данных идут ПОСЛЕ измеренных, а не среди нулей.

import (
	"encoding/csv"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"amnezia-admin/core"
)

// statsSource — то, что `stats` читает с сервера.
type statsSource interface {
	StatsStatus() core.CollectorStatus
	ReadTraffic() (*core.TrafficLog, error)
	LoadClients(c *core.Container) ([]core.ClientEntry, error)
}

// statsWriter — запись на сервер (install/uninstall).
type statsWriter interface {
	StatsInstall() error
	StatsUninstall() error
}

type statsFlags struct {
	from, to, csv, by string
}

const statsUsage = "stats [status|install|uninstall] [-from ГГГГ-ММ-ДД] [-to ГГГГ-ММ-ДД] [-csv файл] [-by day|month] [-yes]"

func runStats(in io.Reader, out, errOut io.Writer, isTTY, yes bool, src statsSource, wr statsWriter, containers []core.Container, sub string, f statsFlags) int {
	switch sub {
	case "status":
		return runStatsStatus(out, errOut, src)
	case "install":
		return runStatsInstall(in, out, errOut, isTTY, yes, src, wr)
	case "uninstall":
		return runStatsUninstall(in, out, errOut, isTTY, yes, src, wr)
	case "", "show":
		return runStatsShow(out, errOut, src, containers, f)
	}
	fmt.Fprintf(errOut, "stats: неизвестное действие %q (%s)\n", sub, statsUsage)
	return 1
}

func collectorText(st core.CollectorStatus) string {
	switch st.State {
	case core.CollectorInstalled:
		return "установлен, таймер работает (снимок раз в 5 минут)"
	case core.CollectorNotInstalled:
		return "не установлен (установить: amnezia-admin stats install)"
	case core.CollectorPartial:
		return "установлен не полностью или другой версии: " + strings.Join(st.Detail, "; ") +
			" (переустановить: amnezia-admin stats install)"
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

func runStatsStatus(out, errOut io.Writer, src statsSource) int {
	st := src.StatsStatus()
	fmt.Fprintln(out, "Сборщик статистики: "+collectorText(st))
	if st.Full != "" {
		fmt.Fprintln(out, cWarn("Сборщик остановлен: достигнут предел объёма 100 МБ ("+st.Full+"). Новые снимки не пишутся."))
	}
	fmt.Fprintln(out, "Данные: "+core.StatsDir)
	l, err := src.ReadTraffic()
	switch {
	case err != nil:
		fmt.Fprintln(out, "Накопленные данные прочитать не удалось: "+err.Error())
	case l.Empty():
		fmt.Fprintln(out, "Накопленных данных нет.")
	default:
		statsDataNotes(out, l)
	}
	if st.State == core.CollectorUnknown {
		return 1
	}
	return 0
}

func statsDataNotes(out io.Writer, l *core.TrafficLog) {
	if days := l.CoveredDays(""); len(days) > 0 {
		fmt.Fprintf(out, "Учтены сутки (UTC): с %s по %s, всего %d.\n", dayText(days[0]), dayText(days[len(days)-1]), len(days))
	} else {
		fmt.Fprintln(out, "Учтённых интервалов пока нет: нужно не меньше двух снимков.")
	}
	if !l.LastSnapshot.IsZero() {
		fmt.Fprintln(out, "Последний снимок: "+l.LastSnapshot.UTC().Format("2006-01-02 15:04")+" UTC")
	}
	if l.Corrupt > 0 {
		fmt.Fprintln(out, cWarn(fmt.Sprintf("Пропущено повреждённых записей: %d — цифры могут быть неполными.", l.Corrupt)))
	}
	if l.Failed > 0 {
		fmt.Fprintln(out, cWarn(fmt.Sprintf("Снимков, в которых сервер не отдал счётчики: %d.", l.Failed)))
	}
	if l.Torn {
		fmt.Fprintln(out, cDim("Последний снимок ещё дописывается или оборван — не учтён."))
	}
}

func dayText(d int64) string { return core.DayStart(d).Format("2006-01-02") }

func parseDay(s string) (int64, error) {
	t, err := time.ParseInLocation("2006-01-02", s, time.UTC)
	if err != nil {
		return 0, fmt.Errorf("дата %q: нужен формат ГГГГ-ММ-ДД", s)
	}
	return core.DayOf(t), nil
}

func statsRange(f statsFlags) (core.DayRange, string, error) {
	r := core.AllTime
	if f.from != "" {
		d, err := parseDay(f.from)
		if err != nil {
			return r, "", err
		}
		r.From = d
	}
	if f.to != "" {
		d, err := parseDay(f.to)
		if err != nil {
			return r, "", err
		}
		r.To = d
	}
	if r.From > r.To {
		return r, "", fmt.Errorf("начало периода позже конца")
	}
	switch {
	case f.from == "" && f.to == "":
		return r, "за всё время", nil
	case f.to == "":
		return r, "с " + f.from, nil
	case f.from == "":
		return r, "по " + f.to, nil
	}
	return r, f.from + " … " + f.to, nil
}

// statsRow — строка таблицы/CSV.
type statsRow struct {
	key   core.TrafficKey
	proto string
	name  string
}

// statsRows — все клиенты: из clientsTable каждого контейнера семейства WG
// и из данных сборщика (удалённые клиенты остаются в истории).
func statsRows(src statsSource, containers []core.Container, l *core.TrafficLog) ([]statsRow, []string) {
	var notes []string
	rows := map[core.TrafficKey]*statsRow{}
	protoOf := map[string]string{}
	for i := range containers {
		c := &containers[i]
		if _, err := core.WGFamilyOf(c); err != nil {
			continue
		}
		protoOf[c.Name] = c.Title()
		if !c.Managed() {
			continue
		}
		clients, err := src.LoadClients(c)
		if err != nil {
			notes = append(notes, fmt.Sprintf("Имена клиентов %s прочитать не удалось: %v — показаны ключи.", c.Title(), err))
			continue
		}
		for _, cl := range clients {
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
			rows[k] = &statsRow{key: k, proto: p, name: "(нет в списке клиентов) " + shortKey(k.PubKey)}
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

func shortKey(k string) string {
	if r := []rune(k); len(r) > 10 {
		return string(r[:10]) + "…"
	}
	return k
}

// statsCellText — текст одной цифры. Число — только у измеренной ячейки.
func statsCellText(c core.TrafficCell, v func(rx, tx int64) int64) string {
	switch c.State {
	case core.TrafficMeasured:
		rx, tx, _ := c.Measured()
		return core.HumanBytes(v(rx, tx))
	case core.TrafficNoData:
		return "нет данных"
	case core.TrafficNotInstalled:
		return "не собиралось"
	}
	return "?"
}

func statsSeenText(c core.TrafficCell) string {
	if _, _, ok := c.Measured(); !ok {
		return statsCellText(c, nil)
	}
	if c.LastHandshake.IsZero() {
		return "не подключался"
	}
	return c.LastHandshake.UTC().Format("2006-01-02 15:04")
}

func cellRx(rx, _ int64) int64     { return rx }
func cellTx(_, tx int64) int64     { return tx }
func cellTotal(rx, tx int64) int64 { return rx + tx }

// statsSort — измеренные по убыванию «всего», за ними — без данных (по
// имени). Порядок — тоже утверждение: «нет данных» внизу среди нулей
// выглядел бы нулём (25.09: нарушение было в сортировке, не в тексте).
func statsSort(rows []statsRow, cells map[core.TrafficKey]core.TrafficCell) {
	sort.SliceStable(rows, func(i, j int) bool {
		ri, ti, oki := cells[rows[i].key].Measured()
		rj, tj, okj := cells[rows[j].key].Measured()
		if oki != okj {
			return oki
		}
		if oki && ri+ti != rj+tj {
			return ri+ti > rj+tj
		}
		return false
	})
}

func runStatsShow(out, errOut io.Writer, src statsSource, containers []core.Container, f statsFlags) int {
	r, label, err := statsRange(f)
	if err != nil {
		fmt.Fprintln(errOut, "stats:", err)
		return 1
	}
	if f.by != "" && f.by != "day" && f.by != "month" {
		fmt.Fprintln(errOut, "stats: -by — day или month")
		return 1
	}
	if f.by != "" && f.csv == "" {
		fmt.Fprintln(errOut, "stats: -by действует только с -csv")
		return 1
	}
	st := src.StatsStatus()
	l, err := src.ReadTraffic()
	if err != nil {
		// Не знаем — не строим таблицу (иначе она была бы из «нет данных»).
		fmt.Fprintln(errOut, "Статистику прочитать не удалось:", err)
		return 1
	}
	fmt.Fprintln(out, "Сборщик статистики: "+collectorText(st))
	if st.Full != "" {
		fmt.Fprintln(out, cWarn("Сборщик остановлен: достигнут предел объёма 100 МБ ("+st.Full+"). Новые снимки не пишутся."))
	}
	if l.Empty() && st.State == core.CollectorNotInstalled {
		fmt.Fprintln(out, "Накопленной статистики нет: сборщик на сервере не установлен. Счётчики сервера обнуляются при перезапуске, "+
			"поэтому «за всё время» начнёт копиться только после установки: amnezia-admin stats install")
		return 0
	}
	rows, notes := statsRows(src, containers, l)
	if f.csv != "" {
		return writeStatsCSV(out, errOut, rows, l, st.State, r, f)
	}
	cells := map[core.TrafficKey]core.TrafficCell{}
	for _, row := range rows {
		cells[row.key] = l.Cell(row.key, r, st.State)
	}
	statsSort(rows, cells)
	fmt.Fprintln(out, "Период: "+label+" (сутки по UTC). Принято — от клиента, отправлено — клиенту (со стороны сервера).")
	fmt.Fprintln(out)
	fmt.Fprintln(out, cHead(pad("#", 4)+pad("Протокол", 14)+pad("Имя", 34)+pad("Принято", 13)+pad("Отправлено", 13)+pad("Всего", 13)+"Последнее подключение (UTC)"))
	fmt.Fprintln(out, cDim(strings.Repeat("─", 4+14+34+13*3+27)))
	for i, row := range rows {
		c := cells[row.key]
		fmt.Fprintln(out, pad(fmt.Sprint(i+1), 4)+pad(row.proto, 14)+pad(row.name, 34)+
			pad(statsCellText(c, cellRx), 13)+pad(statsCellText(c, cellTx), 13)+pad(statsCellText(c, cellTotal), 13)+statsSeenText(c))
	}
	if len(rows) == 0 {
		fmt.Fprintln(out, "Клиентов нет.")
	}
	fmt.Fprintln(out)
	statsDataNotes(out, l)
	for _, n := range notes {
		fmt.Fprintln(out, cWarn(n))
	}
	for _, c := range containers {
		if core.IsXRay(&c) {
			fmt.Fprintln(out, cDim("XRay: сервер не ведёт счётчиков трафика по клиентам — статистики по ним нет."))
			break
		}
	}
	return 0
}

// csvSafe — ячейка, которую Excel не примет за формулу (имя клиента
// задаёт человек).
func csvSafe(s string) string {
	if s != "" && strings.ContainsRune("=+-@\t\r", rune(s[0])) {
		return "'" + s
	}
	return s
}

func stateText(c core.TrafficCell) string {
	switch c.State {
	case core.TrafficMeasured:
		return "измерено"
	case core.TrafficNoData:
		return "нет данных"
	case core.TrafficNotInstalled:
		return "сборщик не установлен"
	}
	return "неизвестно"
}

const utf8BOM = "\xef\xbb\xbf"

type statsPeriod struct {
	label string
	r     core.DayRange
}

// statsPeriods — периоды выгрузки: один (за выбранный период) или сутки/
// месяцы между первыми и последними учтёнными сутками, обрезанные периодом.
func statsPeriods(l *core.TrafficLog, r core.DayRange, label, by string) []statsPeriod {
	if by == "" {
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
		if by == "day" {
			ps = append(ps, statsPeriod{dayText(d), core.DayRange{From: d, To: d}})
			continue
		}
		t := core.DayStart(d)
		m := t.Format("2006-01")
		if len(ps) > 0 && ps[len(ps)-1].label == m {
			ps[len(ps)-1].r.To = d
			continue
		}
		ps = append(ps, statsPeriod{m, core.DayRange{From: d, To: d}})
	}
	return ps
}

func writeStatsCSV(out, errOut io.Writer, rows []statsRow, l *core.TrafficLog, cs core.CollectorState, r core.DayRange, f statsFlags) int {
	_, label, _ := statsRange(f)
	periods := statsPeriods(l, r, label, f.by)
	var b strings.Builder
	b.WriteString(utf8BOM) // Excel: UTF-8
	w := csv.NewWriter(&b)
	w.Comma = ';'
	w.UseCRLF = true
	_ = w.Write([]string{"Период", "Протокол", "Клиент", "Публичный ключ", "Принято, байт", "Отправлено, байт", "Всего, байт", "Последнее подключение (UTC)", "Состояние"})
	for _, p := range periods {
		for _, row := range rows {
			c := l.Cell(row.key, p.r, cs)
			rec := []string{p.label, row.proto, csvSafe(row.name), row.key.PubKey, "", "", "", "", stateText(c)}
			if rx, tx, ok := c.Measured(); ok {
				rec[4], rec[5], rec[6] = fmt.Sprint(rx), fmt.Sprint(tx), fmt.Sprint(rx+tx)
				if !c.LastHandshake.IsZero() {
					rec[7] = c.LastHandshake.UTC().Format("2006-01-02 15:04")
				}
			}
			_ = w.Write(rec)
		}
	}
	w.Flush()
	if err := w.Error(); err != nil {
		fmt.Fprintln(errOut, "CSV:", err)
		return 1
	}
	if err := os.WriteFile(f.csv, []byte(b.String()), 0o600); err != nil {
		fmt.Fprintln(errOut, "CSV не записан:", err)
		return 1
	}
	abs, err := filepath.Abs(f.csv)
	if err != nil {
		abs = f.csv
	}
	fmt.Fprintf(out, "CSV записан: %s (строк: %d; пустые цифры — «нет данных», не ноль).\n", abs, len(periods)*len(rows))
	if len(periods) == 0 {
		fmt.Fprintln(out, cWarn("Учтённых суток нет — в файле только заголовок."))
	}
	return 0
}

// statsAsk — подтверждение записи на сервер: -yes; без терминала — отказ
// с кодом 2; иначе вопрос y/n (тот же договор, что у confirmOrExit).
func statsAsk(in io.Reader, out, errOut io.Writer, isTTY, yes bool, q string) (bool, int) {
	if yes {
		return true, 0
	}
	if !isTTY {
		fmt.Fprintln(errOut, "Действие не выполнено: без терминала требуется флаг -yes (для скриптов).")
		return false, 2
	}
	fmt.Fprint(out, q+" (y/n): ")
	a := strings.ToLower(strings.TrimSpace(readLine(in)))
	if a == "y" || a == "yes" {
		return true, 0
	}
	fmt.Fprintln(out, "Отменено.")
	return false, 2
}

func runStatsInstall(in io.Reader, out, errOut io.Writer, isTTY, yes bool, src statsSource, wr statsWriter) int {
	st := src.StatsStatus()
	if st.State == core.CollectorInstalled {
		fmt.Fprintln(out, "Сборщик уже установлен этой версии и работает — ничего не меняется.")
		return 0
	}
	fmt.Fprintln(out, "Сейчас: "+collectorText(st))
	fmt.Fprintln(out, "Будет записано на сервер (от root):")
	for _, f := range core.StatsInstallFiles() {
		fmt.Fprintf(out, "\n── %s (права %s) ──\n%s", f.Path, f.Mode, f.Content)
	}
	fmt.Fprintln(out, "\nи выполнено: systemctl daemon-reload; systemctl enable --now "+core.StatsUnit+".timer")
	fmt.Fprintln(out, "Сборщик раз в 5 минут читает счётчики wg/awg (только чтение) и дописывает снимок в "+core.StatsDir+
		"; объём — не более 100 МБ (старые снимки сворачиваются в суточные итоги). Снять: amnezia-admin stats uninstall")
	ok, code := statsAsk(in, out, errOut, isTTY, yes, "Установить сборщик статистики?")
	if !ok {
		return code
	}
	if err := wr.StatsInstall(); err != nil {
		fmt.Fprintln(errOut, "Ошибка:", err)
		return 1
	}
	after := src.StatsStatus()
	fmt.Fprintln(out, "Готово. Сборщик: "+collectorText(after))
	if after.State != core.CollectorInstalled {
		return 1
	}
	return 0
}

func runStatsUninstall(in io.Reader, out, errOut io.Writer, isTTY, yes bool, src statsSource, wr statsWriter) int {
	st := src.StatsStatus()
	if st.State == core.CollectorNotInstalled {
		fmt.Fprintln(out, "Сборщик не установлен — снимать нечего.")
		return 0
	}
	fmt.Fprintln(out, "Сейчас: "+collectorText(st))
	fmt.Fprintln(out, "Будет: systemctl disable --now "+core.StatsUnit+".timer; удалены "+
		core.StatsTimerPath+", "+core.StatsServicePath+", "+core.StatsScriptPath+".")
	fmt.Fprintln(out, "Накопленные данные ("+core.StatsDir+"/snapshots.log, daily.log) ОСТАЮТСЯ; удалить их вручную: rm -r "+core.StatsDir)
	ok, code := statsAsk(in, out, errOut, isTTY, yes, "Снять сборщик статистики?")
	if !ok {
		return code
	}
	if err := wr.StatsUninstall(); err != nil {
		fmt.Fprintln(errOut, "Ошибка:", err)
		return 1
	}
	after := src.StatsStatus()
	fmt.Fprintln(out, "Готово. Сборщик: "+collectorText(after))
	if after.State != core.CollectorNotInstalled {
		return 1
	}
	return 0
}
