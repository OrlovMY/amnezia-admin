// Package statsview — общие правила показа статистики трафика для CLI
// (`amnezia-admin stats`) и GUI (окно «Статистика»): тексты состояния
// сборщика, ячейки трёх состояний, порядок строк, пометки о полноте
// данных, периоды и формат CSV. Одна копия правил на обе программы
// (раунд 2 GUI-STATS): расхождение CLI и окна в том, что считать «нет
// данных», — ровно та ошибка, которую правило П-НЕЗНАНИЕ запрещает.
//
// ТРИ СОСТОЯНИЯ (CLAUDE.md, инцидент ложного нуля 25.09): цифра
// показывается только через CellText; «нет данных» никогда не «0 B».
// Порядок — тоже утверждение: Compare ставит «нет данных» ниже
// измеренного нуля, «не меньше» — между, в любую сторону сортировки.
package statsview

import (
	"encoding/csv"
	"fmt"
	"sort"
	"strings"
	"time"

	"amnezia-admin/core"
)

// Hints — как программа называет действие: команда CLI или кнопка GUI.
type Hints struct {
	Install   string // установить сборщик
	Uninstall string // снять сборщик
	Export    string // выгрузка итогов по месяцам
}

// CollectorText — состояние сборщика. «Работает» — только по исходу
// службы и свежему снимку (AU-1, С2), никогда по одному «таймер активен».
func CollectorText(st core.CollectorStatus, h Hints) string {
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
		return "не установлен (установить: " + h.Install + ")"
	case core.CollectorPartial:
		return "установлен не полностью или другой версии: " + strings.Join(st.Detail, "; ") +
			" (переустановить: " + h.Install + ")"
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

// FullText — что случилось и что делать, когда сборщик остановлен
// пределом объёма (ревью 1, Н3).
func FullText(why string, h Hints) string {
	head := "Сборщик остановлен: достигнут предел объёма 100 МБ (" + why + "). Новые снимки не пишутся."
	if why == "raw" {
		return head + " Причина — ротация журнала не удаётся (место на диске, awk). Проверьте сервер, затем удалите метку: rm " +
			core.StatsDir + "/FULL — сбор продолжится."
	}
	return head + " Сохраните выгрузку (" + h.Export + "), затем на сервере освободите место: " +
		"rm " + core.StatsDir + "/daily.log " + core.StatsDir + "/FULL — сбор начнётся заново (старые итоги будут потеряны)."
}

// InstallText — полный текст того, что будет записано на сервер при
// установке (показывается до вопроса).
func InstallText(h Hints) string {
	var b strings.Builder
	b.WriteString("Будет выполнено на сервере (от root): mkdir -p " + core.StatsDir +
		"; каждый файл пишется во временный <путь>.new, получает права и переносится на место (mv):\n")
	for _, f := range core.StatsInstallFiles() {
		fmt.Fprintf(&b, "\n── %s (права %s) ──\n%s", f.Path, f.Mode, f.Content)
	}
	b.WriteString("\nзатем: systemctl daemon-reload; systemctl enable --now " + core.StatsUnit + ".timer\n")
	b.WriteString("Сборщик раз в 5 минут читает счётчики wg/awg (только чтение) и дописывает снимок в " + core.StatsDir +
		"; объём — не более 100 МБ (старые снимки сворачиваются в суточные итоги). Снять: " + h.Uninstall)
	return b.String()
}

// UninstallText — что будет сделано при снятии и что останется.
func UninstallText() string {
	return "Будет: systemctl disable --now " + core.StatsUnit + ".timer; удалены " +
		core.StatsTimerPath + ", " + core.StatsServicePath + ", " + core.StatsScriptPath + ".\n" +
		"Накопленные данные (" + core.StatsDir + "/snapshots.log, daily.log) ОСТАЮТСЯ; удалить их вручную: rm -r " + core.StatsDir
}

// ---------- пометки ----------

// Level — вес пометки: обычная, предупреждение, второстепенная.
type Level int

const (
	Plain Level = iota
	Warn
	Dim
)

// Note — одна строка пометок.
type Note struct {
	Level Level
	Text  string
}

// DayText — сутки как ГГГГ-ММ-ДД (UTC).
func DayText(d int64) string { return core.DayStart(d).Format("2006-01-02") }

// DataNotes — полнота данных ЗА ВЫБРАННЫЙ ПЕРИОД и по каждому контейнеру
// (аудит AU-1, С3): учтённые сутки и сутки без снимков между ними — дыра
// в середине видна, а не прячется за «с … по …».
func DataNotes(l *core.TrafficLog, r core.DayRange) []Note {
	var out []Note
	add := func(lv Level, s string) { out = append(out, Note{lv, s}) }
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
		add(Plain, fmt.Sprintf("%s: учтены сутки (UTC) с %s по %s, всего %d.", c, DayText(lo), DayText(hi), len(days)))
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
					gaps = append(gaps, DayText(d))
				}
			}
		}
		if n > 0 {
			more := ""
			if n > len(gaps) {
				more = fmt.Sprintf(" и ещё %d", n-len(gaps))
			}
			add(Warn, fmt.Sprintf("  %s: нет снимков за %d сут.: %s%s — цифры за них неполные, если в это время был перезапуск.",
				c, n, strings.Join(gaps, ", "), more))
		}
	}
	if !any {
		add(Plain, "Учтённых интервалов за период нет: нужно не меньше двух снимков в нём.")
	}
	if n := l.PartialIn(r); n > 0 {
		add(Warn, fmt.Sprintf("Интервалов с перезапуском после перерыва в сборе: %d — трафик до перезапуска в них потерян; "+
			"такие цифры помечены «≥» (не меньше).", n))
	}
	if !l.LastSnapshot.IsZero() {
		add(Plain, "Последний снимок: "+l.LastSnapshot.UTC().Format("2006-01-02 15:04")+" UTC")
	}
	if l.Corrupt > 0 {
		add(Warn, fmt.Sprintf("Пропущено повреждённых записей: %d — цифры могут быть неполными.", l.Corrupt))
	}
	if l.Failed > 0 {
		add(Warn, fmt.Sprintf("Снимков, в которых сервер не отдал счётчики: %d.", l.Failed))
	}
	if l.Torn {
		add(Dim, "Последний снимок ещё дописывается или оборван — не учтён.")
	}
	// С1 ревью 1: отброшенный журнал — не молча (признак 4 CLAUDE.md).
	if l.RawStale {
		add(Warn, "Журнал снимков устарел (ротация на сервере была прервана) и не учтён: "+
			"цифры неполные — нет снимков после последней ротации. Сборщик исправит это при следующем запуске (до 5 минут).")
	}
	if l.Heuristic > 0 {
		add(Dim, fmt.Sprintf("Интервалов без признака перезапуска сервера/контейнера: %d (снимки старого формата). "+
			"В них перезапуск, после которого счётчик успел перерасти прежний, мог остаться незамеченным — цифры могут быть занижены.", l.Heuristic))
	}
	return out
}

// XRayNote — пометка, если среди протоколов есть XRay ("" — нет).
func XRayNote(containers []core.Container) string {
	for i := range containers {
		if core.IsXRay(&containers[i]) {
			return "XRay: сервер не ведёт счётчиков трафика по клиентам — статистики по ним нет."
		}
	}
	return ""
}

// ---------- строки ----------

// Row — клиент: ключ в данных сборщика, протокол, имя.
type Row struct {
	Key   core.TrafficKey
	Proto string
	Name  string
}

// ContainerClients — клиенты контейнера семейства WG, как их прочитали.
// Read=false — список не читался (контейнер не под управлением).
type ContainerClients struct {
	C       core.Container
	Clients []core.ClientEntry
	Err     error
	Read    bool
}

// ReadClients — по контейнерам семейства WG прочитать клиентов функцией
// load (только у контейнеров под управлением).
func ReadClients(containers []core.Container, load func(*core.Container) ([]core.ClientEntry, error)) []ContainerClients {
	var out []ContainerClients
	for i := range containers {
		c := containers[i]
		if _, err := core.WGFamilyOf(&c); err != nil {
			continue
		}
		cc := ContainerClients{C: c}
		if c.Managed() {
			cc.Read = true
			cc.Clients, cc.Err = load(&c)
		}
		out = append(out, cc)
	}
	return out
}

// Rows — все клиенты: из clientsTable каждого контейнера и из данных
// сборщика (удалённые клиенты остаются в истории). Второй результат —
// пометки-предупреждения о непрочитанных списках.
func Rows(cs []ContainerClients, l *core.TrafficLog) ([]Row, []string) {
	var notes []string
	rows := map[core.TrafficKey]*Row{}
	protoOf := map[string]string{}
	for _, cc := range cs {
		c := cc.C
		protoOf[c.Name] = c.Title()
		if !cc.Read {
			continue
		}
		if cc.Err != nil {
			notes = append(notes, fmt.Sprintf("Имена клиентов %s прочитать не удалось: %v — показаны ключи.", c.Title(), cc.Err))
			continue
		}
		for _, cl := range cc.Clients {
			k := core.TrafficKey{Container: c.Name, PubKey: cl.ClientID}
			rows[k] = &Row{Key: k, Proto: c.Title(), Name: cl.Name()}
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
			rows[k] = &Row{Key: k, Proto: p, Name: "(нет в списке клиентов) " + ShortKey(k.PubKey)}
		}
	}
	out := make([]Row, 0, len(rows))
	for _, r := range rows {
		out = append(out, *r)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Proto != out[j].Proto {
			return out[i].Proto < out[j].Proto
		}
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].Key.PubKey < out[j].Key.PubKey
	})
	return out, notes
}

// ShortKey — начало ключа для строки удалённого клиента.
func ShortKey(k string) string {
	if r := []rune(k); len(r) > 10 {
		return string(r[:10]) + "…"
	}
	return k
}

// ---------- ячейки ----------

// CellNums — цифры ячейки: измеренные (rank 0) или нижняя граница при
// частичной потере (rank 1); иначе rank 2 и цифр нет.
func CellNums(c core.TrafficCell) (rx, tx int64, rank int) {
	if rx, tx, ok := c.Measured(); ok {
		return rx, tx, 0
	}
	if rx, tx, ok := c.LowerBound(); ok {
		return rx, tx, 1
	}
	return 0, 0, 2
}

// CellText — текст одной цифры. Число — только у измеренной ячейки; у
// частично потерянной — «≥ число» (AU-1, С3); иначе слово, не «0 B».
func CellText(c core.TrafficCell, v func(rx, tx int64) int64) string {
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

// SeenText — последнее подключение за период.
func SeenText(c core.TrafficCell) string {
	rx, tx, rank := CellNums(c)
	if rank == 2 {
		return CellText(c, nil)
	}
	if c.LastHandshake.IsZero() {
		// «не подключался» — только когда это измерено: трафика ровно 0 и
		// ничего не потеряно. Трафик есть или часть потеряна — время
		// рукопожатия просто неизвестно (признак 2: ноль не ответ).
		if rank == 0 && rx+tx == 0 {
			return "не подключался"
		}
		return "время неизвестно"
	}
	return c.LastHandshake.UTC().Format("2006-01-02 15:04")
}

func Rx(rx, _ int64) int64     { return rx }
func Tx(_, tx int64) int64     { return tx }
func Total(rx, tx int64) int64 { return rx + tx }

// StateText — исход ячейки словами (столбец «Состояние» CSV).
func StateText(c core.TrafficCell) string {
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

// Col — столбец с цифрами, по которому сортируют.
type Col int

const (
	ColRx Col = iota
	ColTx
	ColTotal
	ColSeen
)

// Compare — порядок двух ячеек по столбцу: <0 — a выше, >0 — b выше,
// 0 — равны. desc меняет направление ВНУТРИ исхода, но не порядок
// исходов: измеренные, затем «не меньше», затем без данных — всегда
// (25.09: нарушение было в сортировке, не в тексте).
func Compare(a, b core.TrafficCell, col Col, desc bool) int {
	ra, ta, ka := CellNums(a)
	rb, tb, kb := CellNums(b)
	if ka != kb {
		if ka < kb {
			return -1
		}
		return 1
	}
	if ka == 2 {
		return 0
	}
	var x, y int64
	switch col {
	case ColRx:
		x, y = ra, rb
	case ColTx:
		x, y = ta, tb
	case ColTotal:
		x, y = ra+ta, rb+tb
	case ColSeen:
		// Внутри исхода — тоже закреплённый порядок, не зависящий от
		// направления: известное время, затем «время неизвестно» (трафик
		// был), затем «не подключался» (ревью GUI-STATS-2, N1).
		if sa, sb := seenRank(a), seenRank(b); sa != sb {
			if sa < sb {
				return -1
			}
			return 1
		}
		x, y = a.LastHandshake.Unix(), b.LastHandshake.Unix()
	}
	c := 0
	switch {
	case x < y:
		c = -1
	case x > y:
		c = 1
	}
	if desc {
		c = -c
	}
	return c
}

// seenRank — исход столбца «Последнее подключение» у ячейки с цифрами:
// 0 — время известно, 1 — «время неизвестно», 2 — «не подключался».
// Три состояния, как у SeenText: незнание не сливается с «никогда».
func seenRank(c core.TrafficCell) int {
	if !c.LastHandshake.IsZero() {
		return 0
	}
	if rx, tx, rank := CellNums(c); rank == 0 && rx+tx == 0 {
		return 2
	}
	return 1
}

// SortByTotal — порядок таблицы CLI: по убыванию «всего», без данных — в
// конце; равные сохраняют прежний порядок (по имени).
func SortByTotal(rows []Row, cells map[core.TrafficKey]core.TrafficCell) {
	sort.SliceStable(rows, func(i, j int) bool {
		return Compare(cells[rows[i].Key], cells[rows[j].Key], ColTotal, true) < 0
	})
}

// ---------- период ----------

// ParseRange — период по датам ГГГГ-ММ-ДД (пустая — без границы) и его
// подпись.
func ParseRange(from, to string) (core.DayRange, string, error) {
	r := core.AllTime
	parse := func(s string) (int64, error) {
		t, err := time.ParseInLocation("2006-01-02", s, time.UTC)
		if err != nil {
			return 0, fmt.Errorf("дата %q: нужен формат ГГГГ-ММ-ДД", s)
		}
		return core.DayOf(t), nil
	}
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

// Period — период выгрузки/группы.
type Period struct {
	Name string
	R    core.DayRange
}

// Periods — один период (by == "") или сутки ("day") / месяцы ("month")
// между первыми и последними учтёнными сутками, обрезанные периодом.
func Periods(l *core.TrafficLog, r core.DayRange, label, by string) []Period {
	if by == "" {
		return []Period{{label, r}}
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
	var ps []Period
	for d := lo; d <= hi; d++ {
		if by == "day" {
			ps = append(ps, Period{DayText(d), core.DayRange{From: d, To: d}})
			continue
		}
		m := core.DayStart(d).Format("2006-01")
		if len(ps) > 0 && ps[len(ps)-1].Name == m {
			ps[len(ps)-1].R.To = d
			continue
		}
		ps = append(ps, Period{m, core.DayRange{From: d, To: d}})
	}
	return ps
}

// ---------- CSV ----------

// UTF8BOM — Excel читает UTF-8 только с ним.
const UTF8BOM = "\xef\xbb\xbf"

// CSVSafe — ячейка, которую Excel не примет за формулу. Закрытый список
// (ревью 1, Н1): без префикса остаётся только ячейка, начинающаяся с
// латинской или русской буквы или цифры; всё прочее получает «'».
func CSVSafe(s string) string {
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

// CSV — содержимое файла выгрузки и число строк данных. Пустые цифры —
// «нет данных», не ноль: столбец «Состояние» говорит это словами.
func CSV(rows []Row, l *core.TrafficLog, cs core.CollectorState, periods []Period) ([]byte, int, error) {
	var b strings.Builder
	b.WriteString(UTF8BOM)
	w := csv.NewWriter(&b)
	w.Comma = ';'
	w.UseCRLF = true
	_ = w.Write([]string{"Период", "Протокол", "Клиент", "Публичный ключ", "Принято, байт", "Отправлено, байт", "Всего, байт", "Последнее подключение (UTC)", "Состояние"})
	n := 0
	for _, p := range periods {
		for _, row := range rows {
			c := l.Cell(row.Key, p.R, cs)
			rec := []string{p.Name, row.Proto, row.Name, row.Key.PubKey, "", "", "", "", StateText(c)}
			if rx, tx, rank := CellNums(c); rank < 2 {
				rec[4], rec[5], rec[6] = fmt.Sprint(rx), fmt.Sprint(tx), fmt.Sprint(rx+tx)
				// Время, «время неизвестно» или «не подключался» — словами:
				// пустая ячейка сливала бы незнание с «никогда» (N1).
				rec[7] = SeenText(c)
			}
			for i := range rec {
				rec[i] = CSVSafe(rec[i]) // все ячейки, не только имя
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
