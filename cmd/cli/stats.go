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
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"amnezia-admin/core"
	"amnezia-admin/internal/statsview"
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

// cliHints — как CLI называет действия в текстах общего пакета.
var cliHints = statsview.Hints{
	Install:   "amnezia-admin stats install",
	Uninstall: "amnezia-admin stats uninstall",
	Export:    "amnezia-admin stats -csv итоги.csv -by month",
}

// Правила — в internal/statsview (одна копия на CLI и GUI); здесь — печать.
func collectorText(st core.CollectorStatus) string { return statsview.CollectorText(st, cliHints) }
func fullText(why string) string                   { return statsview.FullText(why, cliHints) }
func dayText(d int64) string                       { return statsview.DayText(d) }
func csvSafe(s string) string                      { return statsview.CSVSafe(s) }

const utf8BOM = statsview.UTF8BOM

// printNotes — пометки общего пакета с цветом по их весу.
func printNotes(out io.Writer, ns []statsview.Note) {
	for _, n := range ns {
		switch n.Level {
		case statsview.Warn:
			fmt.Fprintln(out, cWarn(n.Text))
		case statsview.Dim:
			fmt.Fprintln(out, cDim(n.Text))
		default:
			fmt.Fprintln(out, n.Text)
		}
	}
}

func runStatsStatus(out, errOut io.Writer, src statsSource) int {
	st := src.StatsStatus()
	fmt.Fprintln(out, "Сборщик статистики: "+collectorText(st))
	if st.Full != "" {
		fmt.Fprintln(out, cWarn(fullText(st.Full)))
	}
	fmt.Fprintln(out, "Данные: "+core.StatsDir)
	l, err := src.ReadTraffic()
	switch {
	case err != nil:
		fmt.Fprintln(out, "Накопленные данные прочитать не удалось: "+err.Error())
	case l.Empty():
		fmt.Fprintln(out, "Накопленных данных нет.")
	default:
		printNotes(out, statsview.DataNotes(l, core.AllTime))
	}
	if st.State == core.CollectorUnknown || st.State == core.CollectorInstalled && st.Collect == core.CollectUnknown {
		return 1
	}
	return 0
}

func statsRange(f statsFlags) (core.DayRange, string, error) {
	return statsview.ParseRange(f.from, f.to)
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
		fmt.Fprintln(out, cWarn(fullText(st.Full)))
	}
	if l.Empty() && st.State == core.CollectorNotInstalled {
		fmt.Fprintln(out, "Накопленной статистики нет: сборщик на сервере не установлен. Счётчики сервера обнуляются при перезапуске, "+
			"поэтому «за всё время» начнёт копиться только после установки: amnezia-admin stats install")
		return 0
	}
	rows, notes := statsview.Rows(statsview.ReadClients(containers, src.LoadClients), l)
	if f.csv != "" {
		return writeStatsCSV(out, errOut, rows, l, st.State, r, f)
	}
	cells := map[core.TrafficKey]core.TrafficCell{}
	for _, row := range rows {
		cells[row.Key] = l.Cell(row.Key, r, st.State)
	}
	statsview.SortByTotal(rows, cells)
	fmt.Fprintln(out, "Период: "+label+" (сутки по UTC). Принято — от клиента, отправлено — клиенту (со стороны сервера).")
	fmt.Fprintln(out)
	fmt.Fprintln(out, cHead(pad("#", 4)+pad("Протокол", 14)+pad("Имя", 34)+pad("Принято", 13)+pad("Отправлено", 13)+pad("Всего", 13)+"Последнее подключение (UTC)"))
	fmt.Fprintln(out, cDim(strings.Repeat("─", 4+14+34+13*3+27)))
	for i, row := range rows {
		c := cells[row.Key]
		fmt.Fprintln(out, pad(fmt.Sprint(i+1), 4)+pad(row.Proto, 14)+pad(row.Name, 34)+
			pad(statsview.CellText(c, statsview.Rx), 13)+pad(statsview.CellText(c, statsview.Tx), 13)+pad(statsview.CellText(c, statsview.Total), 13)+statsview.SeenText(c))
	}
	if len(rows) == 0 {
		fmt.Fprintln(out, "Клиентов нет.")
	}
	fmt.Fprintln(out)
	printNotes(out, statsview.DataNotes(l, r))
	for _, n := range notes {
		fmt.Fprintln(out, cWarn(n))
	}
	if n := statsview.XRayNote(containers); n != "" {
		fmt.Fprintln(out, cDim(n))
	}
	return 0
}

func writeStatsCSV(out, errOut io.Writer, rows []statsview.Row, l *core.TrafficLog, cs core.CollectorState, r core.DayRange, f statsFlags) int {
	_, label, _ := statsRange(f)
	periods := statsview.Periods(l, r, label, f.by)
	data, n, err := statsview.CSV(rows, l, cs, periods)
	if err != nil {
		fmt.Fprintln(errOut, "CSV:", err)
		return 1
	}
	if err := os.WriteFile(f.csv, data, 0o600); err != nil {
		fmt.Fprintln(errOut, "CSV не записан:", err)
		return 1
	}
	abs, err := filepath.Abs(f.csv)
	if err != nil {
		abs = f.csv
	}
	fmt.Fprintf(out, "CSV записан: %s (строк: %d; пустые цифры — «нет данных», не ноль).\n", abs, n)
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
	fmt.Fprintln(out, statsview.InstallText(cliHints))
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
	fmt.Fprintln(out, statsview.UninstallText())
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
