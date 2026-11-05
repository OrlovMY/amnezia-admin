package main

// Раунд 3 — аудит AU-1: С2 (идёт ли сбор), С3 (частичная потеря, дыры по
// периоду и контейнеру).

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"amnezia-admin/core"
)

// TestStatusNeverWorkingByTimerOnly — С2: «работает» печатается только
// при CollectWorking; таймер активен, служба падает — «НЕ работает».
func TestStatusNeverWorkingByTimerOnly(t *testing.T) {
	cases := []struct {
		st   core.CollectorStatus
		want string
		bad  string
	}{
		{core.CollectorStatus{State: core.CollectorInstalled, Collect: core.CollectWorking, SnapshotAge: 3 * time.Minute}, "сбор работает (последний снимок 3 мин назад", "НЕ работает"},
		{core.CollectorStatus{State: core.CollectorInstalled, Collect: core.CollectStopped, CollectWhy: "последний запуск сборщика завершился с ошибкой (Result=exit-code)"}, "сбор НЕ работает: последний запуск", "сбор работает"},
		{core.CollectorStatus{State: core.CollectorInstalled, Collect: core.CollectUnknown, CollectWhy: "состояние службы прочитать не удалось"}, "идёт ли сбор — неизвестно", "сбор работает"},
	}
	for _, c := range cases {
		got := collectorText(c.st)
		if !strings.Contains(got, c.want) || strings.Contains(got, c.bad) {
			t.Errorf("%q: ждали %q без %q", got, c.want, c.bad)
		}
	}
	f := sampleStats()
	f.status = core.CollectorStatus{State: core.CollectorInstalled, Collect: core.CollectUnknown, CollectWhy: "x"}
	var out, errb bytes.Buffer
	if code := runStats(strings.NewReader(""), &out, &errb, false, false, f, f, awgOnly, "status", statsFlags{}); code != 1 {
		t.Errorf("сбор неизвестен — код %d, ждали 1", code)
	}
}

// TestStatsPartialShown — С3: частично потерянная ячейка — «≥», не
// измеренная цифра; стоит после измеренных, до «нет данных»; дыра в
// сутках видна по контейнеру и в пределах периода.
func TestStatsPartialShown(t *testing.T) {
	d := tDay * 86400
	raw := "H v1 0\n" +
		tBlk(d, "amnezia-awg", "KA= 900 900 0", "KB= 1 1 0") +
		tBlk(d+300, "amnezia-awg", "KA= 901 901 0", "KB= 2 2 0") +
		tBlk(d+3*86400, "amnezia-awg", "KA= 5000 5000 0", "KB= 1 1 0")
	f := sampleStats()
	f.log = core.ParseTrafficLog("", false, raw, true)
	out, code := showLines(t, f, statsFlags{})
	if code != 0 {
		t.Fatal(out)
	}
	// KA вырос (5000 > 901) без признака — разница, не сброс; KB
	// уменьшился после дыры в 3 суток — сброс в дыре: «не меньше».
	if r := rowOf(t, out, "Bob"); !strings.Contains(r, "≥ ") {
		t.Errorf("Bob — частичная потеря без «≥»: %s", r)
	}
	if r := rowOf(t, out, "Alice"); strings.Contains(r, "≥") {
		t.Errorf("Alice измерена полностью: %s", r)
	}
	if strings.Index(out, "Alice") > strings.Index(out, "Bob") || strings.Index(out, "Bob") > strings.Index(out, "Abe ") {
		t.Errorf("порядок: измеренные, «не меньше», без данных:\n%s", out)
	}
	for _, w := range []string{"amnezia-awg: учтены сутки (UTC) с 2024-10-04 по 2024-10-07, всего 2", "нет снимков за 2 сут.: 2024-10-05, 2024-10-06", "помечены «≥»"} {
		if !strings.Contains(out, w) {
			t.Errorf("нет %q:\n%s", w, out)
		}
	}
	// Период без дыры: про дыру не говорится.
	out, _ = showLines(t, f, statsFlags{from: "2024-10-07"})
	if strings.Contains(out, "нет снимков за") || !strings.Contains(out, "с 2024-10-07 по 2024-10-07") {
		t.Errorf("учтённые сутки не по периоду:\n%s", out)
	}
}
