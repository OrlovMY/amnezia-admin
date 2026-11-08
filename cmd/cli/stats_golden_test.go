package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"amnezia-admin/core"
)

// Эталон вывода `stats` (раунд 2 GUI-STATS): правила вынесены в
// internal/statsview, и вывод CLI не должен измениться ни на байт.
// Эталоны сняты С РЕВИЗИИ ДО ПЕРЕНОСА (-update-stats-golden на 24ce66c) —
// с цветами, чтобы уровень каждой строки (предупреждение/серое) тоже был
// зафиксирован.

var updateStatsGolden = flag.Bool("update-stats-golden", false, "переснять эталоны stats")

// goldenLog — данные со всеми пометками: два контейнера, дыра в сутках,
// неполный интервал, повреждённая запись, эвристика, удалённый клиент,
// оборванный снимок, устаревший журнал.
func goldenLog() *core.TrafficLog {
	hs := core.DayStart(tDay).Add(13*time.Hour + 7*time.Minute).Unix()
	daily := fmt.Sprintf("D 1 %d amnezia-awg KA= 3000 5000 %d 5\n", tDay, hs) +
		fmt.Sprintf("D 1 %d amnezia-awg KB= 0 0 0 5\n", tDay) +
		fmt.Sprintf("D 1 %d amnezia-awg KC= 100000 1 0 5 1\n", tDay+3) +
		fmt.Sprintf("D 1 %d amnezia-awg KZ= 7 9 0 5\n", tDay+3) +
		fmt.Sprintf("D 1 %d amnezia-wireguard WA= 1500000 2500000000 %d 3\n", tDay+1, hs+86400) +
		fmt.Sprintf("N 1 %d amnezia-awg 5 2\n", tDay) +
		fmt.Sprintf("N 1 %d amnezia-awg 5\n", tDay+3) +
		fmt.Sprintf("N 1 %d amnezia-wireguard 3\n", tDay+1) +
		"мусор\n"
	raw := "H v1 0\n" + tBlk(tDay*86400, "amnezia-awg", "KA= 1 1 0") + "\nS 5 amnezia-awg 1\nP KA= 1"
	return core.ParseTrafficLog(daily, true, raw, true)
}

var goldenConts = []core.Container{
	{Name: "amnezia-awg", Dir: "/opt/amnezia/awg", Proto: "awg", Support: core.SupportYes},
	{Name: "amnezia-wireguard", Dir: "/opt/amnezia/wireguard", Proto: "wireguard", Support: core.SupportYes},
	{Name: core.XRayContainer, Dir: "/opt/amnezia/xray", Proto: "xray", Support: core.SupportYes},
}

type goldenSrc struct {
	*fakeStats
	clientsErr error
}

func (g goldenSrc) LoadClients(c *core.Container) ([]core.ClientEntry, error) {
	if c.Name == "amnezia-wireguard" && g.clientsErr != nil {
		return nil, g.clientsErr
	}
	return g.fakeStats.LoadClients(c)
}

func goldenFake(st core.CollectorStatus) *fakeStats {
	return &fakeStats{status: st, after: st, log: goldenLog(), clients: map[string][]core.ClientEntry{
		"amnezia-awg":       {client("KD=", "Abe"), client("KB=", "Bob"), client("KA=", "=Alice"), client("KC=", "Carl")},
		"amnezia-wireguard": {client("WA=", "Роутер")},
	}}
}

func TestStatsGoldenOutput(t *testing.T) {
	old := colorsEnabled
	colorsEnabled = true
	t.Cleanup(func() { colorsEnabled = old })

	next := time.Date(2026, 11, 6, 14, 35, 0, 0, time.UTC)
	states := map[string]core.CollectorStatus{
		"working":      {State: core.CollectorInstalled, Collect: core.CollectWorking, SnapshotAge: 4 * time.Minute},
		"pending":      {State: core.CollectorInstalled, Collect: core.CollectPending, NextRun: next},
		"pending0":     {State: core.CollectorInstalled, Collect: core.CollectPending},
		"stopped":      {State: core.CollectorInstalled, Collect: core.CollectStopped, CollectWhy: "служба завершилась с ошибкой"},
		"collectunk":   {State: core.CollectorInstalled, Collect: core.CollectUnknown, CollectWhy: "systemctl не ответил"},
		"notinstalled": {State: core.CollectorNotInstalled},
		"partial":      {State: core.CollectorPartial, Detail: []string{"нет таймера", "скрипт другой версии"}},
		"unknown":      {State: core.CollectorUnknown, Err: errors.New("ssh: обрыв")},
		"unknown0":     {},
		"fullraw":      {State: core.CollectorInstalled, Collect: core.CollectStopped, CollectWhy: "FULL", Full: "raw"},
		"fulldaily":    {State: core.CollectorInstalled, Collect: core.CollectStopped, CollectWhy: "FULL", Full: "daily"},
	}
	var b strings.Builder
	run := func(name string, f *fakeStats, src statsSource, sub string, fl statsFlags) {
		var out, errb bytes.Buffer
		code := runStats(strings.NewReader(""), &out, &errb, false, false, src, f, goldenConts, sub, fl)
		fmt.Fprintf(&b, "##### %s (код %d)\n--- out\n%s--- err\n%s", name, code, out.String(), errb.String())
	}
	for _, k := range []string{"working", "pending", "pending0", "stopped", "collectunk", "notinstalled", "partial", "unknown", "unknown0", "fullraw", "fulldaily"} {
		f := goldenFake(states[k])
		run("status "+k, f, f, "status", statsFlags{})
		run("show "+k, f, goldenSrc{f, errors.New("нет доступа")}, "", statsFlags{})
	}
	f := goldenFake(states["working"])
	run("show from", f, f, "", statsFlags{from: dayText(tDay + 1)})
	run("show to", f, f, "", statsFlags{to: dayText(tDay)})
	run("show range", f, f, "", statsFlags{from: dayText(tDay), to: dayText(tDay + 1)})
	run("show пусто", f, f, "", statsFlags{from: "2030-01-01"})
	run("show bad", f, f, "", statsFlags{from: "2030-13-01"})
	run("install", f, f, "install", statsFlags{})
	run("uninstall", f, f, "uninstall", statsFlags{})
	fn := goldenFake(states["notinstalled"])
	fn.log = core.ParseTrafficLog("", false, "", false)
	run("show notinstalled empty", fn, fn, "", statsFlags{})
	run("install notinstalled", fn, fn, "install", statsFlags{})
	run("uninstall notinstalled", fn, fn, "uninstall", statsFlags{})
	// Ревью GUI-STATS-1, L3: запись после -yes и после ответа «y» в
	// терминале — итог по перечитанному состоянию: успех, не то состояние,
	// ошибка записи; и ошибки флага -by.
	write := func(name string, st, after core.CollectorStatus, tty bool, in string, sub string, iErr, rErr error) {
		w := goldenFake(st)
		w.after, w.installErr, w.removeErr = after, iErr, rErr
		var out, errb bytes.Buffer
		code := runStats(strings.NewReader(in), &out, &errb, tty, !tty, w, w, goldenConts, sub, statsFlags{})
		fmt.Fprintf(&b, "##### %s (код %d, установок %d, снятий %d)\n--- out\n%s--- err\n%s", name, code, w.installed, w.removed, out.String(), errb.String())
	}
	notI, inst := states["notinstalled"], states["pending"]
	write("install -yes ok", notI, inst, false, "", "install", nil, nil)
	write("install -yes не то состояние", notI, states["partial"], false, "", "install", nil, nil)
	write("install -yes ошибка", notI, states["unknown"], false, "", "install", errors.New("scp: обрыв"), nil)
	write("install tty y", notI, inst, true, "y\n", "install", nil, nil)
	write("uninstall -yes ok", inst, notI, false, "", "uninstall", nil, nil)
	write("uninstall -yes не то состояние", inst, states["partial"], false, "", "uninstall", nil, nil)
	write("uninstall -yes ошибка", inst, inst, false, "", "uninstall", nil, errors.New("systemctl: отказ"))
	write("uninstall tty y", inst, notI, true, "yes\n", "uninstall", nil, nil)
	run("show -by без -csv", f, f, "", statsFlags{by: "day"})
	run("show -by неверное", f, f, "", statsFlags{csv: "x.csv", by: "week"})
	// Свежий журнал: последний снимок, сбой счётчиков, оборванный хвост.
	fr := goldenFake(states["working"])
	fr.log = core.ParseTrafficLog("", false, "H v1 0\n"+tBlk(tDay*86400, "amnezia-awg", "KA= 100 200 0")+
		tBlk(tDay*86400+300, "amnezia-awg", "KA= 3100 5200 0")+"F 600 amnezia-awg x\n"+"S 900 amnezia-awg 1\nP KA= 1 1 0\n", true)
	run("show raw", fr, fr, "", statsFlags{})
	fe := goldenFake(states["working"])
	fe.readErr = errors.New("cat: нет файла")
	run("show readerr", fe, fe, "", statsFlags{})
	run("status readerr", fe, fe, "status", statsFlags{})

	dir := t.TempDir()
	for _, by := range []string{"", "day", "month"} {
		p := filepath.Join(dir, "x"+by+".csv")
		var out, errb bytes.Buffer
		runStats(strings.NewReader(""), &out, &errb, false, false, f, f, goldenConts, "", statsFlags{csv: p, by: by})
		data, _ := os.ReadFile(p)
		fmt.Fprintf(&b, "##### csv by=%q\n%s\n--- out\n%s", by, data, strings.ReplaceAll(strings.ReplaceAll(out.String(), dir+string(os.PathSeparator), "<DIR>/"), dir, "<DIR>"))
	}

	got := b.String()
	gp := filepath.Join("testdata", "stats_golden.txt")
	if *updateStatsGolden {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(gp, []byte(got), 0o600); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(gp)
	if err != nil {
		t.Fatalf("эталона нет: %v", err)
	}
	if got != string(want) {
		gl, wl := strings.Split(got, "\n"), strings.Split(string(want), "\n")
		for i := 0; i < len(gl) || i < len(wl); i++ {
			var g, w string
			if i < len(gl) {
				g = gl[i]
			}
			if i < len(wl) {
				w = wl[i]
			}
			if g != w {
				t.Fatalf("вывод stats изменился, строка %d:\n было: %q\nстало: %q", i+1, w, g)
			}
		}
	}
	if !strings.Contains(got, "нет данных") || !strings.Contains(got, "≥ ") || !strings.Contains(got, "\x1b[") {
		t.Error("эталон не покрывает три состояния или цвета — проверка мало значит")
	}
}
