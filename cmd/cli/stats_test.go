package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"amnezia-admin/core"
)

const tDay = int64(20000)

func tBlk(ts int64, c string, peers ...string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "\nS %d %s %d\n", ts, c, len(peers))
	for _, p := range peers {
		b.WriteString("P " + p + "\n")
	}
	fmt.Fprintf(&b, "E %d %s %d\n", ts, c, len(peers))
	return b.String()
}

type fakeStats struct {
	status    core.CollectorStatus
	after     core.CollectorStatus
	log       *core.TrafficLog
	readErr   error
	clients   map[string][]core.ClientEntry
	installed int
	removed   int
	// installErr/removeErr — ошибка записи (запись при этом считается
	// состоявшейся: перечитывается after).
	installErr error
	removeErr  error
}

func (f *fakeStats) StatsStatus() core.CollectorStatus {
	if f.installed+f.removed > 0 {
		return f.after
	}
	return f.status
}
func (f *fakeStats) ReadTraffic() (*core.TrafficLog, error) { return f.log, f.readErr }
func (f *fakeStats) LoadClients(c *core.Container) ([]core.ClientEntry, error) {
	return f.clients[c.Name], nil
}
func (f *fakeStats) StatsInstall() error   { f.installed++; return f.installErr }
func (f *fakeStats) StatsUninstall() error { f.removed++; return f.removeErr }

func client(id, name string) core.ClientEntry {
	return core.ClientEntry{ClientID: id, UserData: map[string]any{"clientName": name}}
}

var awgOnly = []core.Container{{Name: "amnezia-awg", Dir: "/opt/amnezia/awg", Proto: "awg", Support: core.SupportYes}}

// Клиенты: Alice — трафик, Bob — измеренный ноль, Abe — нет в снимках.
func sampleStats() *fakeStats {
	raw := "H v1 0\n" +
		tBlk(tDay*86400, "amnezia-awg", "KA= 100 200 0", "KB= 5 5 0") +
		tBlk(tDay*86400+300, "amnezia-awg", "KA= 3100 5200 1728000250", "KB= 5 5 0")
	return &fakeStats{
		status: core.CollectorStatus{State: core.CollectorInstalled},
		log:    core.ParseTrafficLog("", false, raw, true),
		clients: map[string][]core.ClientEntry{"amnezia-awg": {
			client("KC=", "Abe"), client("KB=", "Bob"), client("KA=", "Alice"),
		}},
	}
}

func showLines(t *testing.T, f *fakeStats, fl statsFlags) (string, int) {
	t.Helper()
	var out, errb bytes.Buffer
	code := runStats(strings.NewReader(""), &out, &errb, false, false, f, f, awgOnly, "", fl)
	return out.String() + errb.String(), code
}

func rowOf(t *testing.T, out, name string) string {
	t.Helper()
	for _, l := range strings.Split(out, "\n") {
		if strings.Contains(l, name) {
			return l
		}
	}
	t.Fatalf("строки %s нет:\n%s", name, out)
	return ""
}

// TestStatsShowThreeStates — различение: измерено / измеренный ноль / нет
// данных; и порядок: «нет данных» после измеренного нуля.
func TestStatsShowThreeStates(t *testing.T) {
	out, code := showLines(t, sampleStats(), statsFlags{})
	if code != 0 {
		t.Fatalf("код %d\n%s", code, out)
	}
	if r := rowOf(t, out, "Alice"); !strings.Contains(r, "3.0 KB") || !strings.Contains(r, "8.0 KB") {
		t.Errorf("Alice: %s", r)
	}
	if r := rowOf(t, out, "Bob"); !strings.Contains(r, "0 B") || !strings.Contains(r, "не подключался") {
		t.Errorf("Bob — измеренный ноль: %s", r)
	}
	if r := rowOf(t, out, "Abe"); strings.Contains(r, "0 B") || !strings.Contains(r, "нет данных") {
		t.Errorf("Abe — нет данных, не ноль: %s", r)
	}
	if strings.Index(out, "Bob") > strings.Index(out, "Abe ") || strings.Index(out, "Alice") > strings.Index(out, "Bob") {
		t.Errorf("порядок: измеренные по убыванию, затем без данных:\n%s", out)
	}
	// Период без снимков — у всех «нет данных», ни одного «0 B».
	out, _ = showLines(t, sampleStats(), statsFlags{from: "2030-01-01"})
	if strings.Contains(out, "0 B") || strings.Count(out, "нет данных") < 9 {
		t.Errorf("период без снимков:\n%s", out)
	}
}

func TestStatsShowNotInstalledAndFailure(t *testing.T) {
	f := &fakeStats{status: core.CollectorStatus{State: core.CollectorNotInstalled}, log: core.ParseTrafficLog("", false, "", false)}
	out, code := showLines(t, f, statsFlags{})
	if code != 0 || !strings.Contains(out, "сборщик на сервере не установлен") || strings.Contains(out, "0 B") || strings.Contains(out, "нет данных") {
		t.Errorf("не установлен (%d):\n%s", code, out)
	}
	// Установлен, данных ещё нет — «нет данных», не «не установлен».
	f = &fakeStats{status: core.CollectorStatus{State: core.CollectorInstalled}, log: core.ParseTrafficLog("", false, "", false),
		clients: map[string][]core.ClientEntry{"amnezia-awg": {client("KA=", "Alice")}}}
	out, _ = showLines(t, f, statsFlags{})
	if r := rowOf(t, out, "Alice"); !strings.Contains(r, "нет данных") {
		t.Errorf("установлен без данных: %s", r)
	}
	f = &fakeStats{status: core.CollectorStatus{State: core.CollectorInstalled}, readErr: errors.New("ssh оборвался")}
	out, code = showLines(t, f, statsFlags{})
	if code != 1 || strings.Contains(out, "Alice") || strings.Contains(out, "нет данных") || !strings.Contains(out, "прочитать не удалось") {
		t.Errorf("отказ чтения (%d):\n%s", code, out)
	}
}

func TestStatsCSV(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "all.csv")
	f := sampleStats()
	f.clients["amnezia-awg"] = append(f.clients["amnezia-awg"], client("KD=", "=HYPERLINK(1)"))
	out, code := showLines(t, f, statsFlags{csv: p})
	if code != 0 {
		t.Fatalf("%d %s", code, out)
	}
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	if !strings.HasPrefix(s, utf8BOM) {
		t.Error("нет BOM для Excel")
	}
	for _, want := range []string{
		"за всё время;awg;Alice;KA=;3000;5000;8000;",
		"за всё время;awg;Bob;KB=;0;0;0;не подключался;измерено",
		"за всё время;awg;Abe;KC=;;;;;нет данных",
		"'=HYPERLINK(1)",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("в CSV нет %q:\n%s", want, s)
		}
	}
	pd := filepath.Join(dir, "day.csv")
	if _, code := showLines(t, sampleStats(), statsFlags{csv: pd, by: "day"}); code != 0 {
		t.Fatal(code)
	}
	b, _ = os.ReadFile(pd)
	if !strings.Contains(string(b), "2024-10-04;awg;Alice;KA=;3000;5000;8000") {
		t.Errorf("по суткам:\n%s", b)
	}
	if _, code := showLines(t, sampleStats(), statsFlags{by: "week", csv: pd}); code != 1 {
		t.Error("-by week принят")
	}
}

func TestStatsInstallConfirm(t *testing.T) {
	f := sampleStats()
	f.status = core.CollectorStatus{State: core.CollectorNotInstalled}
	f.after = core.CollectorStatus{State: core.CollectorInstalled}
	var out, errb bytes.Buffer
	// Без терминала «y» во входе не считается согласием — только -yes.
	if code := runStats(strings.NewReader("y\n"), &out, &errb, false, false, f, f, awgOnly, "install", statsFlags{}); code != 2 || f.installed != 0 {
		t.Errorf("без терминала и -yes: код %d, установок %d", code, f.installed)
	}
	for _, p := range []string{core.StatsScriptPath, core.StatsServicePath, core.StatsTimerPath, "OnUnitActiveSec=5min", "stats uninstall"} {
		if !strings.Contains(out.String(), p) {
			t.Errorf("перед подтверждением не показано %q", p)
		}
	}
	out.Reset()
	if code := runStats(strings.NewReader("n\n"), &out, &errb, true, false, f, f, awgOnly, "install", statsFlags{}); code != 2 || f.installed != 0 {
		t.Errorf("ответ «n»: код %d, установок %d", code, f.installed)
	}
	if code := runStats(strings.NewReader("y\n"), &out, &errb, true, false, f, f, awgOnly, "install", statsFlags{}); code != 0 || f.installed != 1 {
		t.Errorf("ответ «y»: код %d, установок %d", code, f.installed)
	}
	g := sampleStats() // уже установлен — идемпотентно, без записи
	if code := runStats(strings.NewReader(""), &out, &errb, false, true, g, g, awgOnly, "install", statsFlags{}); code != 0 || g.installed != 0 {
		t.Errorf("повторная установка: код %d, установок %d", code, g.installed)
	}
	h := sampleStats()
	h.after = core.CollectorStatus{State: core.CollectorNotInstalled}
	out.Reset()
	if code := runStats(strings.NewReader(""), &out, &errb, false, true, h, h, awgOnly, "uninstall", statsFlags{}); code != 0 || h.removed != 1 {
		t.Errorf("снятие: код %d, снятий %d", code, h.removed)
	}
	if !strings.Contains(out.String(), "ОСТАЮТСЯ") {
		t.Error("не сказано, что данные остаются")
	}
}

// statsRunner — сервер для теста доезда через настоящую core.Session.
type statsRunner struct{ raw string }

func (r statsRunner) Run(cmd string, stdin []byte) (string, error) {
	s := string(stdin)
	switch {
	case strings.Contains(s, "AA_STATUS_END"):
		var b strings.Builder
		for _, f := range core.StatsInstallFiles() {
			b.WriteString("AA_F " + f.Path + " -\n")
		}
		return b.String() + "AA_ACTIVE inactive\nAA_STATUS_END\n", nil
	case strings.Contains(s, "AA_READ_END"):
		return "AA_NOFILE daily.log\nAA_FILE snapshots.log\n" + r.raw + "\nAA_EOF snapshots.log\nAA_READ_END\n", nil
	}
	return "", errors.New("неизвестно")
}

// TestStatsReachesThroughSession — тест доезда: «нет данных» и ноль
// возникают боевым путём core.Session → разбор ответа → печать; сборщик
// снят, а данные остались — показываются.
func TestStatsReachesThroughSession(t *testing.T) {
	raw := "H v1 0\n" + tBlk(tDay*86400, "amnezia-awg", "KA= 1 1 0", "KB= 1 1 0") +
		tBlk(tDay*86400+300, "amnezia-awg", "KA= 1 1 0")
	sess := core.NewSessionWithRunner(statsRunner{raw}, &core.ServerCreds{Host: "h", User: "root"})
	var out, errb bytes.Buffer
	code := runStats(strings.NewReader(""), &out, &errb, false, false, sess, sess, nil, "", statsFlags{})
	s := out.String()
	if code != 0 || !strings.Contains(s, "не установлен") {
		t.Fatalf("код %d:\n%s%s", code, s, errb.String())
	}
	if r := rowOf(t, s, "KA="); !strings.Contains(r, "0 B") {
		t.Errorf("KA — измеренный ноль: %s", r)
	}
	// KB исчез из второго снимка — интервалов нет — строки нет вовсе
	// (ключей вне снимков программа не выдумывает).
	if strings.Contains(s, "KB=") {
		t.Errorf("KB без интервалов попал в таблицу:\n%s", s)
	}
}
