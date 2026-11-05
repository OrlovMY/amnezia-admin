package main

// Раунд 2 ревью TRAFFIC-STATS-1: С1, Н1, Н3, Н4.

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

// staleRunner — ротация прервана: daily.log поколения 1, журнал поколения 0.
type staleRunner struct{ full string }

func (r staleRunner) Run(cmd string, stdin []byte) (string, error) {
	s := string(stdin)
	switch {
	case strings.Contains(s, "AA_STATUS_END"):
		var b strings.Builder
		for _, f := range core.StatsInstallFiles() {
			fmt.Fprintf(&b, "AA_F %s -\n", f.Path)
		}
		b.WriteString("AA_ACTIVE inactive\n")
		if r.full != "" {
			b.WriteString("AA_FULL " + r.full + "\n")
		}
		return b.String() + "AA_STATUS_END\n", nil
	case strings.Contains(s, "AA_READ_END"):
		daily := fmt.Sprintf("D 1 %d amnezia-awg +KA= 100 200 0 3\nN 1 %d amnezia-awg 3 0\n", tDay, tDay)
		raw := "H v1 0\n" + tBlk(tDay*86400, "amnezia-awg", "+KA= 1 1 0") + tBlk(tDay*86400+300, "amnezia-awg", "+KA= 5 5 0")
		return "AA_FILE daily.log\n" + daily + "\nAA_EOF daily.log\nAA_FILE snapshots.log\n" + raw + "\nAA_EOF snapshots.log\nAA_READ_END\n", nil
	}
	return "", errors.New("неизвестно")
}

// TestStatsStaleRawShown — С1: отброшенный устаревший журнал говорится
// вслух (доезд: core.Session → разбор → печать); цифры — только из итогов.
func TestStatsStaleRawShown(t *testing.T) {
	sess := core.NewSessionWithRunner(staleRunner{}, &core.ServerCreds{Host: "h", User: "root"})
	var out, errb bytes.Buffer
	if code := runStats(strings.NewReader(""), &out, &errb, false, false, sess, sess, nil, "", statsFlags{}); code != 0 {
		t.Fatalf("код %d %s", code, errb.String())
	}
	s := out.String()
	if !strings.Contains(s, "Журнал снимков устарел") {
		t.Errorf("устаревший журнал отброшен молча:\n%s", s)
	}
	if r := rowOf(t, s, "+KA="); !strings.Contains(r, "100 B") {
		t.Errorf("цифры не из итогов: %s", r)
	}
	// Н1: ключ на «+» и имя на «(» в CSV экранированы.
	p := filepath.Join(t.TempDir(), "k.csv")
	if code := runStats(strings.NewReader(""), &out, &errb, false, false, sess, sess, nil, "", statsFlags{csv: p}); code != 0 {
		t.Fatal(code)
	}
	b, _ := os.ReadFile(p)
	if !strings.Contains(string(b), ";'+KA=;") || strings.Contains(string(b), ";+KA=;") {
		t.Errorf("ключ на «+» не экранирован:\n%s", b)
	}
	if !strings.Contains(string(b), ";'(нет в списке клиентов)") {
		t.Errorf("имя на «(» не экранировано (закрытый список):\n%s", b)
	}
}

func TestCSVSafeClosedList(t *testing.T) {
	for in, want := range map[string]string{
		"Alice": "Alice", "Ёж": "Ёж", "яблоко": "яблоко", "42": "42", "": "",
		"+KA=": "'+KA=", "=1": "'=1", "-1": "'-1", "@x": "'@x", " x": "' x", "\tx": "'\tx", "(x": "'(x", "«x": "'«x",
	} {
		if got := csvSafe(in); got != want {
			t.Errorf("csvSafe(%q) = %q, ждали %q", in, got, want)
		}
	}
}

// TestStatsFullHint — Н3: после FULL сказано, что делать.
func TestStatsFullHint(t *testing.T) {
	for why, want := range map[string]string{"raw": "ротация журнала не удаётся", "daily": "stats -csv"} {
		sess := core.NewSessionWithRunner(staleRunner{full: why}, &core.ServerCreds{Host: "h", User: "root"})
		var out, errb bytes.Buffer
		runStats(strings.NewReader(""), &out, &errb, false, false, sess, sess, nil, "status", statsFlags{})
		if s := out.String(); !strings.Contains(s, want) || !strings.Contains(s, core.StatsDir+"/FULL") {
			t.Errorf("FULL %s: нет подсказки:\n%s", why, s)
		}
	}
}

// TestStatsInstallShowsSteps — Н4: показ перечисляет mkdir и .new+mv.
func TestStatsInstallShowsSteps(t *testing.T) {
	f := sampleStats()
	f.status = core.CollectorStatus{State: core.CollectorNotInstalled}
	var out, errb bytes.Buffer
	runStats(strings.NewReader(""), &out, &errb, false, false, f, f, awgOnly, "install", statsFlags{})
	for _, w := range []string{"mkdir -p " + core.StatsDir, ".new", "(mv)"} {
		if !strings.Contains(out.String(), w) {
			t.Errorf("в показе нет %q", w)
		}
	}
}
