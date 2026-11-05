package core

// Раунд 3 — аудит AU-1 TRAFFIC-STATS: С1 (таймауты), С2 (идёт ли сбор),
// С3 (дыры с перезапуском, контейнер вне docker ps), Н1 (каталог), Н2
// (снятие).

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestStatsTimeouts(t *testing.T) {
	if !strings.Contains(StatsServiceUnit(), "\nTimeoutStartSec=300s\n") {
		t.Error("у oneshot-службы нет TimeoutStartSec=300s — зависший docker остановит сбор навсегда")
	}
	// Н5 раунда 4: бюджет службы покрывает худший случай. Вызовы docker в
	// скрипте: 2 вне цикла по контейнерам и 2 внутри (на каждый контейнер).
	if n := strings.Count(StatsCollectorScript(), "timeout 30 docker "); n != 4 {
		t.Errorf("вызовов docker в скрипте %d — пересчитайте бюджет statsStartTimeoutSec", n)
	}
	if worst := 30*(2+2*len(wgFamilies)) + statsRunSlackSec; statsStartTimeoutSec() < worst {
		t.Errorf("TimeoutStartSec %d меньше худшего случая %d", statsStartTimeoutSec(), worst)
	}
	sc := StatsCollectorScript()
	docker := strings.Count(sc, "docker ")
	timed := strings.Count(sc, "timeout 30 docker ")
	if docker == 0 || docker != timed {
		t.Errorf("вызовов docker %d, из них под timeout %d", docker, timed)
	}
	if !strings.Contains(sc, "> 660") || statsGapSec != 660 {
		t.Error("порог дыры в awk и в Go разошёлся")
	}
}

// statusOut — вывод statsStatusScript в форме настоящего сервера:
// systemctl show печатает «Ключ=значение» по строке.
func statusOut(active, result, state string, now int64, tail string) string {
	var b strings.Builder
	for _, f := range StatsInstallFiles() {
		fmt.Fprintf(&b, "AA_F %s %d %d\n", f.Path, posixCksum([]byte(f.Content)), len(f.Content))
	}
	b.WriteString("AA_ACTIVE " + active + "\n")
	if result != "" {
		fmt.Fprintf(&b, "Result=%s\nActiveState=%s\nSubState=%s\n", result, state, map[string]string{"activating": "start", "inactive": "dead", "failed": "failed"}[state])
	}
	if now > 0 {
		fmt.Fprintf(&b, "AA_NOW %d\n", now)
	}
	if tail != "-" {
		b.WriteString("AA_TAIL_BEGIN\n" + tail + "\nAA_TAIL_END\n")
	}
	return b.String() + "AA_STATUS_END\n"
}

// TestCollectState — тест различения: таймер активен во всех строках, а
// «работает» — только при успешной службе и свежем снимке.
func TestCollectState(t *testing.T) {
	now := int64(1_800_000_000)
	fresh := tblk(now-200, awgC, "A 1 1 0") + "\nF 1799999900 amnezia-wireguard stopped"
	old := tblk(now-3600, awgC, "A 1 1 0")
	cases := []struct {
		name string
		out  string
		want CollectState
		why  string
	}{
		{"успех и свежий снимок", statusOut("active", "success", "inactive", now, fresh), CollectWorking, ""},
		{"служба падает", statusOut("active", "exit-code", "failed", now, fresh), CollectStopped, "Result=exit-code"},
		{"снимок старый", statusOut("active", "success", "inactive", now, old), CollectStopped, "60 мин назад"},
		{"служба висит", statusOut("active", "success", "activating", now, old), CollectStopped, "зависла"},
		{"снимков нет", statusOut("active", "success", "inactive", now, "-"), CollectStopped, "снимков нет"},
		{"в хвосте нет целого снимка", statusOut("active", "success", "inactive", now, "H v1 0\nF 1 - ps"), CollectStopped, "ни одного целого"},
		{"systemctl show не ответил", statusOut("active", "", "", now, fresh), CollectUnknown, "прочитать не удалось"},
		{"нет времени сервера", statusOut("active", "success", "inactive", 0, fresh), CollectUnknown, "прочитать не удалось"},
	}
	for _, c := range cases {
		st := parseCollectorStatus(c.out)
		if st.Collect != c.want || !strings.Contains(st.CollectWhy, c.why) {
			t.Errorf("%s: %v %q, ждали %v %q", c.name, st.Collect, st.CollectWhy, c.want, c.why)
		}
	}
	if st := parseCollectorStatus(statusOut("active", "success", "inactive", now, fresh)); st.SnapshotAge != 200*time.Second {
		t.Errorf("возраст снимка: %v", st.SnapshotAge)
	}
}

// statusRunner — сервер, отвечающий на статус.
type statusRunner struct{ out string }

func (r statusRunner) Run(cmd string, stdin []byte) (string, error) { return r.out, nil }

// TestCollectStateReaches — доезд через Session.StatsStatus.
func TestCollectStateReaches(t *testing.T) {
	now := int64(1_800_000_000)
	s := NewSessionWithRunner(statusRunner{statusOut("active", "exit-code", "failed", now, tblk(now-100, awgC, "A 1 1 0"))}, &ServerCreds{Host: "h", User: "root"})
	st := s.StatsStatus()
	if st.State != CollectorInstalled || st.Collect != CollectStopped {
		t.Errorf("таймер активен, служба падает: %v %v", st.State, st.Collect)
	}
}

// TestTrafficGapRestart — С3: перезапуск в дыре — «не меньше», не «измерено».
func TestTrafficGapRestart(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want TrafficState
	}{
		{"дыра и сброс по величине", tblk(tsAt(day0, 0), awgC, "A 500 500 0") + tblk(tsAt(day0, 4000), awgC, "A 10 10 0"), TrafficPartial},
		{"дыра и смена признака", tsig(tsAt(day0, 0), awgC, "b1 s1", "A 5 5 0") + tsig(tsAt(day0, 4000), awgC, "b1 s2", "A 900 900 0"), TrafficPartial},
		{"дыра без перезапуска", tblk(tsAt(day0, 0), awgC, "A 5 5 0") + tblk(tsAt(day0, 4000), awgC, "A 900 900 0"), TrafficMeasured},
		{"перезапуск без дыры", tblk(tsAt(day0, 0), awgC, "A 500 500 0") + tblk(tsAt(day0, 300), awgC, "A 10 10 0"), TrafficMeasured},
	}
	for _, c := range cases {
		l := ParseTrafficLog("", false, "H v1 0\n"+c.raw, true)
		cell := cellAll(l, "A")
		if cell.State != c.want {
			t.Errorf("%s: %v, ждали %v", c.name, cell.State, c.want)
		}
		if c.want == TrafficPartial {
			if _, _, ok := cell.Measured(); ok {
				t.Errorf("%s: частичная ячейка выдала цифры как измеренные", c.name)
			}
			if _, _, ok := cell.LowerBound(); !ok || l.Partial() != 1 {
				t.Errorf("%s: нет нижней границы (partial=%d)", c.name, l.Partial())
			}
		}
	}
	// Итоги ротации несут пометку: десятое поле D.
	l := ParseTrafficLog(fmt.Sprintf("D 1 %d amnezia-awg A 10 10 0 1 1\n", day0), true, "", false)
	if cellAll(l, "A").State != TrafficPartial {
		t.Error("пометка частичной потери из daily.log не дошла")
	}
}

// TestCollectorStoppedContainer — С3: контейнер есть, но не запущен —
// строка F, а не молчание.
func TestCollectorStoppedContainer(t *testing.T) {
	e := newCollectorEnv(t)
	e.mustRun(tsAt(day0, 0), 1)
	l := e.read()
	raw, _ := os.ReadFile(filepath.Join(e.data, "snapshots.log"))
	if l.Failed != 1 || !strings.Contains(string(raw), " amnezia-wireguard stopped") {
		e.dump()
		t.Errorf("остановленный контейнер: строк F %d", l.Failed)
	}
}

func shOrSkip(t *testing.T) string {
	return needSh(t)
}

// TestStatsDirCheck — Н1: каталог-симлинк и каталог с чужим
// владельцем/правами — отказ с причиной (настоящий sh).
func TestStatsDirCheck(t *testing.T) {
	sh := shOrSkip(t)
	run := func(dir string, neutralizeChown bool) string {
		sc := strings.ReplaceAll(statsDirCheck(), StatsDir, filepath.ToSlash(dir)) + "echo AA_DIR_OK\n"
		if neutralizeChown {
			// не root: chown невозможен — проверяем, что сверка stat ловит
			// чужого владельца, а не молча проходит
			sc = strings.Replace(sc, "chown root:root ", ": ", 1)
		}
		out, _ := exec.Command(sh, "-c", sc).CombinedOutput()
		return string(out)
	}
	base := t.TempDir()
	target := filepath.Join(base, "real")
	if err := os.MkdirAll(target, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(target, link); err == nil {
		if out := run(link, true); !strings.Contains(out, "AA_STATS_BADDIR symlink") || strings.Contains(out, "AA_DIR_OK") {
			t.Errorf("симлинк принят: %s", out)
		}
	} else if runtime.GOOS != "windows" {
		t.Fatal(err)
	}
	out := run(filepath.Join(base, "d"), true)
	if os.Getuid() != 0 && (!strings.Contains(out, "AA_STATS_BADDIR ") || strings.Contains(out, "AA_DIR_OK")) {
		t.Errorf("каталог не root принят: %s", out)
	}
}

// TestStatsUninstallMarker — Н2: *.new удаляются, маркер — только если
// файлов действительно нет.
func TestStatsUninstallMarker(t *testing.T) {
	sh := shOrSkip(t)
	dir := t.TempDir()
	sc := statsUninstallScript()
	paths := []string{StatsTimerPath, StatsServicePath, StatsScriptPath}
	local := map[string]string{}
	for i, p := range paths {
		local[p] = filepath.ToSlash(filepath.Join(dir, fmt.Sprintf("f%d", i)))
	}
	for p, l := range local {
		sc = strings.ReplaceAll(sc, p, l)
	}
	sc = "systemctl() { :; }\n" + sc
	for _, l := range local {
		for _, f := range []string{l, l + ".new"} {
			if err := os.WriteFile(filepath.FromSlash(f), []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	out, err := exec.Command(sh, "-c", sc).CombinedOutput()
	if err != nil || !strings.Contains(string(out), "AA_STATS_REMOVED") {
		t.Errorf("снятие: %v %s", err, out)
	}
	for _, l := range local {
		for _, f := range []string{l, l + ".new"} {
			if _, err := os.Stat(filepath.FromSlash(f)); err == nil {
				t.Errorf("не удалён %s", f)
			}
		}
	}
	// rm не смог (на месте файла — непустой каталог): маркера нет.
	stuck := filepath.FromSlash(local[StatsServicePath])
	if err := os.MkdirAll(filepath.Join(stuck, "x"), 0o700); err != nil {
		t.Fatal(err)
	}
	out, _ = exec.Command(sh, "-c", sc).CombinedOutput()
	if strings.Contains(string(out), "AA_STATS_REMOVED") {
		t.Errorf("маркер снятия при неудаче rm: %s", out)
	}
}
