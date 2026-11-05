package core

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"
)

const day0 = int64(20000) // 2024-10-04 UTC

func tsAt(day int64, sec int64) int64 { return day*86400 + sec }

// tblk — целый блок снимка; peers — «ключ rx tx hs».
func tblk(ts int64, c string, peers ...string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "\nS %d %s %d\n", ts, c, len(peers))
	for _, p := range peers {
		b.WriteString("P " + p + "\n")
	}
	fmt.Fprintf(&b, "E %d %s %d\n", ts, c, len(peers))
	return b.String()
}

const awgC = "amnezia-awg"

func cellAll(l *TrafficLog, pub string) TrafficCell {
	return l.Cell(TrafficKey{awgC, pub}, AllTime, CollectorInstalled)
}

func TestPosixCksum(t *testing.T) {
	// Значения — вывод настоящей утилиты cksum (printf … | cksum).
	for in, want := range map[string]uint32{"": 4294967295, "123456789": 930766865} {
		if got := posixCksum([]byte(in)); got != want {
			t.Errorf("cksum(%q) = %d, want %d", in, got, want)
		}
	}
}

// TestTrafficAggregate — табличный: разбор и агрегация. Колонка state
// обязательна: «нет данных» отличается от измеренного нуля.
func TestTrafficAggregate(t *testing.T) {
	type want struct {
		state  TrafficState
		rx, tx int64
	}
	cases := []struct {
		name    string
		raw     string
		pub     string
		r       DayRange
		want    want
		corrupt int
		torn    bool
	}{
		{
			name: "только точка отсчёта — нет данных, не ноль",
			raw:  "H v1 0\n" + tblk(tsAt(day0, 0), awgC, "A 100 200 0"),
			pub:  "A", r: AllTime, want: want{TrafficNoData, 0, 0},
		},
		{
			name: "два снимка — разница",
			raw:  "H v1 0\n" + tblk(tsAt(day0, 0), awgC, "A 100 200 0") + tblk(tsAt(day0, 300), awgC, "A 150 260 5"),
			pub:  "A", r: AllTime, want: want{TrafficMeasured, 50, 60},
		},
		{
			name: "измеренный ноль — Measured с нулём",
			raw:  "H v1 0\n" + tblk(tsAt(day0, 0), awgC, "A 100 200 0") + tblk(tsAt(day0, 300), awgC, "A 100 200 0"),
			pub:  "A", r: AllTime, want: want{TrafficMeasured, 0, 0},
		},
		{
			name: "сброс счётчика — прибавляем с нуля",
			raw: "H v1 0\n" + tblk(tsAt(day0, 0), awgC, "A 100 200 0") + tblk(tsAt(day0, 300), awgC, "A 500 900 0") +
				tblk(tsAt(day0, 600), awgC, "A 30 40 0"),
			pub: "A", r: AllTime, want: want{TrafficMeasured, 400 + 30, 700 + 40},
		},
		{
			name: "сброс одного счётчика — сброс обоих",
			raw:  "H v1 0\n" + tblk(tsAt(day0, 0), awgC, "A 100 200 0") + tblk(tsAt(day0, 300), awgC, "A 50 300 0"),
			pub:  "A", r: AllTime, want: want{TrafficMeasured, 50, 300},
		},
		{
			name: "peer добавлен после первого снимка — считается целиком",
			raw:  "H v1 0\n" + tblk(tsAt(day0, 0), awgC, "A 1 1 0") + tblk(tsAt(day0, 300), awgC, "A 1 1 0", "B 70 80 0"),
			pub:  "B", r: AllTime, want: want{TrafficMeasured, 70, 80},
		},
		{
			name: "клиента нет в снимках — нет данных",
			raw:  "H v1 0\n" + tblk(tsAt(day0, 0), awgC, "A 1 1 0") + tblk(tsAt(day0, 300), awgC, "A 2 2 0"),
			pub:  "Z", r: AllTime, want: want{TrafficNoData, 0, 0},
		},
		{
			name: "битая строка в середине — блок пропущен, разница через пропуск",
			raw: "H v1 0\n" + tblk(tsAt(day0, 0), awgC, "A 100 100 0") +
				"\nS 1728000300 amnezia-awg 1\nP A 1x0 100 0\nE 1728000300 amnezia-awg 1\n" +
				tblk(tsAt(day0, 600), awgC, "A 300 400 0"),
			pub: "A", r: AllTime, want: want{TrafficMeasured, 200, 300}, corrupt: 1,
		},
		{
			name: "блок без E, за ним следующий — повреждение",
			raw: "H v1 0\n" + tblk(tsAt(day0, 0), awgC, "A 100 100 0") + "\nS 1 amnezia-awg 1\nP A 5" +
				tblk(tsAt(day0, 600), awgC, "A 300 400 0"),
			pub: "A", r: AllTime, want: want{TrafficMeasured, 200, 300}, corrupt: 1,
		},
		{
			name: "число строк P не совпало — блок не учтён",
			raw: "H v1 0\n" + tblk(tsAt(day0, 0), awgC, "A 100 100 0") +
				strings.Replace(tblk(tsAt(day0, 300), awgC, "A 200 200 0"), "E 1728000300 amnezia-awg 1", "E 1728000300 amnezia-awg 2", 1),
			pub: "A", r: AllTime, want: want{TrafficNoData, 0, 0}, corrupt: 1,
		},
		{
			name: "строка P потеряна, S и E согласны — блок не учтён",
			raw: "H v1 0\n" + tblk(tsAt(day0, 0), awgC, "A 100 100 0", "B 1 1 0") +
				strings.Replace(tblk(tsAt(day0, 300), awgC, "A 200 200 0", "B 2 2 0"), "P B 2 2 0\n", "", 1),
			pub: "A", r: AllTime, want: want{TrafficNoData, 0, 0}, corrupt: 1,
		},
		{
			name: "оборванный хвост — не учтён, не повреждение",
			raw:  "H v1 0\n" + tblk(tsAt(day0, 0), awgC, "A 100 100 0") + "\nS 1728000300 amnezia-awg 1\nP A 20",
			pub:  "A", r: AllTime, want: want{TrafficNoData, 0, 0}, torn: true,
		},
		{
			name: "строки F — не ноль, пропуск",
			raw: "H v1 0\n" + tblk(tsAt(day0, 0), awgC, "A 100 100 0") + "\nF 1728000300 amnezia-awg exec\n" +
				tblk(tsAt(day0, 600), awgC, "A 110 120 0"),
			pub: "A", r: AllTime, want: want{TrafficMeasured, 10, 20},
		},
		{
			name: "период без снимков — нет данных",
			raw:  "H v1 0\n" + tblk(tsAt(day0, 0), awgC, "A 100 200 0") + tblk(tsAt(day0, 300), awgC, "A 150 260 0"),
			pub:  "A", r: DayRange{day0 + 1, day0 + 5}, want: want{TrafficNoData, 0, 0},
		},
		{
			name: "разница относится к суткам завершающего снимка",
			raw:  "H v1 0\n" + tblk(tsAt(day0, 86000), awgC, "A 100 200 0") + tblk(tsAt(day0+1, 100), awgC, "A 150 260 0"),
			pub:  "A", r: DayRange{day0 + 1, day0 + 1}, want: want{TrafficMeasured, 50, 60},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			l := ParseTrafficLog("", false, c.raw, true)
			got := l.Cell(TrafficKey{awgC, c.pub}, c.r, CollectorInstalled)
			rx, tx, ok := got.Measured()
			if got.State != c.want.state || rx != c.want.rx || tx != c.want.tx {
				t.Errorf("получено %v %d/%d (ok=%v), ожидалось %v %d/%d", got.State, rx, tx, ok, c.want.state, c.want.rx, c.want.tx)
			}
			if ok != (c.want.state == TrafficMeasured) {
				t.Errorf("Measured ok=%v при состоянии %v", ok, got.State)
			}
			if l.Corrupt != c.corrupt || l.Torn != c.torn {
				t.Errorf("повреждено %d (ждали %d), хвост %v (ждали %v)", l.Corrupt, c.corrupt, l.Torn, c.torn)
			}
		})
	}
}

// TestTrafficThreeStates — тест различения: «не установлен», «нет данных»
// и «измерено 0» — три разных исхода, а нулевая ячейка — незнание.
func TestTrafficThreeStates(t *testing.T) {
	empty := ParseTrafficLog("", false, "", false)
	k := TrafficKey{awgC, "A"}
	if got := empty.Cell(k, AllTime, CollectorNotInstalled).State; got != TrafficNotInstalled {
		t.Errorf("нет файлов, сборщика нет: %v", got)
	}
	if got := empty.Cell(k, AllTime, CollectorInstalled).State; got != TrafficNoData {
		t.Errorf("нет файлов, сборщик есть: %v", got)
	}
	if got := empty.Cell(k, AllTime, CollectorUnknown).State; got != TrafficUnknown {
		t.Errorf("нет файлов, о сборщике не знаем: %v", got)
	}
	if _, _, ok := (TrafficCell{}).Measured(); ok {
		t.Error("нулевая ячейка выдала цифры")
	}
	// Данные есть, сборщик снят — данные остаются данными.
	l := ParseTrafficLog("", false, "H v1 0\n"+tblk(1, awgC, "A 1 1 0")+tblk(2, awgC, "A 1 1 0"), true)
	if got := l.Cell(k, AllTime, CollectorNotInstalled).State; got != TrafficMeasured {
		t.Errorf("данные при снятом сборщике: %v", got)
	}
}

// TestTrafficRotationGenerations — суточные итоги и журнал складываются;
// журнал старше итогов (окно между mv) не считается дважды.
func TestTrafficRotationGenerations(t *testing.T) {
	daily := fmt.Sprintf("D 1 %d amnezia-awg A 1000 2000 0 5\nN 1 %d amnezia-awg 5\n", day0, day0)
	raw := "H v1 1\n" + tblk(tsAt(day0, 1000), awgC, "A 10 10 0") + tblk(tsAt(day0, 1300), awgC, "A 15 17 0")
	l := ParseTrafficLog(daily, true, raw, true)
	if rx, tx, ok := cellAll(l, "A").Measured(); !ok || rx != 1005 || tx != 2007 {
		t.Errorf("итоги+журнал: %d/%d ok=%v", rx, tx, ok)
	}
	stale := "H v1 0\n" + tblk(tsAt(day0, 1000), awgC, "A 10 10 0") + tblk(tsAt(day0, 1300), awgC, "A 15 17 0")
	l = ParseTrafficLog(daily, true, stale, true)
	if !l.RawStale {
		t.Error("старый журнал не опознан")
	}
	if rx, tx, ok := cellAll(l, "A").Measured(); !ok || rx != 1000 || tx != 2000 {
		t.Errorf("старый журнал посчитан дважды: %d/%d", rx, tx)
	}
	bad := ParseTrafficLog(daily+"D 1 x amnezia-awg A 1 1 0 1\nqq\n", true, "", false)
	if bad.Corrupt != 2 {
		t.Errorf("битые строки итогов: %d", bad.Corrupt)
	}
}

// fakeStatsRunner — сервер, отвечающий на команды статистики.
type fakeStatsRunner struct {
	files  map[string]string // имя → содержимое (нет ключа — нет файла)
	fail   error
	cmds   []string
	stdins []string
}

func (f *fakeStatsRunner) Run(cmd string, stdin []byte) (string, error) {
	f.cmds = append(f.cmds, cmd)
	f.stdins = append(f.stdins, string(stdin))
	if f.fail != nil {
		return "", f.fail
	}
	s := string(stdin)
	if s == statsReadScript() {
		var b strings.Builder
		for _, n := range []string{"daily.log", "snapshots.log"} {
			if c, ok := f.files[n]; ok {
				b.WriteString("AA_FILE " + n + "\n" + c + "\nAA_EOF " + n + "\n")
			} else {
				b.WriteString("AA_NOFILE " + n + "\n")
			}
		}
		b.WriteString("AA_READ_END\n")
		return b.String(), nil
	}
	return "", errors.New("неизвестная команда")
}

// TestReadTrafficReaches — тест доезда: состояния возникают боевым путём
// Session.ReadTraffic → разбор ответа сервера, а не присваиванием.
func TestReadTrafficReaches(t *testing.T) {
	f := &fakeStatsRunner{files: map[string]string{
		"snapshots.log": "H v1 0\n" + tblk(tsAt(day0, 0), awgC, "A 100 200 0", "B 1 1 0") + tblk(tsAt(day0, 300), awgC, "A 150 260 0", "B 1 1 0"),
	}}
	s := NewSessionWithRunner(f, &ServerCreds{Host: "h", User: "root"})
	l, err := s.ReadTraffic()
	if err != nil {
		t.Fatal(err)
	}
	if c := l.Cell(TrafficKey{awgC, "B"}, AllTime, CollectorInstalled); c.State != TrafficMeasured {
		t.Errorf("B: измеренный ноль потерян: %v", c.State)
	}
	if c := l.Cell(TrafficKey{awgC, "A"}, DayRange{day0 + 1, day0 + 2}, CollectorInstalled); c.State != TrafficNoData {
		t.Errorf("A вне периода: %v", c.State)
	}
	f.files = map[string]string{}
	l, err = s.ReadTraffic()
	if err != nil || !l.Empty() {
		t.Fatalf("нет файлов: %v %v", l, err)
	}
	f.fail = errors.New("connection lost")
	if l, err := s.ReadTraffic(); err == nil || l != nil {
		t.Error("отказ чтения превратился в данные")
	}
}

func TestParseTrafficReadTruncated(t *testing.T) {
	if _, err := parseTrafficRead("AA_FILE snapshots.log\nH v1 0\n"); err == nil {
		t.Error("оборванный ответ принят")
	}
	if _, err := parseTrafficRead("AA_FILE snapshots.log\nH v1 0\nAA_ERR snapshots.log\nAA_READ_END\n"); err == nil {
		t.Error("ошибка чтения файла принята")
	}
}

func TestCollectorStatus(t *testing.T) {
	line := func(f StatsInstallFile, ours bool) string {
		c := f.Content
		if !ours {
			c += "x"
		}
		return fmt.Sprintf("AA_F %s %d %d\n", f.Path, posixCksum([]byte(c)), len(c))
	}
	all := func(ours bool, active string) string {
		var b strings.Builder
		for _, f := range StatsInstallFiles() {
			b.WriteString(line(f, ours))
		}
		return b.String() + "AA_ACTIVE " + active + "\nAA_STATUS_END\n"
	}
	var none strings.Builder
	for _, f := range StatsInstallFiles() {
		none.WriteString("AA_F " + f.Path + " -\n")
	}
	cases := []struct {
		name string
		out  string
		want CollectorState
	}{
		{"установлен", all(true, "active"), CollectorInstalled},
		{"таймер не активен", all(true, "inactive"), CollectorPartial},
		{"другая версия", all(false, "active"), CollectorPartial},
		{"нет ничего", none.String() + "AA_ACTIVE inactive\nAA_STATUS_END\n", CollectorNotInstalled},
		{"оборванный ответ", strings.TrimSuffix(all(true, "active"), "AA_STATUS_END\n"), CollectorUnknown},
		{"пусто", "", CollectorUnknown},
	}
	for _, c := range cases {
		if got := parseCollectorStatus(c.out).State; got != c.want {
			t.Errorf("%s: %v, ждали %v", c.name, got, c.want)
		}
	}
	if st := parseCollectorStatus(all(true, "active") + "AA_FULL raw\n"); st.Full != "raw" {
		t.Errorf("FULL: %q", st.Full)
	}
}

// ---------- настоящий sh/awk ----------

// needSh — sh и awk. На Linux и macOS их отсутствие — падение, а не
// пропуск: иначе сверка awk с Go молча не выполнялась бы там, где
// выполняться обязана.
func needSh(t *testing.T) string {
	t.Helper()
	sh, err := exec.LookPath("sh")
	if err == nil {
		if out, e := exec.Command(sh, "-c", "awk 'BEGIN { print 1 }'").Output(); e == nil && strings.TrimSpace(string(out)) == "1" {
			return sh
		}
	}
	if runtime.GOOS == "windows" {
		t.Skip("sh/awk недоступны (Windows без Git Bash)")
	}
	t.Fatalf("sh/awk недоступны: %v", err)
	return ""
}

func runAwk(t *testing.T, sh, prog string, vars map[string]string, input string) string {
	t.Helper()
	dir := t.TempDir()
	in := filepath.Join(dir, "in.log")
	pf := filepath.Join(dir, "prog.awk")
	if err := os.WriteFile(in, []byte(input), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pf, []byte(prog), 0o600); err != nil {
		t.Fatal(err)
	}
	args := []string{"-c", `p=$1; shift; exec awk "$@" -f "$p" in.log`, "sh", "prog.awk"}
	keys := make([]string, 0, len(vars))
	for k := range vars {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		args = append(args, "-v", k+"="+vars[k])
	}
	cmd := exec.Command(sh, args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("awk: %v\n%s", err, out)
	}
	return string(out)
}

// statsSampleRaw — журнал со всеми трудными местами: сброс, добавление и
// удаление peer'а, битые и оборванные блоки, F, несколько суток и два
// контейнера.
func statsSampleRaw() string {
	w := "amnezia-wireguard"
	return "H v1 0\n" +
		tblk(tsAt(day0, 100), awgC, "A 100 200 1", "B 5 5 0") +
		tblk(tsAt(day0, 100), w, "W 1 1 0") +
		tblk(tsAt(day0, 400), awgC, "A 300 250 2", "B 5 5 0") +
		"\nF 1728000700 amnezia-awg exec\n" +
		"\nS 1728000800 amnezia-awg 2\nP A 9x 1 1\nE 1728000800 amnezia-awg 2\n" +
		tblk(tsAt(day0, 86000), awgC, "A 40 50 3", "C 7 8 4") +
		tblk(tsAt(day0+1, 200), awgC, "A 90 60 5", "C 9 9 4", "B 1 2 6") +
		tblk(tsAt(day0+1, 300), w, "W 100 300 9") +
		tblk(tsAt(day0+2, 50), awgC, "A 95 61 7") +
		"\nS 1728200000 amnezia-awg 1\nP A 1 1"
}

func cellsEqual(t *testing.T, what string, a, b *TrafficLog) {
	t.Helper()
	keys := map[TrafficKey]bool{}
	for _, k := range append(a.Keys(), b.Keys()...) {
		keys[k] = true
	}
	if len(keys) == 0 {
		t.Fatalf("%s: пусто — сверять нечего", what)
	}
	for k := range keys {
		for d := day0 - 1; d <= day0+3; d++ {
			r := DayRange{d, d}
			ca, cb := a.Cell(k, r, CollectorInstalled), b.Cell(k, r, CollectorInstalled)
			if ca != cb {
				t.Errorf("%s: %v сутки %d: %+v ≠ %+v", what, k, d, ca, cb)
			}
		}
	}
	for _, c := range []string{"", awgC, "amnezia-wireguard"} {
		if fmt.Sprint(a.CoveredDays(c)) != fmt.Sprint(b.CoveredDays(c)) {
			t.Errorf("%s: покрытие %q: %v ≠ %v", what, c, a.CoveredDays(c), b.CoveredDays(c))
		}
	}
}

// TestAwkMatchesGo — правило разницы на сервере (awkAgg, ротация) и в Go
// одно и то же: Go по журналу ≡ Go по (итоги awk + контрольная точка awk +
// продолжение журнала).
func TestAwkMatchesGo(t *testing.T) {
	sh := needSh(t)
	raw := statsSampleRaw()
	direct := ParseTrafficLog("", false, raw, true)

	// Ротация посреди: первая половина свёрнута awk, вторая дописана к
	// контрольной точке.
	cut := strings.Index(raw, tblk(tsAt(day0+1, 200), awgC, "A 90 60 5", "C 9 9 4", "B 1 2 6"))
	first, second := raw[:cut], raw[cut:]
	daily := runAwk(t, sh, awkAgg, map[string]string{"gen": "1"}, first)
	ckpt := runAwk(t, sh, awkCheckpoint, nil, first)
	if !strings.Contains(daily, "D 1 ") || !strings.Contains(ckpt, "\nS ") {
		t.Fatalf("awk ничего не вывел:\n%s\n---\n%s", daily, ckpt)
	}
	rotated := ParseTrafficLog(daily, true, "H v1 1\n"+ckpt+second, true)
	cellsEqual(t, "ротация", direct, rotated)

	// И целиком: итоги awk по всему журналу ≡ Go.
	whole := ParseTrafficLog(runAwk(t, sh, awkAgg, map[string]string{"gen": "1"}, raw), true, "", false)
	cellsEqual(t, "целиком", direct, whole)

	if g := runAwk(t, sh, awkGen, map[string]string{"add": "1"}, daily+"D 7 1 x A 1 1 0 1\n"); strings.TrimSpace(g) != "8" {
		t.Errorf("awkGen: %q", g)
	}
}

// TestCollectorScriptEndToEnd — настоящий collect.sh под sh с подменённым
// docker и date: снимки, F при отказе, ротация с порогом, уменьшенным для
// теста, FULL. Каталог подменяется на временный (единственная правка
// текста скрипта, кроме порогов).
func TestCollectorScriptEndToEnd(t *testing.T) {
	sh := needSh(t)
	dir := t.TempDir()
	data := filepath.Join(dir, "data")
	bin := filepath.Join(dir, "bin")
	for _, d := range []string{data, bin} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	// Состояние подмены: файлы в bin/ (rx и время).
	write := func(name, s string) {
		if err := os.WriteFile(filepath.Join(bin, name), []byte(s), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	write("docker", `#!/bin/sh
d=$(dirname "$0")
if [ "$1" = ps ]; then printf 'amnezia-awg\nother\n'; exit 0; fi
if [ "$1" = exec ] && [ "$2" = amnezia-awg ] && [ "$3" = wg ] && [ "$5" = wg0 ]; then
  if [ -e "$d/fail" ]; then exit 1; fi
  rx=$(cat "$d/rx")
  printf 'priv\tpub\t51820\toff\n'
  printf 'KEYA=\tpsk\t1.2.3.4:5\t10.8.1.2/32\t1700000000\t%s\t%s\toff\n' "$rx" "$rx"
  exit 0
fi
exit 2
`)
	write("date", `#!/bin/sh
cat "$(dirname "$0")/now"
`)
	script := StatsCollectorScript()
	script = strings.ReplaceAll(script, StatsDir, filepath.ToSlash(data))
	script = strings.Replace(script, fmt.Sprintf(`-gt %d ]`, statsRotateBytes), `-gt 400 ]`, 1)
	if !strings.Contains(script, "-gt 400 ]") {
		t.Fatal("порог ротации не подменён")
	}
	sf := filepath.Join(dir, "collect.sh")
	if err := os.WriteFile(sf, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	run := func(now int64, rx int64, fail bool) {
		t.Helper()
		write("now", fmt.Sprintf("%d\n", now))
		write("rx", fmt.Sprintf("%d\n", rx))
		_ = os.Remove(filepath.Join(bin, "fail"))
		if fail {
			write("fail", "")
		}
		cmd := exec.Command(sh, "-c", `cd "$1" && PATH="$(pwd):$PATH" && export PATH && exec sh "$2"`, "sh", filepath.ToSlash(bin), filepath.ToSlash(sf))
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("collect.sh: %v\n%s", err, out)
		}
	}
	read := func() *TrafficLog {
		t.Helper()
		get := func(n string) (string, bool) {
			b, err := os.ReadFile(filepath.Join(data, n))
			if err != nil {
				return "", false
			}
			return string(b), true
		}
		d, hd := get("daily.log")
		r, hr := get("snapshots.log")
		return ParseTrafficLog(d, hd, r, hr)
	}
	// Счётчик растёт на 10 за снимок, сброс на 6-м снимке, отказ на 4-м.
	rx := int64(1000)
	var wantRx int64
	for i := 0; i < 12; i++ {
		now := tsAt(day0, int64(i)*300)
		switch {
		case i == 3:
			run(now, rx, true)
			continue
		case i == 6:
			rx = 5
			if i > 0 {
				wantRx += 5
			}
		default:
			if i > 0 {
				rx += 10
				wantRx += 10
				if i == 4 {
					wantRx += 10 // пропущенный снимок 3: разница через пропуск
					rx += 10
				}
			}
		}
		run(now, rx, false)
	}
	l := read()
	if t.Failed() || !l.HaveDaily {
		for _, n := range []string{"snapshots.log", "daily.log"} {
			b, _ := os.ReadFile(filepath.Join(data, n))
			t.Logf("%s:\n%s", n, b)
		}
	}
	if !l.HaveDaily {
		t.Error("ротация не произошла (daily.log нет)")
	}
	if l.Failed == 0 && !l.HaveDaily {
		t.Error("отказ docker не записан строкой F")
	}
	c := l.Cell(TrafficKey{awgC, "KEYA="}, AllTime, CollectorInstalled)
	got, _, ok := c.Measured()
	if !ok || got != wantRx {
		t.Errorf("за всё время: %d ok=%v, ждали %d (corrupt=%d torn=%v stale=%v)", got, ok, wantRx, l.Corrupt, l.Torn, l.RawStale)
	}
	if l.Corrupt != 0 || l.Torn {
		t.Errorf("повреждения в собственных файлах: %d %v", l.Corrupt, l.Torn)
	}
	if c.LastHandshake.Unix() != 1700000000 {
		t.Errorf("рукопожатие: %v", c.LastHandshake)
	}
	// Предел: журнал больше statsRawCapBytes (подменённого) — FULL и тишина.
	full := strings.Replace(script, fmt.Sprintf(`-gt %d ]`, statsRawCapBytes), `-gt 1 ]`, 1)
	if err := os.WriteFile(sf, []byte(full), 0o700); err != nil {
		t.Fatal(err)
	}
	run(tsAt(day0, 99999), rx+1, false)
	if _, err := os.Stat(filepath.Join(data, "FULL")); err != nil {
		t.Error("FULL не создан при превышении предела")
	}
	before, _ := os.ReadFile(filepath.Join(data, "snapshots.log"))
	run(tsAt(day0, 99999+300), rx+2, false)
	after, _ := os.ReadFile(filepath.Join(data, "snapshots.log"))
	if string(before) != string(after) {
		t.Error("после FULL сборщик продолжил писать")
	}
	_ = time.Now
}
