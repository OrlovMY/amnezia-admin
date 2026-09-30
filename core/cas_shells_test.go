package core

// A3б, PR-2: точный текст команды записи (CASWriteCommand — часть после
// `docker exec -i C`, CASWriteScript, CASWriteStdin) исполняется в настоящих
// оболочках busybox sh и dash, с настоящими утилитами (у busybox — его
// апплеты, как в контейнере на busybox; у dash — coreutils). fakesrv
// исполняет скрипт системным sh; здесь — именно те оболочки, которых на
// Windows-машине разработчика нет.
//
// Только Linux. На Linux в CI (переменная CI) отсутствие dash, busybox или
// flock — провал: проверка, которая молча не выполнилась, выглядит как
// пройденная. Вне CI — пропуск с названием причины; путь к busybox можно
// дать переменной AMNEZIA_BUSYBOX.
//
// Вердикт — функция shellsVerdict (список нарушений), каждое нарушение
// печатается t.Errorf с меткой shellsMarker. Канарейка
// TestCASScriptRealShellsCanary запускает этот тест дочерним процессом с
// посадками: скрипт без сверки суммы wg0.conf и выпавший сценарий. Прогон
// обязан упасть по вердикту — иначе проверка перестала проверять.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
)

const shellsMarker = "ОБОЛОЧКИ-ВЕРДИКТ:"
const shellsPlantEnv = "AMNEZIA_SHELLS_PLANT"

// shellsWantScenarios — ТОЧНОЕ число сценариев на каждую оболочку.
const shellsWantScenarios = 13

type realShell struct {
	name  string
	sh    string            // путь к оболочке (для busybox — сам busybox, аргумент "sh")
	shArg []string          // префикс аргументов оболочки
	tools map[string]string // имя в PATH → цель (исполняемый файл)
}

func sum64(b []byte, ok bool) string {
	if !ok {
		return CASAbsent
	}
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// findRealShells — dash и busybox с их утилитами. Ошибка — чего нет.
func findRealShells() ([]realShell, []string) {
	var shells []realShell
	var missing []string
	core := []string{"sha256sum", "base64", "mv", "rm", "timeout"}
	if dash, err := exec.LookPath("dash"); err == nil {
		tools := map[string]string{"sh": dash}
		ok := true
		for _, t := range core {
			p, err := exec.LookPath(t)
			if err != nil {
				missing = append(missing, "coreutils "+t)
				ok = false
				continue
			}
			tools[t] = p
		}
		if ok {
			shells = append(shells, realShell{name: "dash", sh: dash, tools: tools})
		}
	} else {
		missing = append(missing, "dash")
	}
	bb := os.Getenv("AMNEZIA_BUSYBOX")
	if bb == "" {
		bb, _ = exec.LookPath("busybox")
	}
	if bb != "" {
		if _, err := os.Stat(bb); err != nil {
			missing = append(missing, "busybox ("+bb+": "+err.Error()+")")
			return shells, missing
		}
		tools := map[string]string{"sh": bb}
		for _, t := range core {
			tools[t] = bb // апплет: вызывается по имени ссылки
		}
		shells = append(shells, realShell{name: "busybox", sh: bb, shArg: []string{"sh"}, tools: tools})
	} else {
		missing = append(missing, "busybox")
	}
	return shells, missing
}

// shimDir — каталог, который становится ЕДИНСТВЕННЫМ PATH: ссылки на
// утилиты оболочки; drop — убрать; fail — заменить падающим скриптом;
// failMvTo — mv на этот файл падает (остальные mv — настоящие).
func (rs realShell) shimDir(t *testing.T, drop, fail, failMvTo string) string {
	t.Helper()
	d := t.TempDir()
	for name, target := range rs.tools {
		if name == drop {
			continue
		}
		p := filepath.Join(d, name)
		switch {
		case name == fail:
			writeExec(t, p, "#!/bin/sh\necho \""+name+": имитированный отказ\" >&2\nexit 1\n")
		case name == "mv" && failMvTo != "":
			real := realLink(t, d, name, target)
			writeExec(t, p, "#!/bin/sh\nfor a; do last=$a; done\ncase \"$last\" in */"+failMvTo+
				") echo \"mv: Permission denied\" >&2; exit 1;; esac\nexec \""+real+"\" \"$@\"\n")
		default:
			if err := os.Symlink(target, p); err != nil {
				t.Fatal(err)
			}
		}
	}
	return d
}

// realLink — ссылка на настоящую утилиту с ТЕМ ЖЕ именем в подкаталоге
// .real: апплет busybox выбирается по имени, под которым его вызвали.
func realLink(t *testing.T, d, name, target string) string {
	t.Helper()
	rd := filepath.Join(d, ".real")
	if err := os.MkdirAll(rd, 0o700); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(rd, name)
	if err := os.Symlink(target, p); err != nil {
		t.Fatal(err)
	}
	return p
}

func writeExec(t *testing.T, p, body string) {
	t.Helper()
	if err := os.WriteFile(p, []byte(body), 0o700); err != nil {
		t.Fatal(err)
	}
}

// commandTail — точная часть серверной команды, которую исполняет контейнер:
// всё после `docker exec -i <C> ` (timeout 50 sh -c '<скрипт>' метка каталог
// суммы). Оболочка «хоста» (dash) разбирает кавычки, как login-shell по SSH.
func commandTail(t *testing.T, script, label, dir, ww, wt string) string {
	t.Helper()
	cmd, err := CASWriteCommand(label, "c", dir, ww, wt)
	if err != nil {
		t.Fatal(err)
	}
	const cut = " docker exec -i c "
	i := strings.Index(cmd, cut)
	if i < 0 {
		t.Fatalf("нет %q в команде", cut)
	}
	tail := cmd[i+len(cut):]
	if script != CASWriteScript {
		tail = strings.Replace(tail, CASWriteScript, script, 1)
	}
	return tail
}

type shellRun struct {
	code   int
	stderr string
}

// runTail — исполняет хвост команды: разбор кавычек — host-оболочкой dash (или
// busybox sh), timeout и sh — из PATH-обёртки.
func (rs realShell) runTail(t *testing.T, tail, path string, stdin []byte) shellRun {
	t.Helper()
	args := append(append([]string{}, rs.shArg...), "-c", tail)
	cmd := exec.Command(rs.sh, args...)
	cmd.Env = []string{"PATH=" + path}
	cmd.Stdin = bytes.NewReader(stdin)
	var errb bytes.Buffer
	cmd.Stderr = &errb
	err := cmd.Run()
	code := 0
	if err != nil {
		ee, ok := err.(*exec.ExitError)
		if !ok {
			t.Fatalf("%s: запуск: %v", rs.name, err)
		}
		code = ee.ExitCode()
	}
	return shellRun{code: code, stderr: strings.TrimSpace(errb.String())}
}

type scenario struct {
	name  string
	check func(t *testing.T, rs realShell, script string) []string
}

// casDir — каталог «контейнера» с wg0.conf и (если tbl != nil) clientsTable.
func casDir(t *testing.T, wg, tbl []byte) string {
	t.Helper()
	d := asciiTemp(t)
	if err := os.WriteFile(filepath.Join(d, "wg0.conf"), wg, 0o600); err != nil {
		t.Fatal(err)
	}
	if tbl != nil {
		if err := os.WriteFile(filepath.Join(d, "clientsTable"), tbl, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return d
}

// asciiTemp — временный каталог с путём только из ASCII: CASWriteCommand
// принимает каталог по ^/[A-Za-z0-9_./-]+$, а t.TempDir() несёт имя подтеста.
func asciiTemp(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp("", "a3b-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(d) })
	return d
}

func readOpt(d, name string) ([]byte, bool) {
	b, err := os.ReadFile(filepath.Join(d, name))
	return b, err == nil
}

// expect — общая проверка исхода: код, файлы, отсутствие временных файлов.
func expect(d string, r shellRun, code int, stderrHas string, wgWant, tblWant []byte, tblPresent bool) []string {
	var bad []string
	if r.code != code {
		bad = append(bad, fmt.Sprintf("код %d, ждали %d (stderr %q)", r.code, code, r.stderr))
	}
	if stderrHas != "" && !strings.Contains(r.stderr, stderrHas) {
		bad = append(bad, fmt.Sprintf("stderr %q не содержит %q", r.stderr, stderrHas))
	}
	if wg, _ := readOpt(d, "wg0.conf"); !bytes.Equal(wg, wgWant) {
		bad = append(bad, "wg0.conf не тот")
	}
	tbl, ok := readOpt(d, "clientsTable")
	if ok != tblPresent || (ok && !bytes.Equal(tbl, tblWant)) {
		bad = append(bad, fmt.Sprintf("clientsTable не та (есть=%v, ждали есть=%v)", ok, tblPresent))
	}
	if left, _ := filepath.Glob(filepath.Join(d, "*"+CASTempInfix+"*")); len(left) != 0 {
		bad = append(bad, fmt.Sprintf("остались временные файлы: %v", left))
	}
	return bad
}

var (
	wgOld  = []byte("[Interface]\nPrivateKey = old\n")
	wgNew  = []byte("[Interface]\nPrivateKey = new\n\n[Peer]\nPublicKey = p\n")
	tblOld = []byte(`[{"clientId":"a"}]`)
	tblNew = []byte(`[{"clientId":"a"},{"clientId":"b"}]`)
)

func simpleRun(t *testing.T, rs realShell, script, path string, wg, tbl []byte, ww, wt string, inWg, inTbl []byte) (string, shellRun) {
	d := casDir(t, wg, tbl)
	tail := commandTail(t, script, CASLabelApply, d, ww, wt)
	return d, rs.runTail(t, tail, path, CASWriteStdin(inWg, inTbl))
}

func shellScenarios() []scenario {
	hOld, hTbl := sum64(wgOld, true), sum64(tblOld, true)
	return []scenario{
		{"запись при верных суммах", func(t *testing.T, rs realShell, script string) []string {
			d, r := simpleRun(t, rs, script, rs.shimDir(t, "", "", ""), wgOld, tblOld, hOld, hTbl, wgNew, tblNew)
			bad := expect(d, r, 0, "", wgNew, tblNew, true)
			for _, n := range []string{"wg0.conf", "clientsTable"} {
				if fi, err := os.Stat(filepath.Join(d, n)); err == nil && fi.Mode().Perm()&0o077 != 0 {
					bad = append(bad, fmt.Sprintf("%s: права %v, ждали без доступа группе и прочим (umask 077)", n, fi.Mode().Perm()))
				}
			}
			return bad
		}},
		{"устаревшая сумма wg0.conf", func(t *testing.T, rs realShell, script string) []string {
			d, r := simpleRun(t, rs, script, rs.shimDir(t, "", "", ""), wgOld, tblOld, sum64(wgNew, true), hTbl, wgNew, tblNew)
			return expect(d, r, 3, "changed: wg0.conf", wgOld, tblOld, true)
		}},
		{"устаревшая сумма только clientsTable", func(t *testing.T, rs realShell, script string) []string {
			d, r := simpleRun(t, rs, script, rs.shimDir(t, "", "", ""), wgOld, tblOld, hOld, sum64(tblNew, true), wgNew, tblNew)
			return expect(d, r, 3, "changed: clientsTable", wgOld, tblOld, true)
		}},
		{"rename: wg0.conf не переписывается", func(t *testing.T, rs realShell, script string) []string {
			d, r := simpleRun(t, rs, script, rs.shimDir(t, "", "", ""), wgOld, tblOld, hOld, hTbl, nil, tblNew)
			return expect(d, r, 0, "", wgOld, tblNew, true)
		}},
		{"absent, таблицы нет — создаётся", func(t *testing.T, rs realShell, script string) []string {
			d, r := simpleRun(t, rs, script, rs.shimDir(t, "", "", ""), wgOld, nil, hOld, CASAbsent, wgNew, tblNew)
			return expect(d, r, 0, "", wgNew, tblNew, true)
		}},
		{"absent заявлен, а таблица есть", func(t *testing.T, rs realShell, script string) []string {
			d, r := simpleRun(t, rs, script, rs.shimDir(t, "", "", ""), wgOld, tblOld, hOld, CASAbsent, wgNew, tblNew)
			return expect(d, r, 3, "changed: clientsTable", wgOld, tblOld, true)
		}},
		{"нет sha256sum — код 5", func(t *testing.T, rs realShell, script string) []string {
			d, r := simpleRun(t, rs, script, rs.shimDir(t, "sha256sum", "", ""), wgOld, tblOld, hOld, hTbl, wgNew, tblNew)
			return expect(d, r, 5, "missing tool: sha256sum", wgOld, tblOld, true)
		}},
		{"нет base64 — код 5", func(t *testing.T, rs realShell, script string) []string {
			d, r := simpleRun(t, rs, script, rs.shimDir(t, "base64", "", ""), wgOld, tblOld, hOld, hTbl, wgNew, tblNew)
			return expect(d, r, 5, "missing tool: base64", wgOld, tblOld, true)
		}},
		{"sha256sum падает — код 1, ничего не записано", func(t *testing.T, rs realShell, script string) []string {
			d, r := simpleRun(t, rs, script, rs.shimDir(t, "", "sha256sum", ""), wgOld, tblOld, hOld, hTbl, wgNew, tblNew)
			return expect(d, r, 1, "", wgOld, tblOld, true)
		}},
		{"второй mv падает — код 6, wg0.conf новый", func(t *testing.T, rs realShell, script string) []string {
			d, r := simpleRun(t, rs, script, rs.shimDir(t, "", "", "clientsTable"), wgOld, tblOld, hOld, hTbl, wgNew, tblNew)
			return expect(d, r, 6, "", wgNew, tblOld, true)
		}},
		{"строка base64 в 2 МБ проходит read", func(t *testing.T, rs realShell, script string) []string {
			big := bytes.Repeat([]byte("0123456789abcdef"), 2<<20/16)
			d, r := simpleRun(t, rs, script, rs.shimDir(t, "", "", ""), wgOld, tblOld, hOld, hTbl, wgNew, big)
			return expect(d, r, 0, "", wgNew, big, true)
		}},
		{"printf встроенный, данные не в /proc/*/cmdline (SEC R3)", func(t *testing.T, rs realShell, script string) []string {
			return secretNotInCmdline(t, rs, script)
		}},
		{"два писателя × 50 под flock: ни потерь, ни смеси", func(t *testing.T, rs realShell, script string) []string {
			return parallelWriters(t, rs, script)
		}},
	}
}

// secretNotInCmdline — (1) printf в этой оболочке встроенный: `command -v
// printf` печатает имя, а не путь; (2) обёртка base64 в момент декодирования
// просматривает /proc/*/cmdline на маркер из данных (сам текст base64 и
// раскодированный) — ни у одного процесса его быть не должно.
func secretNotInCmdline(t *testing.T, rs realShell, script string) []string {
	var bad []string
	path := rs.shimDir(t, "", "", "")
	out, err := exec.Command(rs.sh, append(append([]string{}, rs.shArg...), "-c", "command -v printf")...).Output()
	if err != nil || strings.TrimSpace(string(out)) != "printf" {
		bad = append(bad, fmt.Sprintf("printf не встроенный: command -v printf = %q (%v)", out, err))
	}
	marker := []byte("SECRETMARKER-A3B-PR2")
	// Размер подобран с двух сторон (измерено в WSL, посадка extprintf):
	// строка base64 БОЛЬШЕ буфера канала (64 КБ) — внешний printf, будь он в
	// скрипте, блокировался бы на записи и был бы жив в момент просмотра
	// /proc; и МЕНЬШЕ предела одного аргумента exec (MAX_ARG_STRLEN, 128 КБ)
	// — иначе внешний printf не запустился бы вовсе («Argument list too
	// long»), base64 получил бы пустой вход, и проверка молчала бы. 60 КБ
	// данных — около 80 КБ base64.
	payload := append(append([]byte("PrivateKey = "), marker...), bytes.Repeat([]byte("x"), 60<<10)...)
	enc := string(CASWriteStdin(payload, tblNew))
	encLine := strings.SplitN(enc, "\n", 2)[0]
	work := t.TempDir()
	report := filepath.Join(work, "found")
	// Образцы — в файле, а не в argv grep: иначе grep нашёл бы сам себя.
	pats := filepath.Join(work, "patterns")
	if err := os.WriteFile(pats, []byte(string(marker)+"\n"+encLine[:40]+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// обёртка base64: при каждом вызове ищет образцы в cmdline всех процессов
	shim := filepath.Join(path, "base64")
	_ = os.Remove(shim)
	real := realLink(t, path, "base64", rs.tools["base64"])
	writeExec(t, shim, "#!/bin/sh\nfor f in /proc/[0-9]*/cmdline; do tr '\\000' ' ' < \"$f\" 2>/dev/null; echo; done | "+
		"grep -F -f '"+pats+"' >> '"+report+"'\nexec \""+real+"\" \"$@\"\n")
	d := casDir(t, wgOld, tblOld)
	tail := commandTail(t, script, CASLabelApply, d, sum64(wgOld, true), sum64(tblOld, true))
	// tr и grep обёртке нужны из системы: PATH = обёртки + /usr/bin:/bin
	res := rs.runTail(t, tail, path+":/usr/bin:/bin", []byte(enc))
	if res.code != 0 {
		bad = append(bad, fmt.Sprintf("запись с маркером: код %d (%s)", res.code, res.stderr))
	}
	if got, _ := readOpt(d, "wg0.conf"); !bytes.Equal(got, payload) {
		bad = append(bad, fmt.Sprintf("wg0.conf после записи с маркером — %d байт вместо %d: данные не дошли", len(got), len(payload)))
	}
	if b, _ := os.ReadFile(report); len(bytes.TrimSpace(b)) != 0 {
		bad = append(bad, fmt.Sprintf("данные видны в /proc/*/cmdline: %q", b))
	}
	return bad
}

// parallelWriters — два писателя, по 50 итераций, каждый под настоящим
// flock на каталоге (как CASLockDir, со слэшем): читает файлы, дописывает
// строку в ОБА, пишет со сверкой. Инвариант: число строк = число успехов
// (нет потерянных обновлений), и wg0.conf с clientsTable равны (нет смеси).
func parallelWriters(t *testing.T, rs realShell, script string) []string {
	flock, err := exec.LookPath("flock")
	if err != nil {
		return []string{"нет flock — сценарий гонки не исполнен"}
	}
	path := rs.shimDir(t, "", "", "")
	d := casDir(t, nil, []byte{})
	lockDir := asciiTemp(t) + "/"
	var mu sync.Mutex
	success := 0
	other := map[int]int{} // коды вне {0, 3}: сколько раз
	var bad []string
	var wg sync.WaitGroup
	for w := 0; w < 2; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < 50; i++ {
				cur, _ := readOpt(d, "wg0.conf")
				curT, _ := readOpt(d, "clientsTable")
				line := []byte(fmt.Sprintf("w%d-%d\n", w, i))
				next := append(append([]byte{}, cur...), line...)
				nextT := append(append([]byte{}, curT...), line...)
				cmd, err := CASWriteCommand(CASLabelApply, "c", d, sum64(cur, true), sum64(curT, true))
				if err != nil {
					mu.Lock()
					bad = append(bad, err.Error())
					mu.Unlock()
					return
				}
				tail := cmd[strings.Index(cmd, " docker exec -i c ")+len(" docker exec -i c "):]
				if script != CASWriteScript {
					tail = strings.Replace(tail, CASWriteScript, script, 1)
				}
				c := exec.Command(flock, "-w", "15", "-E", "4", lockDir, rs.sh)
				c.Args = append(c.Args, rs.shArg...)
				c.Args = append(c.Args, "-c", tail)
				c.Env = []string{"PATH=" + path}
				c.Stdin = bytes.NewReader(CASWriteStdin(next, nextT))
				err = c.Run()
				code := 0
				if ee, ok := err.(*exec.ExitError); ok {
					code = ee.ExitCode()
				} else if err != nil {
					code = -1
				}
				mu.Lock()
				switch code {
				case 0:
					success++
				case 3:
				default:
					other[code]++
				}
				mu.Unlock()
			}
		}(w)
	}
	wg.Wait()
	if len(other) != 0 {
		bad = append(bad, fmt.Sprintf("коды вне {0, 3} (код: сколько раз): %v", other))
	}
	final, _ := readOpt(d, "wg0.conf")
	finalT, _ := readOpt(d, "clientsTable")
	lines := bytes.Count(final, []byte("\n"))
	if lines != success {
		bad = append(bad, fmt.Sprintf("строк в wg0.conf %d, успешных записей %d — потерянное обновление", lines, success))
	}
	if !bytes.Equal(final, finalT) {
		bad = append(bad, "wg0.conf и clientsTable разошлись — смесь двух записей")
	}
	if success == 0 {
		bad = append(bad, "ни одной успешной записи")
	}
	if left, _ := filepath.Glob(filepath.Join(d, "*"+CASTempInfix+"*")); len(left) != 0 {
		bad = append(bad, fmt.Sprintf("остались временные файлы: %v", left))
	}
	return bad
}

// shellsScript — скрипт под посадкой канарейки или настоящий. Посадка
// «nocheck» убирает строку сверки суммы wg0.conf — ищется по самому
// сравнению `"$hw" != "$ww"`, а не по всему тексту строки, чтобы пережить
// правку сообщений скрипта (PR-3). Не нашлась — ok=false, и тест падает
// громко: посадка, которая не применилась, — канарейка, которая молчит.
//
// Посадка «extprintf» (SEC-01 R-1): `printf %s "$W"` и `printf %s "$T"` →
// `env printf …` — данные попадают в argv внешнего процесса, и сценарий
// SEC R3 обязан это увидеть в /proc/*/cmdline.
func shellsScript() (script string, ok bool) {
	switch os.Getenv(shellsPlantEnv) {
	case "extprintf":
		s := strings.ReplaceAll(CASWriteScript, `printf %s "$`, `env printf %s "$`)
		return s, s != CASWriteScript
	case "nocheck":
	default:
		return CASWriteScript, true
	}
	lines := strings.Split(CASWriteScript, "\n")
	for i, l := range lines {
		if strings.Contains(l, `"$hw" != "$ww"`) {
			return strings.Join(append(lines[:i:i], lines[i+1:]...), "\n"), true
		}
	}
	return "", false
}

func TestCASScriptRealShells(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skipf("ОС %s: busybox sh и dash проверяются на Linux (CI, job checks linux); здесь скрипт исполняет fakesrv системным sh", runtime.GOOS)
	}
	shells, missing := findRealShells()
	if _, err := exec.LookPath("flock"); err != nil {
		missing = append(missing, "flock")
	}
	if len(missing) != 0 {
		if os.Getenv("CI") != "" {
			t.Fatalf("%s CI без %v — проверка в настоящих оболочках не выполнилась", shellsMarker, missing)
		}
		t.Skipf("нет %v (не CI): поставьте busybox и dash или задайте AMNEZIA_BUSYBOX", missing)
	}
	script, ok := shellsScript()
	if !ok {
		t.Fatalf("%s посадка %q не применилась к CASWriteScript (nocheck: нет строки сверки `\"$hw\" != \"$ww\"`; extprintf: нет `printf %%s \"$`)", shellsMarker, os.Getenv(shellsPlantEnv))
	}
	scen := shellScenarios()
	if os.Getenv(shellsPlantEnv) == "drop" {
		scen = scen[1:]
	}
	// Итог счёта (QA-01). go test по списку пакетов печатает у прошедшего
	// пакета только «ok», и t.Logf в журнале CI не виден; второй шаг go test
	// -v сторож ciguard запрещает (ровно один шаг go test, без -v) — и
	// правильно. Поэтому итог ещё дописывается в сводку job
	// ($GITHUB_STEP_SUMMARY — её GitHub даёт каждому шагу): на странице
	// прогона видно прямо, что сценарии исполнились.
	var tally []string
	defer func() {
		line := "исполнено сценариев скрипта записи: " + strings.Join(tally, ", ")
		t.Logf("%s", line)
		if p := os.Getenv("GITHUB_STEP_SUMMARY"); p != "" {
			f, err := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0o600)
			if err != nil {
				t.Errorf("%s сводка job %s не открылась: %v", shellsMarker, p, err)
				return
			}
			defer f.Close()
			if _, err := fmt.Fprintf(f, "- A3б, core: %s\n", line); err != nil {
				t.Errorf("%s сводка job: %v", shellsMarker, err)
			}
		}
	}()
	for _, rs := range shells {
		ran := 0
		defer func(name string, ran *int) { tally = append(tally, fmt.Sprintf("%d в %s", *ran, name)) }(rs.name, &ran)
		for _, sc := range scen {
			t.Run(rs.name+"/"+sc.name, func(t *testing.T) {
				ran++
				for _, msg := range sc.check(t, rs, script) {
					t.Errorf("%s %s: %s", shellsMarker, rs.name, msg)
				}
			})
		}
		for _, msg := range shellsVerdict(rs.name, ran) {
			t.Errorf("%s %s", shellsMarker, msg)
		}
	}
}

// shellsVerdict — число исполненных сценариев на оболочку ТОЧНО равно
// shellsWantScenarios: выпавший сценарий — нарушение.
func shellsVerdict(shell string, ran int) []string {
	if ran != shellsWantScenarios {
		return []string{fmt.Sprintf("%s: исполнено сценариев %d, ждали ровно %d", shell, ran, shellsWantScenarios)}
	}
	return nil
}

// TestCASScriptRealShellsCanary — проверка обязана уронить прогон, а не
// только найти дефект: дочерний процесс с посадкой обязан упасть с меткой
// вердикта в блоке провала (без -v: Logf прошедшего теста не печатается).
func TestCASScriptRealShellsCanary(t *testing.T) {
	if os.Getenv(shellsPlantEnv) != "" {
		t.Skip("дочерний процесс")
	}
	if runtime.GOOS != "linux" {
		t.Skipf("ОС %s: см. TestCASScriptRealShells", runtime.GOOS)
	}
	if _, missing := findRealShells(); len(missing) != 0 && os.Getenv("CI") == "" {
		t.Skipf("нет %v (не CI)", missing)
	}
	for _, plant := range []string{"nocheck", "drop", "extprintf"} {
		t.Run(plant, func(t *testing.T) {
			cmd := exec.Command(os.Args[0], "-test.run", "^TestCASScriptRealShells$", "-test.count=1")
			// Без GITHUB_STEP_SUMMARY: итог посаженного прогона не должен
			// попасть в сводку job рядом с настоящим.
			for _, kv := range os.Environ() {
				if !strings.HasPrefix(kv, "GITHUB_STEP_SUMMARY=") {
					cmd.Env = append(cmd.Env, kv)
				}
			}
			cmd.Env = append(cmd.Env, shellsPlantEnv+"="+plant)
			out, err := cmd.CombinedOutput()
			if err == nil {
				t.Fatalf("проверка в оболочках не уронила прогон на посадке %q:\n%s", plant, out)
			}
			if !failBlockHas(string(out), "TestCASScriptRealShells", shellsMarker) {
				t.Fatalf("прогон упал не по вердикту (нет %q в блоке провала) на посадке %q:\n%s", shellsMarker, plant, out)
			}
		})
	}
}

// failBlockHas — есть ли метка в блоке провала теста test (включая подтесты).
func failBlockHas(out, test, marker string) bool {
	in := false
	for _, l := range strings.Split(out, "\n") {
		trim := strings.TrimSpace(l)
		switch {
		case strings.HasPrefix(trim, "--- FAIL: "+test):
			in = true
		case strings.HasPrefix(trim, "--- PASS") || strings.HasPrefix(trim, "--- SKIP") || trim == "FAIL" || trim == "PASS":
			in = false
		case in && strings.Contains(l, ": "+marker):
			return true
		}
	}
	return false
}
