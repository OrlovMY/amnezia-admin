package core

// Сторож скриптов статистики (TRAFFIC-STATS). Устройство то же, что у
// core/provision_script_guard_test.go: запрещено всё, что не разрешено
// явно. Скрипт разбирается на простые команды, и каждая обязана совпасть с
// закрытым шаблоном argv своей программы; каждое перенаправление — с
// закрытым списком целей.
//
// Профили:
//   - collector — collect.sh: читать счётчики (docker ps, docker exec … show
//     … dump) и писать ТОЛЬКО в свой каталог (cd в него — первой командой,
//     дальше только голые имена своих файлов);
//   - readonly — status/read: ни одной записи;
//   - install — install/uninstall: только три своих пути и systemctl по
//     своему юниту.
//
// Не разбираем — значит, не пропускаем: обратная кавычка, обратная косая
// вне одинарных кавычек, незакрытая кавычка или скобка, «&» в фоне,
// неизвестный оператор — нарушение. Программы awk проверяются отдельно:
// system, getline, close, fflush, вывод в файл или в команду — нарушение.

import (
	"regexp"
	"strings"
	"testing"
)

type sgWord struct {
	text   string
	single bool // в слове была часть в одинарных кавычках
}

type sgRedir struct {
	op, target string
}

type sgCmd struct {
	words  []sgWord
	redirs []sgRedir
}

type sgLexer struct {
	s    string
	i    int
	cmds []sgCmd
	bad  []string
}

func (l *sgLexer) fail(why string) { l.bad = append(l.bad, why) }

// readDollarParen — после «$(»: разбор вложенной команды до парной «)».
func (l *sgLexer) parse(sub bool) {
	var cmd sgCmd
	var w strings.Builder
	inWord, single := false, false
	pendingRedir := ""
	endWord := func() {
		if inWord {
			if pendingRedir != "" {
				cmd.redirs = append(cmd.redirs, sgRedir{pendingRedir, w.String()})
				pendingRedir = ""
			} else {
				cmd.words = append(cmd.words, sgWord{w.String(), single})
			}
		}
		w.Reset()
		inWord, single = false, false
	}
	endCmd := func() {
		endWord()
		if pendingRedir != "" {
			l.fail("перенаправление без цели")
			pendingRedir = ""
		}
		if len(cmd.words) > 0 || len(cmd.redirs) > 0 {
			l.cmds = append(l.cmds, cmd)
		}
		cmd = sgCmd{}
	}
	for l.i < len(l.s) {
		c := l.s[l.i]
		switch {
		case c == '#' && !inWord:
			for l.i < len(l.s) && l.s[l.i] != '\n' {
				l.i++
			}
			continue
		case strings.HasPrefix(l.s[l.i:], "2>&1") && !inWord:
			l.i += 4
			continue
		case strings.HasPrefix(l.s[l.i:], "2>") && !inWord:
			endWord()
			pendingRedir = "2>"
			l.i += 2
			continue
		case c == '>' || c == '<':
			endWord()
			op := string(c)
			if strings.HasPrefix(l.s[l.i:], ">>") {
				op = ">>"
			}
			if strings.HasPrefix(l.s[l.i:], "<<") {
				l.fail("heredoc вне профиля")
				op = "<<"
			}
			if strings.HasPrefix(l.s[l.i:], ">&") || strings.HasPrefix(l.s[l.i:], ">|") || strings.HasPrefix(l.s[l.i:], "<>") {
				l.fail("неизвестный оператор перенаправления")
			}
			pendingRedir = op
			l.i += len(op)
			continue
		case c == ' ' || c == '\t':
			endWord()
		case c == '\n' || c == ';':
			endCmd()
		case c == '|' || c == '&':
			if strings.HasPrefix(l.s[l.i:], "||") || strings.HasPrefix(l.s[l.i:], "&&") {
				endCmd()
				l.i += 2
				continue
			}
			if c == '&' {
				l.fail("фоновый запуск «&»")
			}
			endCmd()
		case c == '`' || c == '\\':
			l.fail("недопустимый символ " + string(c))
		case c == '$' && strings.HasPrefix(l.s[l.i:], "$(("):
			l.fail("арифметика $(( ))")
		case c == '$' && strings.HasPrefix(l.s[l.i:], "$("):
			l.i += 2
			l.parse(true)
			w.WriteString("$S")
			inWord = true
			continue
		case c == '(' || c == '{' && !inWord:
			l.fail("группа команд")
		case c == ')':
			if !sub {
				l.fail("непарная «)»")
				break
			}
			endCmd()
			l.i++
			return
		case c == '\'':
			l.i++
			inWord, single = true, true
			closed := false
			for l.i < len(l.s) {
				if l.s[l.i] == '\'' {
					closed = true
					break
				}
				w.WriteByte(l.s[l.i])
				l.i++
			}
			if !closed {
				l.fail("незакрытая одинарная кавычка")
			}
		case c == '"':
			l.i++
			inWord = true
			closed := false
			for l.i < len(l.s) {
				q := l.s[l.i]
				if q == '"' {
					closed = true
					break
				}
				if q == '`' || q == '\\' {
					l.fail("недопустимый символ в кавычках " + string(q))
				}
				if strings.HasPrefix(l.s[l.i:], "$(") {
					l.i += 2
					l.parse(true)
					w.WriteString("$S")
					continue
				}
				w.WriteByte(q)
				l.i++
			}
			if !closed {
				l.fail("незакрытая кавычка")
			}
		default:
			w.WriteByte(c)
			inWord = true
		}
		l.i++
	}
	if sub {
		l.fail("незакрытая $(")
	}
	endCmd()
}

var (
	sgAssign = regexp.MustCompile(`^([A-Za-z_][A-Za-z0-9_]*)=`)
	// sgAwkBad — что запрещено в программе awk: запуск команд, чтение
	// файлов в обход аргументов, вывод в файл или в команду.
	sgAwkBad = []*regexp.Regexp{
		regexp.MustCompile(`system`),
		regexp.MustCompile(`getline`),
		regexp.MustCompile(`close`),
		regexp.MustCompile(`fflush`),
		regexp.MustCompile(`(^|[^|])\|([^|]|$)`),
		regexp.MustCompile(`printf?[^;\n}]*>`),
		regexp.MustCompile(`'`),
	}
)

var sgKeywords = map[string]bool{"if": true, "then": true, "else": true, "fi": true, "do": true, "done": true, "!": true}

// statsOwnFiles — единственные цели записи сборщика (голые имена в его
// каталоге).
var statsOwnFiles = map[string]bool{
	"snapshots.log": true, "daily.log": true, "block.tmp": true,
	"daily.new": true, "snap.new": true, "FULL": true,
}

var statsVarNames = map[string]bool{
	"g0": true, "ts": true, "names": true, "c": true, "r": true, "t": true, "i": true,
	"found": true, "out": true, "blk": true, "sz": true, "ds": true, "gen": true, "p": true,
}

func sgAwkViolations(prog string) []string {
	var bad []string
	for _, re := range sgAwkBad {
		if re.MatchString(prog) {
			bad = append(bad, "awk: запрещено "+re.String())
		}
	}
	return bad
}

func sgTexts(ws []sgWord) []string {
	var a []string
	for _, w := range ws {
		a = append(a, w.text)
	}
	return a
}

func sgEq(a []string, want ...string) bool {
	if len(a) != len(want) {
		return false
	}
	for i := range want {
		if a[i] != want[i] {
			return false
		}
	}
	return true
}

func sgAllOwn(a []string) bool {
	for _, x := range a {
		if !statsOwnFiles[x] {
			return false
		}
	}
	return len(a) > 0
}

// sgCollectorArgv — закрытый список команд collect.sh.
func sgCollectorArgv(ws []sgWord) []string {
	a := sgTexts(ws)
	switch a[0] {
	case "set":
		if sgEq(a, "set", "-u") {
			return nil
		}
	case "umask":
		if sgEq(a, "umask", "022") {
			return nil
		}
	case "cd":
		if sgEq(a, "cd", StatsDir) {
			return nil
		}
	case "[", "printf", "continue", ":":
		return nil
	case "exit":
		if len(a) <= 2 {
			return nil
		}
	case "date":
		if sgEq(a, "date", "+%s") {
			return nil
		}
	case "docker":
		if sgEq(a, "docker", "ps", "--format", "{{.Names}}") || sgEq(a, "docker", "exec", "$c", "$t", "show", "$i", "dump") {
			return nil
		}
	case "wc":
		if sgEq(a, "wc", "-c") {
			return nil
		}
	case "cat", "mv":
		if sgAllOwn(a[1:]) && (a[0] == "cat" || len(a) == 3) {
			return nil
		}
	case "rm":
		if len(a) >= 3 && a[1] == "-f" && sgAllOwn(a[2:]) {
			return nil
		}
	case "awk":
		j := 1
		for j+1 < len(a) && a[j] == "-v" {
			if !regexp.MustCompile(`^(ts|c|add|gen)=`).MatchString(a[j+1]) {
				return []string{"awk -v вне списка: " + a[j+1]}
			}
			j += 2
		}
		if j >= len(a) || !ws[j].single {
			return []string{"awk без программы в одинарных кавычках"}
		}
		bad := sgAwkViolations(a[j])
		rest := a[j+1:]
		if len(rest) > 1 || (len(rest) == 1 && rest[0] != "daily.log" && rest[0] != "snapshots.log") {
			bad = append(bad, "awk: файл вне списка "+strings.Join(rest, " "))
		}
		return bad
	}
	return []string{"вне закрытого списка: " + strings.Join(a, " ")}
}

func sgReadonlyArgv(ws []sgWord) []string {
	a := sgTexts(ws)
	switch a[0] {
	case "echo", "[":
		return nil
	case "cksum":
		if len(a) == 1 {
			return nil
		}
	case "cat":
		if sgEq(a, "cat", "$p") || sgEq(a, "cat", StatsDir+"/FULL") {
			return nil
		}
	case "systemctl":
		if sgEq(a, "systemctl", "is-active", StatsUnit+".timer") {
			return nil
		}
	}
	return []string{"вне закрытого списка: " + strings.Join(a, " ")}
}

var statsInstallPaths = map[string]bool{StatsScriptPath: true, StatsServicePath: true, StatsTimerPath: true}

func sgInstallArgv(ws []sgWord) []string {
	a := sgTexts(ws)
	newOf := func(p string) bool {
		return statsInstallPaths[strings.TrimSuffix(p, ".new")] && strings.HasSuffix(p, ".new")
	}
	switch a[0] {
	case "set":
		if sgEq(a, "set", "-e") {
			return nil
		}
	case "umask":
		if sgEq(a, "umask", "022") {
			return nil
		}
	case "mkdir":
		if sgEq(a, "mkdir", "-p", StatsDir) {
			return nil
		}
	case "echo", "true":
		return nil
	case "cat":
		if len(a) == 1 {
			return nil
		}
	case "chmod":
		if len(a) == 3 && (a[1] == "0755" || a[1] == "0644") && newOf(a[2]) {
			return nil
		}
	case "mv":
		if len(a) == 3 && newOf(a[1]) && a[2] == strings.TrimSuffix(a[1], ".new") {
			return nil
		}
	case "rm":
		if len(a) >= 3 && a[1] == "-f" {
			ok := true
			for _, p := range a[2:] {
				ok = ok && statsInstallPaths[p]
			}
			if ok {
				return nil
			}
		}
	case "systemctl":
		if sgEq(a, "systemctl", "daemon-reload") ||
			sgEq(a, "systemctl", "enable", "--now", StatsUnit+".timer") ||
			sgEq(a, "systemctl", "disable", "--now", StatsUnit+".timer") ||
			sgEq(a, "systemctl", "stop", StatsUnit+".service") {
			return nil
		}
	}
	return []string{"вне закрытого списка: " + strings.Join(a, " ")}
}

type sgProfile int

const (
	sgCollector sgProfile = iota
	sgReadonly
	sgInstall
)

// sgStripHeredocs — профиль install: тела heredoc с кавычками вокруг
// разделителя — данные, а не команды. Сама строка «cat > X <<'D'»
// остаётся (без оператора heredoc), а содержимое проверяется отдельно
// (TestStatsInstallWritesOnlyOwnFiles).
func sgStripHeredocs(s string) string {
	var out []string
	delim := ""
	for _, line := range strings.Split(s, "\n") {
		if delim != "" {
			if line == delim {
				delim = ""
			}
			continue
		}
		if i := strings.Index(line, " <<'"); i >= 0 && strings.HasSuffix(line, "'") {
			delim = line[i+4 : len(line)-1]
			line = line[:i]
		}
		out = append(out, line)
	}
	return strings.Join(out, "\n")
}

func statsScriptViolations(script string, prof sgProfile) []string {
	if prof == sgInstall {
		script = sgStripHeredocs(script)
	}
	l := &sgLexer{s: script}
	l.parse(false)
	bad := l.bad
	cdSeen := false
	for _, cmd := range l.cmds {
		for _, r := range cmd.redirs {
			switch {
			case r.op == "2>":
				if r.target != "/dev/null" {
					bad = append(bad, "stderr в «"+r.target+"»")
				}
			case prof == sgCollector:
				if !statsOwnFiles[r.target] {
					bad = append(bad, "перенаправление вне своего каталога: "+r.op+r.target)
				}
				if !cdSeen {
					bad = append(bad, "перенаправление до cd в свой каталог")
				}
			case prof == sgReadonly:
				if r.op != "<" || r.target != "$f" {
					bad = append(bad, "запись в профиле только-чтения: "+r.op+r.target)
				}
			case prof == sgInstall:
				if r.op != ">" || !statsInstallPaths[strings.TrimSuffix(r.target, ".new")] || !strings.HasSuffix(r.target, ".new") {
					bad = append(bad, "запись вне своих путей: "+r.op+r.target)
				}
			}
		}
		ws := cmd.words
		for len(ws) > 0 && sgKeywords[ws[0].text] {
			ws = ws[1:]
		}
		if len(ws) == 0 {
			continue
		}
		if ws[0].text == "for" {
			if len(ws) < 3 || !statsVarNames[ws[1].text] && ws[1].text != "spec" && ws[1].text != "x" && ws[1].text != "f" || ws[2].text != "in" {
				bad = append(bad, "for вне шаблона")
			}
			continue
		}
		if m := sgAssign.FindStringSubmatch(ws[0].text); m != nil {
			if !statsVarNames[m[1]] {
				bad = append(bad, "присваивание вне закрытого списка имён: "+ws[0].text)
			}
			if len(ws) > 1 {
				bad = append(bad, "команда после присваивания: "+strings.Join(sgTexts(ws), " "))
			}
			continue
		}
		switch prof {
		case sgCollector:
			if ws[0].text == "cd" {
				if cdSeen {
					bad = append(bad, "второй cd")
				}
				cdSeen = true
			} else if !cdSeen && ws[0].text != "set" && ws[0].text != "umask" && ws[0].text != "exit" {
				bad = append(bad, "команда до cd в свой каталог: "+ws[0].text)
			}
			bad = append(bad, sgCollectorArgv(ws)...)
		case sgReadonly:
			bad = append(bad, sgReadonlyArgv(ws)...)
		case sgInstall:
			bad = append(bad, sgInstallArgv(ws)...)
		}
	}
	if prof == sgCollector && !cdSeen {
		bad = append(bad, "нет cd в свой каталог")
	}
	return bad
}

func TestStatsScriptClosedList(t *testing.T) {
	cases := []struct {
		name   string
		script string
		prof   sgProfile
	}{
		{"collect.sh", StatsCollectorScript(), sgCollector},
		{"status", statsStatusScript(), sgReadonly},
		{"read", statsReadScript(), sgReadonly},
		{"install", statsInstallScript(), sgInstall},
		{"uninstall", statsUninstallScript(), sgInstall},
	}
	for _, c := range cases {
		if v := statsScriptViolations(c.script, c.prof); len(v) > 0 {
			t.Errorf("%s: нарушения сторожа: %q", c.name, v)
		}
	}

	// Канарейки: каждая обязана споткнуть сторож. Вставляются в НАСТОЯЩИЙ
	// скрипт (после строки cd), чтобы сторож не мог пропустить их из-за
	// «скрипт кончился раньше».
	base := StatsCollectorScript()
	anchor := "if [ -e FULL ]; then exit 0; fi\n"
	if !strings.Contains(base, anchor) {
		t.Fatal("якорь канареек не найден в collect.sh")
	}
	for _, canary := range []string{
		`touch /tmp/x`,
		`printf x > /etc/motd`,
		`printf x >> ../x`,
		`printf x >/tmp/x`,
		`cat /etc/shadow`,
		`cat snapshots.log > /tmp/x`,
		`rm -f /etc/passwd`,
		`rm -rf snapshots.log`,
		`mv snapshots.log /tmp/x`,
		`docker run x`,
		`docker exec "$c" sh -c id`,
		`docker exec "$c" "$t" set "$i" peer x remove`,
		`awk 'BEGIN { system("id") }'`,
		`awk 'BEGIN { print "x" > "/tmp/f" }'`,
		`awk 'BEGIN { printf "x" | "sh" }'`,
		`awk 'BEGIN { while (("id" | getline l) > 0) print l }'`,
		`awk 'BEGIN { print 1 }' /etc/shadow`,
		`awk -v PATH=/tmp 'BEGIN { print 1 }'`,
		`awk "BEGIN { print 1 }"`,
		"printf `id`",
		`printf "$(touch /tmp/x)"`,
		`x=$(rm -rf /)`,
		`PATH=/tmp`,
		`c=1 docker ps`,
		`cd /tmp`,
		`sleep 1 &`,
		`( cd /tmp )`,
		`printf x 2>/tmp/err`,
		`printf x >| snapshots.log`,
		`eval x`,
		`. ./x`,
		`systemctl stop docker`,
		`printf "\x"`,
	} {
		sc := strings.Replace(base, anchor, anchor+canary+"\n", 1)
		if len(statsScriptViolations(sc, sgCollector)) == 0 {
			t.Errorf("канарейка не поймана: %s", canary)
		}
	}
	// Запись до cd — тоже нарушение (порядок важен: до cd «snapshots.log»
	// — файл в чужом каталоге).
	early := strings.Replace(base, "set -u\n", "set -u\nprintf x > snapshots.log\n", 1)
	if len(statsScriptViolations(early, sgCollector)) == 0 {
		t.Error("канарейка не поймана: запись до cd")
	}
	for _, canary := range []string{`echo x > /tmp/x`, `cat /etc/shadow`, `rm -f x`, `systemctl stop x`} {
		if len(statsScriptViolations(statsReadScript()+canary+"\n", sgReadonly)) == 0 {
			t.Errorf("канарейка только-чтения не поймана: %s", canary)
		}
	}
	for _, canary := range []string{`rm -f /etc/passwd`, `cat > /etc/x.new`, `systemctl enable --now evil.timer`, `mv /tmp/x.new /etc/x`, `chmod 4755 ` + StatsScriptPath + `.new`} {
		if len(statsScriptViolations(statsInstallScript()+canary+"\n", sgInstall)) == 0 {
			t.Errorf("канарейка установки не поймана: %s", canary)
		}
	}
}

// TestStatsInstallWritesOnlyOwnFiles — тела heredoc в установке ровно те
// три файла, что показываются человеку перед подтверждением, и
// разделитель не встречается в их тексте (иначе файл оборвался бы, а
// остаток выполнился бы как команды).
func TestStatsInstallWritesOnlyOwnFiles(t *testing.T) {
	sc := statsInstallScript()
	for _, f := range StatsInstallFiles() {
		if strings.Contains(f.Content, statsHeredoc) {
			t.Errorf("%s: в тексте встречается разделитель heredoc", f.Path)
		}
		block := "cat > " + f.Path + ".new <<'" + statsHeredoc + "'\n" + f.Content + statsHeredoc + "\n"
		if !strings.Contains(sc, block) {
			t.Errorf("%s: в установке не тот текст, что показывается человеку", f.Path)
		}
	}
	if n := strings.Count(sc, "<<'"); n != len(StatsInstallFiles()) {
		t.Errorf("heredoc в установке: %d, файлов: %d", n, len(StatsInstallFiles()))
	}
	for _, w := range []string{"snapshots.log", "daily.log"} {
		if strings.Contains(sgStripHeredocs(sc), w) || strings.Contains(statsUninstallScript(), w) {
			t.Errorf("установка/снятие трогает данные %s", w)
		}
	}
}
