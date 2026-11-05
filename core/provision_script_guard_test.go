package core

// Сторож скриптов проб предпроверки (ревью р2, N1). Закрытый список команд
// (provAllowed) сравнивает с теми же константами, из которых команды
// собраны, и правку САМОГО скрипта не видит. Здесь скрипт разбирается на
// простые команды (лексер: кавычки, $( … ), ; | & и перевод строки), и
// каждая команда обязана совпасть с ЗАКРЫТЫМ шаблоном argv своей программы.
//
// Устройство, а не перечень: запрещено всё, что не разрешено явно.
//   - программа вне таблицы (touch, tee, rm, …) — нарушение;
//   - у разрешённой программы argv сверяется целиком (command — только -v,
//     «.» — только /etc/os-release, docker — только version/ps с --format,
//     sed — только s/^/КЛЮЧ=/);
//   - перенаправление вне кавычек (любой символ > или < в слове) — нарушение,
//     кроме ровно «>/dev/null» и «2>&1»; так ловятся x>/f, 1>/f, >>/f, </f;
//   - обратные кавычки, одинарные кавычки, незакрытые кавычки или скобки —
//     нарушение (не разбираем — значит, не пропускаем);
//   - присваивание допустимо только без команды после него;
//   - подстановки $( … ) проверяются как отдельные команды по тем же
//     правилам, и внутри кавычек тоже.

import (
	"regexp"
	"strings"
	"testing"
)

type provWord struct {
	text  string
	redir bool // в слове был > или < вне кавычек
}

type provLexer struct {
	s    string
	i    int
	cmds [][]provWord
	bad  []string
}

func (l *provLexer) fail(why string) { l.bad = append(l.bad, why) }

// parse — разбор до конца строки (sub=false) или до парной «)» (sub=true).
func (l *provLexer) parse(sub bool) {
	var cmd []provWord
	var w strings.Builder
	inWord, redir := false, false
	endWord := func() {
		if inWord {
			cmd = append(cmd, provWord{w.String(), redir})
		}
		w.Reset()
		inWord, redir = false, false
	}
	endCmd := func() {
		endWord()
		if len(cmd) > 0 {
			l.cmds = append(l.cmds, cmd)
		}
		cmd = nil
	}
	for l.i < len(l.s) {
		c := l.s[l.i]
		switch {
		case strings.HasPrefix(l.s[l.i:], "2>&1"):
			endWord()
			l.i += 4
			continue
		case c == ' ' || c == '\t':
			endWord()
		case c == ';' || c == '|' || c == '&' || c == '\n':
			endCmd()
		case c == '`' || c == '\'' || c == '\\':
			l.fail("недопустимый символ " + string(c))
		case c == '$' && strings.HasPrefix(l.s[l.i:], "$("):
			l.i += 2
			l.parse(true)
			w.WriteString("$S")
			inWord = true
			continue
		case c == ')':
			if !sub {
				l.fail("непарная «)»")
				break
			}
			endCmd()
			l.i++
			return
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
			if c == '>' || c == '<' {
				redir = true
			}
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
	provAssign  = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*=`)
	provSedExpr = regexp.MustCompile(`^s/\^/[A-Z]+=/$`)
	provFormat  = regexp.MustCompile(`^\{\{\.[A-Za-z.]+\}\}(\|\{\{\.[A-Za-z.]+\}\})*$`)
	provTag     = regexp.MustCompile(`^aa-(prov|diag)-[a-z0-9]+$`)
)

// provArgvOK — закрытый шаблон argv для каждой программы.
func provArgvOK(a []string) bool {
	eq := func(want ...string) bool {
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
	switch a[0] {
	case ":":
		return len(a) == 2 && provTag.MatchString(a[1])
	case "echo", "[":
		return true // печать и сравнение; перенаправления проверены отдельно
	case ".":
		return eq(".", "/etc/os-release")
	case "command":
		return len(a) == 3 && a[1] == "-v"
	case "uname":
		return eq("uname", "-r") || eq("uname", "-m")
	case "id":
		return eq("id", "-u")
	case "sudo":
		return eq("sudo", "-n", "true")
	case "ss":
		return eq("ss", "-lntu")
	case "df":
		return len(a) == 3 && a[1] == "-Pk" && a[2] == "$p"
	case "cat":
		return eq("cat", "/etc/docker/daemon.json")
	case "head", "tail":
		return len(a) == 3 && a[1] == "-n" && a[2] == "1"
	case "sed":
		return len(a) == 2 && provSedExpr.MatchString(a[1])
	case "docker":
		return (len(a) == 4 && (a[1] == "version" || a[1] == "info") && a[2] == "--format" && provFormat.MatchString(a[3])) ||
			(len(a) == 5 && a[1] == "ps" && a[2] == "-a" && a[3] == "--format" && provFormat.MatchString(a[4]))
	}
	return false
}

// provVarNames — имена переменных, которые скрипты проб вправе присваивать.
var provVarNames = map[string]bool{"u": true, "o": true, "p": true, "c": true, "r": true, "rc": true, "j": true}

var provKeywords = map[string]bool{"if": true, "then": true, "else": true, "fi": true, "elif": true, "!": true}

func provScriptViolations(script string) []string {
	l := &provLexer{s: script}
	l.parse(false)
	bad := l.bad
	for _, cmd := range l.cmds {
		var a []string
		for _, w := range cmd {
			if w.redir {
				if w.text != ">/dev/null" {
					bad = append(bad, "перенаправление «"+w.text+"»")
				}
				continue
			}
			a = append(a, w.text)
		}
		for len(a) > 0 && provKeywords[a[0]] {
			a = a[1:]
		}
		if len(a) == 0 {
			continue
		}
		if provAssign.MatchString(a[0]) {
			// N5: имена — закрытый список (PATH=, IFS= и т. п. меняют смысл
			// следующих команд).
			if name, _, _ := strings.Cut(a[0], "="); !provVarNames[name] {
				bad = append(bad, "присваивание вне закрытого списка имён: "+a[0])
			}
			if len(a) > 1 {
				bad = append(bad, "команда после присваивания: "+strings.Join(a, " "))
			}
			continue
		}
		if !provArgvOK(a) {
			bad = append(bad, "вне закрытого списка: "+strings.Join(a, " "))
		}
	}
	return bad
}

func TestProvScriptsClosedProgramList(t *testing.T) {
	for _, sc := range []string{provOSScript, provKernelScript, provSudoScript, provDockerScript, provCtrScript, provPortsScript, provDiskScript} {
		if v := provScriptViolations(sc); len(v) > 0 {
			t.Errorf("в пробе нарушение: %q\nскрипт: %s", v, sc)
		}
	}
	// Канарейки: сторож обязан споткнуться о каждую. Первые — из ревью р1 и р2,
	// остальные — тот же класс другими путями.
	for _, canary := range []string{
		` echo x; touch /tmp/x; echo END`,
		` docker start x; echo END`,
		` echo x > /etc/motd; echo END`,
		` o=$(ss -lntu 2>&1); sed -i "s/a/b/" /etc/hosts; echo END`,
		` command touch /tmp/x`,
		` echo x>/tmp/x`,
		` echo x 1>/tmp/x`,
		` . /tmp/evil`,
		` echo x >>/tmp/x`,
		` echo x | tee /tmp/x`,
		` o=$(touch /tmp/x); echo END`,
		` echo "$(rm -rf /tmp/x)"`,
		" echo `touch /tmp/x`",
		` x=1 touch /tmp/f`,
		` sed "s/^/A=/w /tmp/f"`,
		` docker ps -a --format "{{.Names}}" >/tmp/f`,
		` docker run x`,
		` sudo -n rm /x`,
		` echo "$(echo x`,
		` echo x</etc/shadow`,
		` PATH=/tmp; ss -lntu`,
		` IFS=x`,
		` j=$(cat /etc/shadow)`,
		` cat /etc/docker/daemon.json >/etc/docker/x`,
		` r=$(docker info --format "{{.DockerRootDir}}" >/tmp/f)`,
	} {
		if len(provScriptViolations(canary)) == 0 {
			t.Errorf("канарейка не поймана: %s", canary)
		}
	}
}
