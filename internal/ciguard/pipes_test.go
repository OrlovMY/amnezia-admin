// Файл pipes_test.go — сторож формы «ранний выход читателя конвейера»
// (раунд SIGPIPE, main f0febbd; переделан в закрытый список — долги CI,
// 30.09.2026).
//
// Что случилось. `printf '%s\n' "${subjects[@]}" | grep -qxF -- "$f"` в шаге
// «Субъекты аттестации». grep -q выходит на первом совпадении; если printf
// ещё пишет, он получает SIGPIPE (код 141), а под pipefail (раннер исполняет
// run: как `bash -eo pipefail`, наши тела сами ставят set -euo pipefail)
// провал пишущего становится провалом всего конвейера: «входит» читается как
// «не входит». Сбой плавающий — зависит от того, успел ли printf дописать до
// выхода grep.
//
// Почему закрытый список. Первая версия сторожа перечисляла плохих читателей
// (grep -q/-m, head). Ревью QA-01 обошло её тринадцатью формами: `|& grep -q`,
// egrep/fgrep, `grep -m1`, `LC_ALL=C grep`, `env grep`, `sed q`,
// `sed '/x/{p;q}'`, `awk '…exit'`, `grep -l`, `cmp`, `read -r v`,
// `xargs grep -q`, перенос строки после `|`. Список плохого всегда неполон
// (память closed-list-over-blacklist), поэтому правило перевёрнуто:
//
// КАЖДОЕ звено справа от `|` или `|&` в теле run: обоих workflow и в
// scripts/*.sh — из закрытого списка pipeReaders ниже, с флагами из его же
// закрытого списка, без операндов-файлов (иначе читается файл, а не
// конвейер) и без перенаправления входа. Всё незнакомое — красное, включая
// префиксы `env`, `VAR=`, `command`, `\`, `xargs`, `!`, подоболочку и
// группу `{ …; }`, `while`/`read`. Функция допустима читателем, только если
// определена в том же источнике и ПЕРВАЯ команда её тела сама проходит
// закрытый список.
//
// Разбор. Текст разбирается мини-лексером bash (shParse), а не регулярным
// выражением по строкам: так видны `|&`, перенос строки после `|` и `\`+
// перевод строки, конвейеры внутри "$(…)", `<(…)` и обратных кавычек, и не
// видны `|` в кавычках, в шаблонах case, внутри [[ … ]], $(( … )), ${ … } и
// ${{ … }}, в heredoc и комментариях. Текст, который лексер не смог
// разобрать (незакрытая кавычка или скобка), — красный: не разобрано —
// значит не доказано.
//
// ГРАНИЦА (названа поимённо, всё прочее проходящее — дыра):
//   - GNU grep на ДВОИЧНОМ вводе печатает «Binary file matches» и может
//     прекратить чтение. Наши входы grep в конвейере — текст (список
//     зависимостей go, вывод awk).
//   - Функция проверяется по первой команде тела; `f() { cat >/dev/null; … }`
//     законно проходит, и это верно: cat дочитал ввод.
//   - Код, переданный оболочке (строкой -c, heredoc, here-string, через
//     source/. или по имени из переменной), лексер не разбирает. Поэтому
//     это НЕ граница, а закрытый список (AU-LOGIC F1, раунд 3): запуск
//     bash/sh/dash/zsh/ksh, source, `.` — только точной записью из
//     allowedShellCalls и без перенаправления входа; команда с подстановкой
//     в имени — только из allowedDynCmds; eval — красный всегда; оболочка
//     аргументом (find -exec sh, xargs bash) и после обёрток env/exec/… —
//     красная. Определение функции с именем читателя, оболочки или
//     grep/head/sed/awk (в любой форме, включая `function` и тело `( )`) и
//     alias — красные (F2).
//   - Обёртки перечислены в shellWrappers; команда, запускающая свой
//     аргумент и не названная там (например, `ssh host cmd`), не
//     опознаётся. В файлах таких нет.
//   - Тела run: в других ключах (shell:, defaults) не бывают — ключи
//     закрыты TestWorkflowKeysClosedList.
package ciguard

import (
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// --- лексер --------------------------------------------------------------

type shWord struct {
	raw, lit string
	dyn      bool // есть подстановка $…, `…`, <(…) — значение неизвестно
	quoted   bool // есть кавычки или \ — это не голое имя команды
}

// shCmd — одна простая команда, стоящая справа от `|`/`|&`.
type shCmd struct {
	op      string // "|" или "|&"
	words   []shWord
	inRedir string // перенаправление входа, если есть
	line    int
}

type heredoc struct {
	delim string
	strip bool
}

type shParse struct {
	s       string
	i, line int
	readers []shCmd
	cmds    []shCmd          // все простые команды — для закрытого списка вызовов оболочки
	defs    []shDef          // определения функций в форме имя() — для запрета переопределения
	funcs   map[string]shCmd // имя функции → первая команда её тела
	errs    []string
	pending []heredoc
	funcDef string // имя() разобрано, ждём {
	funcArm string // { тела функции открыта, ждём первую команду
	bt      int    // глубина `…`: там обратная кавычка закрывает, а не открывает
}

func parseShell(src string) *shParse {
	src = strings.ReplaceAll(src, "\r\n", "\n")
	p := &shParse{s: src, line: 1, funcs: map[string]shCmd{}}
	p.list(0)
	if p.i < len(p.s) {
		p.errorf("лишняя «%c»", p.s[p.i])
	}
	return p
}

func (p *shParse) errorf(format string, args ...any) {
	p.errs = append(p.errs, fmt.Sprintf("строка %d: ", p.line)+fmt.Sprintf(format, args...))
	p.i = len(p.s) // дальше не разбираем: всё после ошибки — не доказано
}

func (p *shParse) peek(k int) byte {
	if p.i+k < len(p.s) {
		return p.s[p.i+k]
	}
	return 0
}

func (p *shParse) adv() byte {
	c := p.s[p.i]
	p.i++
	if c == '\n' {
		p.line++
	}
	return c
}

func (p *shParse) has(pre string) bool { return strings.HasPrefix(p.s[p.i:], pre) }

var shKeywords = map[string]bool{
	"if": true, "then": true, "else": true, "elif": true, "fi": true,
	"do": true, "done": true, "while": true, "until": true,
	"{": true, "}": true, "!": true, "time": true,
}

type caseFrame struct{ inHeader, inPattern bool }

// list разбирает последовательность команд до term (0 — конец текста,
// ')' — конец $( ), <( ), подоболочки, '`' — конец обратных кавычек).
func (p *shParse) list(term byte) {
	var cur shCmd
	started := false
	pipeOp := ""
	var cases []*caseFrame
	topCase := func() *caseFrame {
		if len(cases) == 0 {
			return nil
		}
		return cases[len(cases)-1]
	}
	endCmd := func() {
		if started {
			if cur.line == 0 {
				cur.line = p.line
			}
			p.cmds = append(p.cmds, cur)
			if pipeOp != "" {
				cur.op = pipeOp
				p.readers = append(p.readers, cur)
			}
			if p.funcArm != "" {
				p.funcs[p.funcArm] = cur
				p.funcArm = ""
			}
			pipeOp = ""
		}
		cur = shCmd{}
		started = false
	}
	// keyword — зарезервированное слово или скобка в начале команды.
	keyword := func(w string) {
		if pipeOp != "" {
			cur = shCmd{words: []shWord{{raw: w, lit: w}}, line: p.line}
			started = true
			endCmd()
		}
	}
	for p.i < len(p.s) {
		if p.errs != nil {
			return
		}
		c := p.s[p.i]
		if fc := topCase(); fc != nil && fc.inPattern && !started {
			// шаблоны case: `a | b)` — `|` здесь не конвейер
			switch {
			case c == ' ' || c == '\t' || c == '\n':
				p.adv()
				p.newlineHeredocs(c)
				continue
			case c == '#':
				p.skipComment()
				continue
			case p.has("esac") && !isWordChar(p.peek(4)):
				p.i += 4
				cases = cases[:len(cases)-1]
				continue
			}
			p.casePattern()
			fc.inPattern = false
			continue
		}
		switch {
		case c == term && term != 0:
			endCmd()
			return
		case c == ' ' || c == '\t':
			p.adv()
		case c == '\\' && p.peek(1) == '\n':
			p.adv()
			p.adv()
		case c == '\n':
			p.adv()
			p.newlineHeredocs('\n')
			if pipeOp != "" && !started {
				continue // перенос строки после `|` — конвейер продолжается
			}
			endCmd()
		case c == '#' && !started:
			p.skipComment()
		case c == '#' && started && (p.s[p.i-1] == ' ' || p.s[p.i-1] == '\t'):
			p.skipComment()
		case p.has(";;&") || p.has(";;") || p.has(";&"):
			if p.has(";;&") {
				p.i += 3
			} else {
				p.i += 2
			}
			endCmd()
			if fc := topCase(); fc != nil {
				fc.inPattern = true
			}
		case c == ';' || (c == '&' && p.peek(1) != '>' && p.peek(1) != '&'):
			p.adv()
			endCmd()
		case p.has("&&") || p.has("||"):
			p.i += 2
			endCmd()
		case p.has("|&") || c == '|':
			op := "|"
			if p.has("|&") {
				op = "|&"
				p.i++
			}
			p.i++
			endCmd()
			pipeOp = op
		case c == ')':
			p.errorf("«)» без пары")
		case p.has("((") && !started:
			p.skipArith()
			started = true
			cur.line = p.line
		case c == '(':
			if started && len(cur.words) == 1 && strings.TrimLeft(p.s[p.i+1:], " \t")[0:1] == ")" {
				// имя() — определение функции
				p.funcDef = cur.words[0].lit
				p.defs = append(p.defs, shDef{cur.words[0].lit, p.line})
				p.adv()
				for p.s[p.i] != ')' {
					p.adv()
				}
				p.adv()
				cur = shCmd{}
				started = false
				continue
			}
			if !started {
				keyword("(")
			}
			p.adv()
			p.list(')')
			if p.i >= len(p.s) {
				p.errorf("незакрытая «(»")
				return
			}
			p.adv()
			started = true
		case p.has("<<<") || p.has("<<") || p.has("<&") || p.has("<>") ||
			(c == '<' && p.peek(1) != '('):
			op := "<"
			heredocOp := false
			switch {
			case p.has("<<<"):
				op = "<<<"
			case p.has("<<-"):
				op, heredocOp = "<<-", true
			case p.has("<<"):
				op, heredocOp = "<<", true
			case p.has("<&"), p.has("<>"):
				op = p.s[p.i : p.i+2]
			}
			p.i += len(op)
			if !started {
				cur.line = p.line
			}
			w := p.wordAfterSpace()
			if heredocOp {
				p.pending = append(p.pending, heredoc{w.lit, op == "<<-"})
			}
			if cur.inRedir == "" {
				cur.inRedir = op + " " + w.raw
			}
			started = true
		case c == '>' && p.peek(1) != '(' || p.has("&>"):
			for p.i < len(p.s) && strings.IndexByte(">&|", p.s[p.i]) >= 0 {
				p.adv()
			}
			p.wordAfterSpace()
			if !started {
				cur.line = p.line
			}
			started = true
		default:
			line := p.line
			w := p.word(false)
			if p.errs != nil {
				return
			}
			// 2>, 1>&2 — номер дескриптора, не слово
			if isDigits(w.raw) && p.i < len(p.s) && (p.s[p.i] == '<' || p.s[p.i] == '>') {
				continue
			}
			if !started {
				if fc := topCase(); fc != nil && fc.inHeader && w.raw == "in" {
					fc.inHeader, fc.inPattern = false, true
					continue
				}
				if w.raw == "esac" && !w.quoted && topCase() != nil {
					cases = cases[:len(cases)-1]
					keyword("esac")
					continue
				}
				if shKeywords[w.raw] && !w.quoted {
					keyword(w.raw)
					if w.raw == "{" && p.funcDef != "" {
						p.funcArm, p.funcDef = p.funcDef, ""
					}
					continue
				}
				if w.raw == "[[" && !w.quoted {
					p.skipCond()
				}
				if w.raw == "case" && !w.quoted {
					cases = append(cases, &caseFrame{inHeader: true})
				}
				cur.line = line
			} else if fc := topCase(); fc != nil && fc.inHeader && w.raw == "in" && len(cur.words) == 2 && cur.words[0].raw == "case" {
				fc.inHeader, fc.inPattern = false, true
				cur = shCmd{}
				started = false
				continue
			}
			cur.words = append(cur.words, w)
			started = true
		}
	}
	if term != 0 {
		return // вызывающий сообщит о незакрытой скобке
	}
	endCmd()
	if len(cases) > 0 {
		p.errorf("незакрытый case")
	}
	if len(p.pending) > 0 {
		p.errorf("незакрытый heredoc «%s»", p.pending[0].delim)
	}
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func isWordChar(c byte) bool {
	return c != 0 && strings.IndexByte(" \t\n;&|()<>", c) < 0
}

func (p *shParse) skipComment() {
	for p.i < len(p.s) && p.s[p.i] != '\n' {
		p.i++
	}
}

// newlineHeredocs — после перевода строки пропускает тела отложенных heredoc.
func (p *shParse) newlineHeredocs(c byte) {
	if c != '\n' {
		return
	}
	for len(p.pending) > 0 {
		h := p.pending[0]
		p.pending = p.pending[1:]
		for {
			if p.i >= len(p.s) {
				p.errorf("незакрытый heredoc «%s»", h.delim)
				return
			}
			end := strings.IndexByte(p.s[p.i:], '\n')
			var l string
			if end < 0 {
				l = p.s[p.i:]
				p.i = len(p.s)
			} else {
				l = p.s[p.i : p.i+end]
				p.i += end + 1
				p.line++
			}
			// тела run: в YAML идут с отступом блока — его снимает YAML,
			// а в скриптах `<<-` снимает табуляции
			if h.strip {
				l = strings.TrimLeft(l, "\t")
			}
			if l == h.delim {
				break
			}
		}
	}
}

func (p *shParse) wordAfterSpace() shWord {
	for p.i < len(p.s) && (p.s[p.i] == ' ' || p.s[p.i] == '\t') {
		p.i++
	}
	return p.word(false)
}

// word читает одно слово с кавычками и подстановками. cond — внутри [[ ]],
// где ( ) | < > — часть слова.
func (p *shParse) word(cond bool) shWord {
	var w shWord
	start := p.i
	var lit strings.Builder
	for p.i < len(p.s) && p.errs == nil {
		c := p.s[p.i]
		if c == ' ' || c == '\t' || c == '\n' || c == ';' {
			break
		}
		if !cond && strings.IndexByte("&|()<>", c) >= 0 {
			if (c == '<' || c == '>') && p.peek(1) == '(' {
				p.i += 2
				p.list(')')
				if p.i >= len(p.s) {
					p.errorf("незакрытая «<(»")
					break
				}
				p.adv()
				w.dyn = true
				continue
			}
			break
		}
		if c == '`' && p.bt > 0 {
			break // конец `…`, в котором стоит слово
		}
		if cond && c == '&' && p.peek(1) == '&' {
			break
		}
		switch c {
		case '\\':
			p.adv()
			if p.i < len(p.s) {
				if p.s[p.i] == '\n' {
					p.adv()
					continue
				}
				lit.WriteByte(p.adv())
			}
			w.quoted = true
		case '\'':
			p.adv()
			j := strings.IndexByte(p.s[p.i:], '\'')
			if j < 0 {
				p.errorf("незакрытая одинарная кавычка")
				break
			}
			seg := p.s[p.i : p.i+j]
			lit.WriteString(seg)
			p.line += strings.Count(seg, "\n")
			p.i += j + 1
			w.quoted = true
		case '"':
			p.adv()
			p.dquote(&w, &lit)
			w.quoted = true
		case '`':
			p.adv()
			p.bt++
			p.list('`')
			p.bt--
			if p.i >= len(p.s) {
				p.errorf("незакрытая обратная кавычка")
				break
			}
			p.adv()
			w.dyn = true
		case '$':
			p.dollar(&w, &lit)
		default:
			lit.WriteByte(p.adv())
		}
	}
	w.raw = p.s[start:min(p.i, len(p.s))]
	w.lit = lit.String()
	return w
}

func (p *shParse) dquote(w *shWord, lit *strings.Builder) {
	for {
		if p.i >= len(p.s) {
			p.errorf("незакрытая двойная кавычка")
			return
		}
		c := p.s[p.i]
		switch c {
		case '"':
			p.adv()
			return
		case '\\':
			p.adv()
			if p.i < len(p.s) {
				if p.s[p.i] == '\n' {
					p.adv()
					continue
				}
				lit.WriteByte(p.adv())
			}
		case '`':
			p.adv()
			p.bt++
			p.list('`')
			p.bt--
			if p.i >= len(p.s) {
				p.errorf("незакрытая обратная кавычка")
				return
			}
			p.adv()
			w.dyn = true
		case '$':
			p.dollar(w, lit)
			if p.errs != nil {
				return
			}
		default:
			lit.WriteByte(p.adv())
		}
	}
}

func (p *shParse) dollar(w *shWord, lit *strings.Builder) {
	p.adv() // $
	if p.i >= len(p.s) {
		lit.WriteByte('$')
		return
	}
	c := p.s[p.i]
	switch {
	case p.has("(("):
		p.skipArith()
		w.dyn = true
	case c == '(':
		p.adv()
		p.list(')')
		if p.i >= len(p.s) {
			p.errorf("незакрытая «$(»")
			return
		}
		p.adv()
		w.dyn = true
	case c == '{':
		p.skipBraces()
		w.dyn = true
	case c == '\'':
		// $'…' — ANSI-C строка
		p.adv()
		for {
			if p.i >= len(p.s) {
				p.errorf("незакрытая строка $'…'")
				return
			}
			if p.s[p.i] == '\\' {
				p.adv()
				if p.i < len(p.s) {
					p.adv()
				}
				continue
			}
			if p.adv() == '\'' {
				break
			}
		}
		w.quoted = true
	case c == '"':
		p.adv()
		p.dquote(w, lit)
		w.quoted = true
	case c == '_' || c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z':
		for p.i < len(p.s) && (p.s[p.i] == '_' || p.s[p.i] >= 'A' && p.s[p.i] <= 'Z' ||
			p.s[p.i] >= 'a' && p.s[p.i] <= 'z' || p.s[p.i] >= '0' && p.s[p.i] <= '9') {
			p.i++
		}
		w.dyn = true
	case strings.IndexByte("0123456789#?@*!$-", c) >= 0:
		p.adv()
		w.dyn = true
	default:
		lit.WriteByte('$')
	}
}

// skipBraces — ${…} и ${{ … }} (выражения GitHub) с учётом вложенности и
// кавычек.
func (p *shParse) skipBraces() {
	depth := 0
	for p.i < len(p.s) {
		c := p.adv()
		switch c {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return
			}
		case '\\':
			if p.i < len(p.s) {
				p.adv()
			}
		case '\'':
			if j := strings.IndexByte(p.s[p.i:], '\''); j >= 0 {
				p.i += j + 1
			}
		case '"':
			var sink strings.Builder
			var w shWord
			p.dquote(&w, &sink)
		}
	}
	p.errorf("незакрытая «${»")
}

// skipArith — (( … )) и $(( … )): `|` там — побитовое ИЛИ.
func (p *shParse) skipArith() {
	depth := 0
	for p.i < len(p.s) {
		switch p.adv() {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return
			}
		}
	}
	p.errorf("незакрытая «((»")
}

// skipCond — слова до «]]»: внутри [[ ]] `|`, `(`, `<` — не операторы.
func (p *shParse) skipCond() {
	for p.i < len(p.s) && p.errs == nil {
		c := p.s[p.i]
		if c == ' ' || c == '\t' || c == '\n' {
			p.adv()
			continue
		}
		if p.has("&&") || p.has("||") {
			p.i += 2
			continue
		}
		if p.word(true).raw == "]]" {
			return
		}
	}
	p.errorf("незакрытая «[[»")
}

// casePattern — `(a | b)` до закрывающей «)» уровня шаблона.
func (p *shParse) casePattern() {
	depth := 0
	if p.s[p.i] == '(' {
		p.adv()
	}
	for p.i < len(p.s) {
		c := p.s[p.i]
		switch c {
		case '\\':
			p.adv()
			if p.i < len(p.s) {
				p.adv()
			}
		case '\'', '"':
			var w shWord
			var sink strings.Builder
			p.adv()
			if c == '"' {
				p.dquote(&w, &sink)
			} else if j := strings.IndexByte(p.s[p.i:], '\''); j >= 0 {
				p.i += j + 1
			} else {
				p.errorf("незакрытая одинарная кавычка")
				return
			}
		case '(':
			depth++
			p.adv()
		case ')':
			p.adv()
			if depth == 0 {
				return
			}
			depth--
		default:
			p.adv()
		}
	}
	p.errorf("незакрытый шаблон case")
}

// --- закрытый список читателей -------------------------------------------

// readerRule — что читателю можно: короткие флаги-буквы, флаги со значением,
// число операндов, и дополнительная проверка содержимого.
type readerRule struct {
	why       string // почему он дочитывает ввод до конца
	flags     string // допустимые короткие флаги без значения
	valFlags  string // допустимые короткие флаги со значением
	operands  [2]int // мин/макс «обычных» операндов (шаблон, скрипт, набор)
	numFlag   bool   // tail: -1, -n N
	content   func(args []shWord) string
	operandOK func(w shWord) bool // если задан — допустимы только такие операнды, и среди них «-»
}

// pipeReaders — ЗАКРЫТЫЙ список. Каждая строка — то, что сейчас стоит в
// ci.yml, release.yml и scripts/*.sh справа от `|`, с обоснованием. Новый
// читатель появляется только видимой строкой здесь.
var pipeReaders = map[string]readerRule{
	"sort": {why: "сортирует весь ввод, прежде чем что-либо вывести", flags: "uVnr"},
	"wc":   {why: "считает до конца ввода", flags: "lcw"},
	"tail": {why: "последние строки известны только в конце ввода", numFlag: true},
	"cat": {why: "копирует все входы по порядку; «-» — сам конвейер",
		operandOK: func(w shWord) bool { return w.lit == "-" || strings.HasPrefix(w.raw, "<(") }},
	"fold":   {why: "построчный фильтр до конца ввода", valFlags: "w"},
	"base64": {why: "кодирует весь ввод"},
	"tr":     {why: "посимвольный фильтр до конца ввода; файлов не читает вовсе", flags: "ds", operands: [2]int{1, 2}},
	"sed": {why: "без q/Q проходит весь ввод", flags: "nE", operands: [2]int{1, 1},
		content: func(args []shWord) string {
			for _, a := range args {
				if a.dyn {
					return "скрипт sed с подстановкой — содержимое неизвестно"
				}
				if strings.ContainsAny(a.lit, "qQ") {
					return "в скрипте sed есть q/Q — выход раньше конца ввода"
				}
			}
			return ""
		}},
	"awk": {why: "без exit/nextfile проходит весь ввод", valFlags: "vF", operands: [2]int{1, 1},
		content: func(args []shWord) string {
			for _, a := range args {
				if a.dyn {
					return "программа awk с подстановкой — содержимое неизвестно"
				}
				if strings.Contains(a.lit, "exit") || strings.Contains(a.lit, "nextfile") {
					return "в программе awk есть exit/nextfile — выход раньше конца ввода"
				}
			}
			return ""
		}},
	"grep": {why: "без -q/-l/-L/-m проходит весь ввод", flags: "EFxvicno", valFlags: "e", operands: [2]int{1, 1}},
	"sha256sum": {why: "хеш всего ввода",
		operandOK: func(w shWord) bool { return w.lit == "-" }},
	// bash — только ради одного скрипта, см. growthScriptProblem.
	"bash": {why: "scripts/check-version-growth.sh читает stdin циклом до EOF", operands: [2]int{2, 2},
		content: func(args []shWord) string {
			if args[0].quoted || args[0].dyn || args[0].lit != "scripts/check-version-growth.sh" || args[1].raw == "" {
				return "bash допустим читателем только как `bash scripts/check-version-growth.sh <тег>`"
			}
			return ""
		}},
}

// growthScript — единственный скрипт-читатель; его «дочитывает до конца»
// проверяется по тексту: успех (exit 0) возможен только после цикла чтения,
// в цикле нет break/exit. Ранние `exit 1` выше цикла допустимы: это отказ,
// и SIGPIPE пишущего его не меняет.
const growthScript = "../../scripts/check-version-growth.sh"

func growthScriptProblem(t *testing.T) string {
	text := strings.ReplaceAll(string(readSource(t, growthScript)), "\r\n", "\n")
	loop := strings.Index(text, "\nwhile IFS= read -r line")
	done := strings.Index(text, "\ndone\n")
	switch {
	case loop < 0 || done < loop:
		return "в check-version-growth.sh не найден цикл `while IFS= read -r line … done`"
	case strings.Contains(text[loop:done], "break") || strings.Contains(text[loop:done], "exit"):
		return "в цикле чтения check-version-growth.sh есть break/exit — выход раньше конца ввода"
	case strings.Contains(text[:loop], "exit 0"):
		return "check-version-growth.sh выходит успешно (exit 0) до цикла чтения"
	}
	return ""
}

// readerProblem — пусто, если команда дочитывает ввод до конца.
func readerProblem(c shCmd, funcs map[string]shCmd, depth int) string {
	if len(c.words) == 0 {
		return "справа от «" + c.op + "» нет команды"
	}
	if c.inRedir != "" {
		return "вход читателя перенаправлен «" + c.inRedir + "» — конвейер не читается"
	}
	name := c.words[0]
	if name.quoted || name.dyn || name.raw != name.lit {
		return "читатель «" + name.raw + "» вне закрытого списка"
	}
	if fc, ok := funcs[name.lit]; ok && depth == 0 {
		if pr := readerProblem(fc, nil, 1); pr != "" {
			return "функция «" + name.lit + "»: первая команда тела — " + pr
		}
		return ""
	}
	rule, ok := pipeReaders[name.lit]
	if !ok {
		return "читатель «" + name.lit + "» вне закрытого списка"
	}
	var operands []shWord
	args := c.words[1:]
	flagsDone := false
	for k := 0; k < len(args); k++ {
		a := args[k]
		if !flagsDone && !a.quoted && a.lit == "--" {
			flagsDone = true
			continue
		}
		if flagsDone || a.quoted || a.dyn || !strings.HasPrefix(a.lit, "-") || a.lit == "-" {
			operands = append(operands, a)
			continue
		}
		f := a.lit[1:]
		if rule.numFlag {
			if isDigits(f) {
				continue
			}
			if f == "n" && k+1 < len(args) && isDigits(strings.TrimPrefix(args[k+1].lit, "+")) {
				k++
				continue
			}
			return "«" + name.lit + "»: флаг «" + a.raw + "» вне закрытого списка"
		}
		if strings.HasPrefix(f, "-") {
			return "«" + name.lit + "»: флаг «" + a.raw + "» вне закрытого списка"
		}
		for j := 0; j < len(f); j++ {
			ch := f[j]
			if strings.IndexByte(rule.flags, ch) >= 0 {
				continue
			}
			if strings.IndexByte(rule.valFlags, ch) >= 0 {
				if j == len(f)-1 {
					if k+1 >= len(args) {
						return "«" + name.lit + "»: у флага «-" + string(ch) + "» нет значения"
					}
					if ch == 'e' {
						operands = append(operands, args[k+1]) // -e ШАБЛОН — это шаблон
					}
					k++
				}
				break
			}
			return "«" + name.lit + "»: флаг «" + a.raw + "» вне закрытого списка"
		}
	}
	// Операнды. У cat и sha256sum допустимы только «-» (сам конвейер) и
	// <(…); у прочих — шаблон/скрипт/набор в пределах operands. Всё сверх —
	// файл: читается он, а не конвейер, и пишущий ловит SIGPIPE.
	plain, sawDash := 0, false
	for _, o := range operands {
		if rule.operandOK != nil {
			if !rule.operandOK(o) {
				return "«" + name.lit + "»: лишний операнд «" + o.raw + "» — читается файл, а не конвейер"
			}
			sawDash = sawDash || o.lit == "-"
			continue
		}
		plain++
	}
	if rule.operandOK != nil && len(operands) > 0 && !sawDash {
		return "«" + name.lit + "»: есть операнды, но нет «-» — конвейер не читается"
	}
	if plain < rule.operands[0] {
		return "«" + name.lit + "»: не хватает операнда"
	}
	if plain > rule.operands[1] {
		return "«" + name.lit + "»: лишний операнд «" + operands[len(operands)-1].raw + "» — читается файл, а не конвейер"
	}
	if rule.content != nil {
		if pr := rule.content(operands); pr != "" {
			return "«" + name.lit + "»: " + pr
		}
	}
	return ""
}

// shDef — определение функции в форме имя() (тело { } или ( )).
type shDef struct {
	name string
	line int
}

var shells = map[string]bool{"bash": true, "sh": true, "dash": true, "zsh": true, "ksh": true}

// allowedShellCalls — ЗАКРЫТЫЙ список вызовов оболочки (раунд 3, AU-LOGIC
// F1). Текст, переданный оболочке строкой, heredoc, here-string, через
// source/. или по имени из переменной, лексер не разбирает — значит,
// конвейеры в нём не проверены. Допустимы только эти точные записи (слова
// как в файле, вход не перенаправлен): каждая запускает наш scripts/*.sh,
// который сторож разбирает сам. Shebang — комментарий, а не вызов.
var allowedShellCalls = map[string]string{
	`bash scripts/check-version-growth.sh "$GITHUB_REF_NAME"`: "release.yml, три job: рост версии тега",
	`bash scripts/build-release.sh ${{ matrix.os }}`:          "ci.yml и release.yml: сборка",
	`bash scripts/dev-tools.sh`:                               "ci.yml: пиновый shellcheck",
}

// allowedDynCmds — ЗАКРЫТЫЙ список команд, имя которых — подстановка
// (`"$SHELLCHECK_BIN" …`). Иначе `"$BASH" -c` и `$SHELL -c` проходили бы: у
// них нет буквального имени. Часть строк — элементы массивов и аргументы,
// которые лексер видит в позиции команды (`names+=("$1")`); они безвредны,
// но вносятся явно, чтобы новое было видно.
var allowedDynCmds = map[string]string{
	`"$SHELLCHECK_BIN"`:          "ci.yml: пиновый shellcheck по пути из dev-tools.sh",
	`"./$bin"`:                   "release.yml: запуск собранного бинаря (version)",
	`"$@"`:                       "check-history-keys.sh: исполнитель переданной команды; её слова проверяются здесь же у вызывающего",
	`"$1"`:                       "check-history-keys.sh: элемент массива names+=(\"$1\")",
	`"$2"`:                       "check-history-keys.sh: элемент массива wants+=(\"$2\")",
	`$pat`:                       "release.yml: элемент массива found=($pat) — глоб субъектов",
	`"${found[@]}"`:              "элемент массива",
	`"$(scan | count_suspects)"`: "check-history-keys.sh: элемент массива gots+=(…)",
}

// shellWrappers — команды, исполняющие следующее слово как команду. После
// них позиция команды сдвигается; сами по себе они допустимы.
var shellWrappers = map[string]bool{
	"env": true, "command": true, "exec": true, "nice": true, "nohup": true,
	"builtin": true, "time": true, "sudo": true, "xargs": true, "timeout": true,
}

var assignRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*(\[[^]]*\])?\+?=`)

// protectedNames — имена, которые нельзя переопределять функцией или alias
// (AU-LOGIC F2): читатели закрытого списка, оболочки и eval/source.
var protectedNames = func() map[string]bool {
	m := map[string]bool{"grep": true, "head": true, "sed": true, "awk": true,
		"eval": true, "source": true, "alias": true}
	for k := range pipeReaders {
		m[k] = true
	}
	for k := range shells {
		m[k] = true
	}
	return m
}()

// shellCallProblem — пусто, если команда не исполняет код в обход лексера.
func shellCallProblem(c shCmd) string {
	ws := c.words
	k := 0
	for k < len(ws) && assignRe.MatchString(ws[k].raw) {
		k++
	}
	if k == len(ws) {
		return ""
	}
	// eval — в любом месте команды
	for _, w := range ws {
		if !w.quoted && w.lit == "eval" {
			return "«eval»"
		}
	}
	first := ws[k]
	switch {
	case !first.quoted && !first.dyn && first.lit == "function":
		if k+1 < len(ws) && protectedNames[strings.TrimSuffix(ws[k+1].lit, "()")] {
			return "«function " + ws[k+1].raw + "» переопределяет имя из закрытого списка"
		}
	case !first.quoted && !first.dyn && first.lit == "alias":
		return "«alias» — подмена имени команды, которую лексер не видит"
	}
	wrapped := false
	for k < len(ws) && !ws[k].quoted && !ws[k].dyn && shellWrappers[ws[k].lit] {
		wrapped = true
		k++
		for k < len(ws) && !ws[k].quoted && (strings.HasPrefix(ws[k].lit, "-") || assignRe.MatchString(ws[k].raw) || isDigits(ws[k].lit)) {
			k++
		}
	}
	if k == len(ws) {
		return ""
	}
	first = ws[k]
	var raws []string
	for _, w := range ws[k:] {
		raws = append(raws, w.raw)
	}
	call := strings.Join(raws, " ")
	if first.dyn {
		if _, ok := allowedDynCmds[first.raw]; !ok || wrapped {
			return "команда с подстановкой в имени «" + call + "» вне закрытого списка allowedDynCmds"
		}
	}
	base := first.lit[strings.LastIndexByte(first.lit, '/')+1:]
	isShell := !first.dyn && (shells[base] || first.lit == "source" || first.lit == ".")
	if isShell {
		if _, ok := allowedShellCalls[call]; !ok || wrapped {
			return "вызов оболочки «" + call + "» вне закрытого списка"
		}
		if c.inRedir != "" {
			return "вход оболочки перенаправлен «" + c.inRedir + "» — код через heredoc/here-string"
		}
	}
	// оболочка аргументом (find -exec sh, xargs … bash) — тоже вызов
	for _, w := range ws[k+1:] {
		b := w.lit[strings.LastIndexByte(w.lit, '/')+1:]
		if !w.quoted && !w.dyn && shells[b] && !isShell {
			return "оболочка «" + w.raw + "» аргументом в «" + call + "» вне закрытого списка"
		}
	}
	return ""
}

func TestNoEarlyExitPipeReader(t *testing.T) {
	type src struct{ where, body string }
	var srcs []src
	for _, path := range []string{releaseYML, ciYML} {
		wf := loadWorkflow(t, path)
		var jobs []string
		for jn := range wf.Jobs {
			jobs = append(jobs, jn)
		}
		sort.Strings(jobs)
		for _, jn := range jobs {
			for i, s := range wf.Jobs[jn].Steps {
				srcs = append(srcs, src{fmtStep(path, jn, i, s.Name), s.Run})
			}
		}
	}
	scripts, err := filepath.Glob(filepath.Join("..", "..", "scripts", "*.sh"))
	if err != nil || len(scripts) == 0 {
		fatal(t, "не найдено ни одного scripts/*.sh (err=%v) — тест перестал что-либо проверять", err)
	}
	sort.Strings(scripts)
	for _, p := range scripts {
		p = filepath.ToSlash(p)
		srcs = append(srcs, src{p, string(readSource(t, p))})
	}
	readers := 0
	for _, s := range srcs {
		p := parseShell(s.body)
		for _, e := range p.errs {
			fail(t, "%s: текст не разобран (%s) — неразобранное не доказано; конвейеры в нём не проверены", s.where, e)
		}
		lines := strings.Split(strings.ReplaceAll(s.body, "\r\n", "\n"), "\n")
		for _, c := range p.cmds {
			if pr := shellCallProblem(c); pr != "" {
				fail(t, "%s: строка %d: %s — код, переданный оболочке, лексер не разбирает, конвейеры в нём не проверены. "+
					"Закрытый список вызовов — allowedShellCalls", s.where, c.line, pr)
			}
		}
		for _, d := range p.defs {
			if protectedNames[d.name] {
				fail(t, "%s: строка %d: определение функции «%s» переопределяет имя из закрытого списка — "+
					"читатель под этим именем уже не тот, кого проверяет сторож", s.where, d.line, d.name)
			}
		}
		for _, r := range p.readers {
			readers++
			l := ""
			if r.line-1 < len(lines) {
				l = strings.TrimSpace(lines[r.line-1])
			}
			if pr := readerProblem(r, p.funcs, 0); pr != "" {
				fail(t, "%s: «%s» — %s. Читатель конвейера обязан дочитать ввод до конца: иначе пишущий ловит "+
					"SIGPIPE, и под pipefail «нашёл» становится «не нашёл» (main f0febbd). Закрытый список — "+
					"pipeReaders; принадлежность — here-string `grep -q … <<< \"$x\"`, циклом или через переменную",
					s.where, l, pr)
			}
		}
	}
	// Счёт через !=, а не <: исчезновение читателей — тоже сигнал
	// (например, лексер перестал видеть конвейеры).
	if readers == 0 {
		fatal(t, "не найдено ни одного читателя конвейера — лексер перестал видеть конвейеры, тест ничего не проверил")
	}
	if readers != wantPipeReaders {
		fail(t, "читателей конвейера найдено %d, ожидалось %d — сторож видит не то, что стоит в файлах; "+
			"законно изменилось — поправь wantPipeReaders", readers, wantPipeReaders)
	}
	// Скрипт-читатель из закрытого списка проверяется всегда, а не только
	// когда встретился: правило «bash — только этот скрипт» опирается на то,
	// что он дочитывает ввод.
	if pr := growthScriptProblem(t); pr != "" {
		fail(t, "%s: %s. Скрипт стоит читателем конвейера в release.yml", growthScript, pr)
	}
}

// wantPipeReaders — сколько звеньев справа от `|` сейчас в файлах. Зачем
// точное число: лексер, переставший видеть конвейеры (или видящий их не
// там), иначе молча зеленеет.
const wantPipeReaders = 30

func fmtStep(path, job string, i int, name string) string {
	return fmt.Sprintf("%s (job %s, шаг №%d «%s»)", path, job, i+1, name)
}
