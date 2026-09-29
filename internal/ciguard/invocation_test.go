// Файл invocation_test.go — сторож СМЫСЛА вызова actionlint (A6, следствие
// A5 № 2) и общий разбор строки shell для сторожа go test.
//
// Сторож версии (actionlintversion_test.go) смотрит на пин и на то, что шаг
// существует и исполняется. Он зелёный на вызовах, которые не проверяют
// ничего. Это тот же класс, с которого всё началось (d174b15): линтер
// запускался и молча ничего не разбирал.
//
// Правила для КАЖДОГО вызова actionlint в обоих workflow (по закрытому
// списку, а не перечислением лжи):
//   - флаги только из allowedActionlintFlags; `-shellcheck` обязателен и с
//     непустым значением;
//   - хотя бы один файл-аргумент.
//
// Правила для РАЗБИРАЮЩЕГО вызова — того, в строке которого назван
// .github/workflows/ (ревью QA-01: смысл обходился одной строкой):
//   - перед вызовом в строке ничего, кроме `go run` (ни `!`, ни `true ||`,
//     ни `if`, ни `echo`, ни присваивания);
//   - после аргументов ничего: ни `|| true`, ни `>/dev/null`, ни `&`, ни `;`;
//   - выше в теле run: стоит `set -euo pipefail`, и между ним и вызовом нет
//     `set +…`;
//   - выше нет строки, начинающейся с `exit` или `return`;
//   - выше нет объявления функции (вызов в теле функции, которую никто не
//     зовёт, не исполняется);
//   - файлы — ровно оба настоящих workflow.
//
// Плюс отдельно: такой вызов обязан существовать.
//
// Первая найденная причина — одно сообщение из одной точки. Поэтому каждая
// подсадка в plant_test.go роняет ровно свою ветку, и ни одна ветка не
// прикрыта соседом.
//
// Смотрятся все шаги, включая стоящие под if: и continue-on-error:
// исполняемость — предмет соседнего сторожа.
//
// ГРАНИЦА. Разбор shell упрощённый: кавычки, продолжение строки обратной
// косой, операторы ; & | < >. Он не раскрывает переменных, массивов, eval,
// alias, не видит `trap`, `exec >файл` и вызов через переменную с именем
// команды. Вызов, который канарейка ci.yml гоняет на своём временном файле,
// разбирающим не считается: его код возврата проверяет сам шаг.
package ciguard

import (
	"regexp"
	"sort"
	"strings"
	"testing"
)

// allowedActionlintFlags — закрытый список флагов. Значение — берёт ли флаг
// аргумент. Новый флаг законен? Внеси строку — это видно в диффе.
var allowedActionlintFlags = map[string]bool{
	"-shellcheck": true,
}

var realWorkflows = []string{".github/workflows/ci.yml", ".github/workflows/release.yml"}

// shword — слово строки shell; op — оператор (; & | < > и их сочетания,
// включая номер дескриптора перед перенаправлением: `2>`).
type shword struct {
	text string
	op   bool
}

func isOpChar(c byte) bool { return c == ';' || c == '&' || c == '|' || c == '<' || c == '>' }

func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// shellWords — упрощённое разбиение строки shell: кавычки снимаются, пустые
// кавычки дают пустое слово, операторы вне кавычек — отдельные слова с op.
func shellWords(line string) []shword {
	var words []shword
	var cur strings.Builder
	inWord, quoted, quote := false, false, byte(0)
	flush := func() {
		if inWord {
			words = append(words, shword{text: cur.String()})
			cur.Reset()
			inWord, quoted = false, false
		}
	}
	for i := 0; i < len(line); i++ {
		c := line[i]
		switch {
		case quote != 0:
			if c == quote {
				quote = 0
			} else {
				cur.WriteByte(c)
			}
		case c == '\'' || c == '"':
			quote, inWord, quoted = c, true, true
		case c == ' ' || c == '\t':
			flush()
		case isOpChar(c):
			prefix := ""
			if inWord && !quoted && allDigits(cur.String()) && (c == '<' || c == '>') {
				prefix = cur.String()
				cur.Reset()
				inWord = false
			}
			flush()
			j := i
			for j < len(line) && (isOpChar(line[j]) || (j > i && line[j-1] == '&' && line[j] >= '0' && line[j] <= '9')) {
				j++
			}
			words = append(words, shword{text: prefix + line[i:j], op: true})
			i = j - 1
		default:
			cur.WriteByte(c)
			inWord = true
		}
	}
	flush()
	return words
}

// actionlintCall — один вызов: слова до него, аргументы, хвост после первого
// оператора и строки тела run: выше строки вызова.
type actionlintCall struct {
	path, job, step string
	line            string
	pre, args, tail []string
	before          []string
	real            bool
}

func texts(ws []shword) []string {
	var out []string
	for _, w := range ws {
		out = append(out, w.text)
	}
	return out
}

func actionlintCalls(t *testing.T, path string) []actionlintCall {
	t.Helper()
	wf := loadWorkflow(t, path)
	var calls []actionlintCall
	for jobName, j := range wf.Jobs {
		for _, s := range j.Steps {
			body := strings.ReplaceAll(stripShellComments(s.Run), "\\\n", " ")
			lines := strings.Split(body, "\n")
			for li, line := range lines {
				loc := actionlintAnyRe.FindStringIndex(line)
				if loc == nil {
					continue
				}
				c := actionlintCall{path: path, job: jobName, step: s.Name, line: strings.TrimSpace(line),
					before: lines[:li], real: strings.Contains(line, ".github/workflows/")}
				scan := line
				// Вызов внутри подстановки команды: out="$(go run … 2>&1)" —
				// только у канарейки. Разбирается содержимое подстановки.
				if at := strings.Index(line, "$("); at >= 0 && at < loc[0] && !c.real {
					if end := strings.LastIndex(line, ")"); end > at {
						scan = line[at+2 : end]
					}
				}
				words := shellWords(scan)
				for i, w := range words {
					if w.op || !actionlintAnyRe.MatchString(w.text) {
						continue
					}
					c.pre = texts(words[:i])
					rest := words[i+1:]
					k := 0
					for k < len(rest) && !rest[k].op {
						k++
					}
					c.args = texts(rest[:k])
					c.tail = texts(rest[k:])
					break
				}
				calls = append(calls, c)
			}
		}
	}
	return calls
}

var (
	setStrictRe = regexp.MustCompile(`^set\s+-[a-z]*e[a-z]*o\s+pipefail$`)
	setPlusRe   = regexp.MustCompile(`^set\s+(\+[a-z]*|.*\+o\s)`)
	exitRe      = regexp.MustCompile(`^(exit|return)(\s|$)`)
	funcRe      = regexp.MustCompile(`^(function\s+\S+|[A-Za-z_][A-Za-z0-9_]*\s*\(\s*\))`)
)

// callProblem — первая причина, по которой вызов ничего не проверяет, или
// пустая строка. Одна точка сообщения на все причины — см. шапку файла.
func callProblem(c actionlintCall, want []string) string {
	if c.real {
		if strings.Join(c.pre, " ") != "go run" {
			return "перед вызовом в строке стоит «" + strings.Join(c.pre, " ") + "» вместо одного `go run` — " +
				"вызов может не исполниться или его код возврата теряется (!, true ||, if, echo, присваивание)"
		}
		if len(c.tail) > 0 {
			return "после аргументов вызова стоит хвост «" + strings.Join(c.tail, " ") + "» — " +
				"`|| true`, перенаправление, `&` или `;` глушат код возврата линтера"
		}
		strict := -1
		for i, l := range c.before {
			l = strings.TrimSpace(l)
			switch {
			case setStrictRe.MatchString(l):
				strict = i
			case setPlusRe.MatchString(l):
				return "выше вызова стоит «" + l + "» — падение линтера больше не роняет шаг"
			case exitRe.MatchString(l):
				return "выше вызова стоит «" + l + "» — до вызова шаг не доходит"
			case funcRe.MatchString(l):
				return "вызов стоит после объявления функции «" + l + "» — тело функции не исполняется, пока её не позвали"
			}
		}
		if strict < 0 {
			return "в теле шага выше вызова нет `set -euo pipefail` — обязателен явно"
		}
	}

	var files []string
	shellcheck, shellcheckEmpty := false, false
	for i := 0; i < len(c.args); i++ {
		a := c.args[i]
		if !strings.HasPrefix(a, "-") {
			files = append(files, a)
			continue
		}
		name, val, hasEq := strings.Cut(a, "=")
		takesArg, ok := allowedActionlintFlags[name]
		if !ok {
			return "флаг " + name + " вне закрытого списка allowedActionlintFlags — вызов может ничего не " +
				"разбирать (--version, -ignore, -init-config…). Флаг законен? Внеси его строкой в список"
		}
		if takesArg && !hasEq {
			if i+1 < len(c.args) {
				i++
				val = c.args[i]
			}
		}
		if name == "-shellcheck" {
			if strings.TrimSpace(val) == "" {
				shellcheckEmpty = true
			} else {
				shellcheck = true
			}
		}
	}
	switch {
	case shellcheckEmpty:
		return "-shellcheck с пустым значением — actionlint молча не разбирает bash внутри run:"
	case !shellcheck:
		return "вызов actionlint без -shellcheck <путь> — bash внутри run: не разбирается"
	case len(files) == 0:
		return "вызов actionlint без файлов — разбирать нечего"
	}
	if c.real {
		sort.Strings(files)
		if strings.Join(files, " ") != strings.Join(want, " ") {
			return "файлы разбирающего вызова " + strings.Join(files, " ") + " — не ровно оба workflow " + strings.Join(want, " ")
		}
	}
	return ""
}

func TestActionlintInvocationMeaning(t *testing.T) {
	var calls []actionlintCall
	for _, path := range []string{releaseYML, ciYML} {
		calls = append(calls, actionlintCalls(t, path)...)
	}
	if len(calls) == 0 {
		t.Fatalf("ни в %s, ни в %s не найдено ни одного вызова actionlint — тест перестал что-либо проверять", releaseYML, ciYML)
	}

	want := append([]string{}, realWorkflows...)
	sort.Strings(want)
	realFound := false
	for _, c := range calls {
		// realFound не зависит от исправности: иначе неисправный разбирающий
		// вызов ронял бы тест двумя сообщениями, и каждое прикрывало бы другое.
		if c.real {
			realFound = true
		}
		if p := callProblem(c, want); p != "" {
			t.Errorf("%s (job %s, шаг «%s»): %s\n  строка: %s", c.path, c.job, c.step, p, c.line)
		}
	}
	if !realFound {
		t.Errorf("нет ни одного вызова actionlint, в строке которого названы workflow %v — настоящий разбор "+
			"исчез или лишился предмета", want)
	}
}
