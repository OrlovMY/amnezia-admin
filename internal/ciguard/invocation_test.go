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
//   - ТЕЛО ШАГА — ЗАКРЫТЫЙ СПИСОК (ревью QA-01, раунд 2): выше вызова только
//     `set -euo pipefail` (обязателен) и строки
//     `test -n "${X:-}" || { echo "…"; exit 1; }`; вызов — последняя строка.
//     Любая другая строка красная: подоболочка, if/while/case, heredoc,
//     литерал `: '…'`, export, set +e, exit, функция. Раньше здесь
//     перечислялись плохие строки — это и было перечисление лжи, и шесть
//     форм окружения проходили зелёными;
//   - у шага нет shell:, у job нет defaults.run.shell, у workflow
//     defaults.run.shell ровно `bash`;
//   - файлы — ровно оба настоящих workflow.
//
// Те же закрытые списки тела и shell применяются к шагу go test
// (releasechain_test.go). GO*-переменные в env и $GITHUB_ENV стережёт
// TestNoToolEnvironmentOverrides.
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
// ГРАНИЦА. Закрытый список тела делает большую часть прежних границ
// неважной: `trap`, `exec >файл`, alias, eval в теле разбирающего шага —
// строки вне списка, они красные. Остаётся то, что не видно в теле шага:
// окружение, которое кладёт раннер или предыдущий шаг способом, отличным от
// env: и строки `GO…=` с GITHUB_ENV (например, собранное из частей имя
// переменной или файл в $GITHUB_PATH, подменяющий `go`); `trap` в ДРУГОМ
// шаге на него не действует. Вызов, который канарейка ci.yml гоняет на своём
// временном файле, разбирающим не считается: его код возврата проверяет сам
// шаг.
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

// shellcheckValue — единственное допустимое значение -shellcheck (после
// снятия кавычек). Саму переменную нигде, кроме scripts/dev-tools.sh, задать
// нельзя — это стережёт TestNoToolEnvironmentOverrides.
const shellcheckValue = "$SHELLCHECK_BIN"

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
	stepIdx         int
	line            string
	pre, args, tail []string
	before, after   []string
	shells          [3]string // шаг, defaults job, defaults workflow
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
		for si, s := range j.Steps {
			body := strings.ReplaceAll(stripShellComments(s.Run), "\\\n", " ")
			lines := strings.Split(body, "\n")
			for li, line := range lines {
				loc := actionlintAnyRe.FindStringIndex(line)
				if loc == nil {
					continue
				}
				c := actionlintCall{path: path, job: jobName, stepIdx: si, step: s.Name, line: strings.TrimSpace(line),
					before: lines[:li], after: lines[li+1:], shells: [3]string{s.Shell, j.Defaults.Run.Shell, wf.Defaults.Run.Shell}, real: strings.Contains(line, ".github/workflows/")}
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
		if sp := shellProblem(c.shells); sp != "" {
			return sp
		}
		if bp := stepBodyProblem(c.before, c.after, true); bp != "" {
			return bp
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
			switch {
			case strings.TrimSpace(val) == "":
				shellcheckEmpty = true
			case val != shellcheckValue:
				// Закрытый список значения (ревью QA-01, раунд 4). actionlint,
				// не найдя бинарь по пути, МОЛЧА отключает shellcheck — ровно
				// исторический дефект, с которого началась история CI.
				return "значение -shellcheck «" + val + "» вне закрытого списка — допустимо только " +
					shellcheckValue + ": путь, который отдал scripts/dev-tools.sh и исправность которого " +
					"доказала канарейка; с несуществующим путём actionlint молча отключает shellcheck"
			default:
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
		fatal(t, "ни в %s, ни в %s не найдено ни одного вызова actionlint — тест перестал что-либо проверять", releaseYML, ciYML)
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
			fail(t, "%s (job %s, шаг «%s»): %s\n  строка: %s", c.path, c.job, c.step, p, c.line)
		}
	}
	if !realFound {
		fail(t, "нет ни одного вызова actionlint, в строке которого названы workflow %v — настоящий разбор "+
			"исчез или лишился предмета", want)
	}

	// Исправность $SHELLCHECK_BIN доказывает канарейка — вызов с тем же
	// значением -shellcheck на файле "$canary" с заведомым SC2086. Она обязана
	// стоять в ТОМ ЖЕ job и РАНЬШЕ каждого разбирающего вызова: иначе
	// разбирающий вызов опирается на путь, который никто не проверил.
	for _, r := range calls {
		if !r.real {
			continue
		}
		proven := false
		for _, c := range calls {
			if !c.real && c.path == r.path && c.job == r.job && c.stepIdx < r.stepIdx &&
				canaryCall(c) {
				proven = true
			}
		}
		if !proven {
			fail(t, "%s (job %s, шаг «%s»): выше в том же job нет канарейки — вызова с -shellcheck %s "+
				"на файле \"$canary\"; путь к shellcheck в разбирающем вызове никто не проверил",
				r.path, r.job, r.step, shellcheckValue)
		}
	}
}

// canaryCall — вызов канарейки: -shellcheck $SHELLCHECK_BIN и единственный
// файл $canary.
func canaryCall(c actionlintCall) bool {
	return strings.Join(c.args, " ") == "-shellcheck "+shellcheckValue+" $canary"
}

// --- закрытый список тела разбирающего шага (ревью QA-01, раунд 2) -------
//
// Прежние правила перечисляли ПЛОХИЕ строки выше вызова (set +, exit,
// функция) — то есть перечисляли ложь, от чего шапка этого файла сама
// отказывается. Вызов в подоболочке, под `if false`, в `while false`, в
// `case`, в heredoc, в строковом литерале `: '…'`, после `export GOFLAGS=-n`
// оставался зелёным. Теперь список закрыт с другой стороны: тело шага
// состоит ТОЛЬКО из допущенных строк, вызов — последняя строка.

var (
	setStrictRe = regexp.MustCompile(`^set\s+-euo\s+pipefail$`)
	// test -n "${ИМЯ:-}" || { echo "текст без $ и `"; exit 1; } — проверка,
	// что scripts/dev-tools.sh отдал переменную.
	guardRe = regexp.MustCompile(`^test -n "\$\{[A-Z_][A-Z0-9_]*:-\}" \|\| \{ echo "[^"$` + "`" + `]*" >&2; exit 1; \}$`)
)

// stepBodyProblem — строки тела шага вне закрытого списка: до вызова только
// `set -euo pipefail` и строки-проверки guardRe, после вызова — ничего.
func stepBodyProblem(before, after []string, requireSet bool) string {
	hasSet := false
	for _, l := range before {
		l = strings.TrimSpace(l)
		switch {
		case l == "":
		case setStrictRe.MatchString(l):
			hasSet = true
		case guardRe.MatchString(l):
		default:
			return "строка «" + l + "» выше вызова — вне закрытого списка тела шага " +
				"(только `set -euo pipefail` и `test -n \"${X:-}\" || { echo …; exit 1; }`): " +
				"блок, подоболочка, heredoc, литерал, export или условие могут не дать вызову исполниться"
		}
	}
	if requireSet && !hasSet {
		return "в теле шага выше вызова нет `set -euo pipefail` — обязателен явно"
	}
	for _, l := range after {
		if l = strings.TrimSpace(l); l != "" {
			return "после вызова стоит строка «" + l + "» — вызов обязан быть последней строкой шага"
		}
	}
	return ""
}

// shellProblem — ключ shell: у шага или defaults.run.shell у job запрещены;
// у workflow defaults.run.shell обязан быть ровно `bash` (раннер исполняет
// его как `bash --noprofile --norc -eo pipefail {0}`). Своя строка shell:
// может выключить -e или добавить `|| true` к самому запуску скрипта.
func shellProblem(sh [3]string) string {
	switch {
	case sh[0] != "":
		return "у шага задан shell: «" + sh[0] + "» — закрытый список: shell у шага не задаётся"
	case sh[1] != "":
		return "у job задан defaults.run.shell: «" + sh[1] + "» — закрытый список: только defaults workflow"
	case sh[2] != "bash":
		return "defaults.run.shell workflow «" + sh[2] + "», а не bash — закрытый список"
	}
	return ""
}
