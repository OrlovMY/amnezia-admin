// Файл invocation_test.go — сторож СМЫСЛА вызова actionlint (A6, следствие
// A5 № 2).
//
// Сторож версии (actionlintversion_test.go) смотрит на пин и на то, что шаг
// существует и исполняется. Он зелёный на трёх вызовах, которые не
// проверяют ничего: `…actionlint@… --version`; вызов без файлов; вызов с
// заглушенными правилами. Это тот же класс, с которого всё началось
// (d174b15): линтер запускался и молча ничего не разбирал.
//
// Правило для КАЖДОГО вызова actionlint в обоих workflow — по закрытому
// списку, а не перечислением лжи:
//   - флаги только из allowedActionlintFlags; `-shellcheck` обязателен и с
//     непустым значением (без него bash внутри run: не разбирается);
//   - хотя бы один файл-аргумент.
//
// И отдельно: среди вызовов есть такой, чьи файлы-аргументы — РОВНО оба
// настоящих workflow. Смотрятся все шаги, включая стоящие под if: и
// continue-on-error: исполняемость — предмет соседнего сторожа, и смешивать
// причины значило бы краснеть не на своей.
//
// ГРАНИЦА. Разбор аргументов — упрощённый (кавычки, продолжение строки
// обратной косой). Подстановки вроде "$@" или массивов bash он не
// раскрывает; такой вызов даст здесь «неизвестный аргумент» и покраснеет —
// в сторону тревоги, а не молчания.
package ciguard

import (
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

// shellWords — упрощённое разбиение строки shell на слова: одинарные и
// двойные кавычки снимаются, пустые кавычки дают пустое слово.
func shellWords(line string) []string {
	var words []string
	var cur strings.Builder
	inWord, quote := false, byte(0)
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
			quote, inWord = c, true
		case c == ' ' || c == '\t':
			if inWord {
				words = append(words, cur.String())
				cur.Reset()
				inWord = false
			}
		default:
			cur.WriteByte(c)
			inWord = true
		}
	}
	if inWord {
		words = append(words, cur.String())
	}
	return words
}

// actionlintCall — аргументы одного вызова: всё после слова с /cmd/actionlint@.
type actionlintCall struct {
	path, job, step string
	args            []string
}

func actionlintCalls(t *testing.T, path string) []actionlintCall {
	t.Helper()
	wf := loadWorkflow(t, path)
	var calls []actionlintCall
	for jobName, j := range wf.Jobs {
		for _, s := range j.Steps {
			body := strings.ReplaceAll(stripShellComments(s.Run), "\\\n", " ")
			for _, line := range strings.Split(body, "\n") {
				if !actionlintAnyRe.MatchString(line) {
					continue
				}
				// Вызов внутри подстановки команды: out="$(go run … 2>&1)".
				// Разбирается содержимое подстановки, иначе внешние кавычки
				// склеили бы вызов в одно слово.
				if at := strings.Index(line, "$("); at >= 0 && at < actionlintAnyRe.FindStringIndex(line)[0] {
					if end := strings.LastIndex(line, ")"); end > at {
						line = line[at+2 : end]
					}
				}
				words := shellWords(line)
				for i, w := range words {
					if actionlintAnyRe.MatchString(w) {
						// Хвост строки после пайпа/перенаправления/`||` — уже не
						// аргументы вызова.
						var args []string
						for _, a := range words[i+1:] {
							if a == "|" || a == "||" || a == "&&" || a == ";" || strings.HasPrefix(a, ">") || strings.HasPrefix(a, "2>") {
								break
							}
							args = append(args, a)
						}
						calls = append(calls, actionlintCall{path: path, job: jobName, step: s.Name, args: args})
						break
					}
				}
			}
		}
	}
	return calls
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
		where := c.path + " (job " + c.job + ", шаг «" + c.step + "»)"
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
				t.Errorf("%s: флаг %s вне закрытого списка allowedActionlintFlags — вызов может ничего не "+
					"разбирать (--version, -ignore, -init-config…). Флаг законен? Внеси его строкой в список", where, name)
				continue
			}
			if takesArg && !hasEq {
				if i+1 >= len(c.args) {
					val = ""
				} else {
					i++
					val = c.args[i]
				}
			}
			if name == "-shellcheck" {
				if strings.TrimSpace(val) == "" {
					t.Errorf("%s: -shellcheck с пустым значением — actionlint молча не разбирает bash внутри run:", where)
					shellcheckEmpty = true
					continue
				}
				shellcheck = true
			}
		}
		// Одна причина — одно сообщение: пустое значение уже названо выше.
		if !shellcheck && !shellcheckEmpty {
			t.Errorf("%s: вызов actionlint без -shellcheck <путь> — bash внутри run: не разбирается", where)
		}
		if len(files) == 0 {
			t.Errorf("%s: вызов actionlint без файлов — разбирать нечего (аргументы: %q)", where, c.args)
			continue
		}
		sort.Strings(files)
		if strings.Join(files, " ") == strings.Join(want, " ") {
			realFound = true
		}
	}
	if !realFound {
		t.Errorf("нет вызова actionlint, получающего на вход ровно оба workflow %v — настоящий разбор "+
			"исчез или лишился предмета", want)
	}
}
