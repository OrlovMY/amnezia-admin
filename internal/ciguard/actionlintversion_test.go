// Файл actionlintversion_test.go — сторож версии actionlint и того, что
// шаги с ним существуют и исполняются.
//
// scripts/dev-tools.sh — ЕДИНЫЙ источник версий инструментов. До A6
// release.yml держал свою строку `actionlint@v1.7.12` — второй источник,
// который однажды разошёлся бы молча. A6 удалил тот шаг целиком (проверку
// несёт ci.yml), и с тех пор литеральный пин не законен ни в одном
// workflow-файле: ci.yml берёт версию из $ACTIONLINT_VERSION, который кладёт
// в окружение сам dev-tools.sh. Все три файла здесь только читаются.
package ciguard

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

const (
	releaseYML  = "../../.github/workflows/release.yml"
	ciYML       = "../../.github/workflows/ci.yml"
	devToolsSH  = "../../scripts/dev-tools.sh"
	actionlintM = "github.com/rhysd/actionlint"
)

// Литеральная версия в вызове `go run github.com/rhysd/actionlint/...@vX.Y.Z`.
// Форма `@${ACTIONLINT_VERSION}` под это выражение не подходит и правильно не
// считается вхождением: там версии нет, там ссылка на единый источник.
var actionlintPinRe = regexp.MustCompile(regexp.QuoteMeta(actionlintM) + `/cmd/actionlint@(v[0-9]+\.[0-9]+\.[0-9]+)`)

// Объявление версии в единственном источнике.
var devToolsVersionRe = regexp.MustCompile(`(?m)^ACTIONLINT_VERSION="(v[0-9]+\.[0-9]+\.[0-9]+)"\s*$`)

// Переопределение версии: YAML-ключ env или присваивание в shell. Форма
// `${ACTIONLINT_VERSION}` и `${ACTIONLINT_VERSION:-}` сюда не попадает.
var versionOverrideRe = regexp.MustCompile(`(?m)^\s*ACTIONLINT_VERSION\s*:.*$|(?:^|[^{A-Za-z0-9_])ACTIONLINT_VERSION=\S*`)

func readFile(t *testing.T, path string) string {
	t.Helper()
	data := readSource(t, path)
	return string(data)
}

func TestActionlintVersionSingleSource(t *testing.T) {
	m := devToolsVersionRe.FindStringSubmatch(readFile(t, devToolsSH))
	if m == nil {
		t.Fatalf("в %s не найдено объявление ACTIONLINT_VERSION=\"vX.Y.Z\" — тест перестал что-либо проверять", devToolsSH)
	}
	want := m[1]

	// С A6 литеральный пин не законен НИГДЕ: слабый шаг release.yml удалён,
	// ci.yml берёт версию из $ACTIONLINT_VERSION. Любой литерал — второй
	// источник версии, то есть ровно тот дефект, ради которого заведён пакет.
	// Поиск идёт по сырому тексту, включая комментарии: вызов, «временно»
	// спрятанный в комментарий, — тоже второй источник, который разойдётся.
	for _, path := range []string{releaseYML, ciYML} {
		for _, pin := range actionlintPinRe.FindAllStringSubmatch(readFile(t, path), -1) {
			t.Errorf("в %s литеральная версия actionlint %s (scripts/dev-tools.sh объявляет %s).\n"+
				"  Единственный источник версии — scripts/dev-tools.sh; вызов обязан иметь форму @${ACTIONLINT_VERSION}.",
				path, pin[1], want)
		}
	}

	// Второй источник версии без литерала в вызове (ревью QA-01): ключ
	// `ACTIONLINT_VERSION:` в env workflow, job или шага, либо присваивание
	// `ACTIONLINT_VERSION=` в теле run: (включая запись в $GITHUB_ENV).
	// Любое из них перекрывает значение из dev-tools.sh, а вызов при этом
	// остаётся формы @${ACTIONLINT_VERSION}, и сторож выше его одобряет.
	for _, path := range []string{releaseYML, ciYML} {
		for _, hit := range versionOverrideRe.FindAllString(readFile(t, path), -1) {
			t.Errorf("в %s переопределяет ACTIONLINT_VERSION: «%s» — второй источник версии; "+
				"единственный — scripts/dev-tools.sh", path, strings.TrimSpace(hit))
		}
	}

	// Литералов нет — это правильное состояние, но оно же выглядело бы так,
	// если бы регулярка перестала попадать вообще во что-либо. Поэтому
	// обязателен хотя бы один вызов через единый источник: без него
	// «литералов не найдено» ничего не значит.
	if !actionlintVarRe.MatchString(readFile(t, ciYML)) {
		t.Fatalf("в %s не найдено ни одного вызова %s/cmd/actionlint@${ACTIONLINT_VERSION} — "+
			"тест перестал что-либо проверять", ciYML, actionlintM)
	}
}

// ---------------------------------------------------------------------------
// Второй сторож того же предмета: вызов actionlint обязан существовать ИМЕННО
// ТЕМ ШАГОМ, которым он обязан быть, и этот шаг обязан исполняться.
//
// Обход первого сторожа, дословно по механизму. Условие `found == 0` выше не
// требует ничего ПРО КОНКРЕТНЫЙ ФАЙЛ: «найден хотя бы один литерал, и все
// найденные совпадают». Убрать пин из release.yml и закрепить версию литералом
// в ci.yml — found == 1, все найденные совпадают, тест зелёный, а на теге
// actionlint не запускается. Проверено прогоном до починки: PASS.
//
// Тот же дефект живёт на каждом следующем этаже, и это главный урок здесь:
// требование, привязанное к ФАЙЛУ, ничего не говорит про ШАГ. В ci.yml вызовов
// два — канарейка (проверяет, что shellcheck вправду подключён, и гоняет
// actionlint на собственном временном файле) и настоящий разбор обоих
// workflow. Требование «в ci.yml не менее одного вызова» удовлетворяется одной
// канарейкой, поэтому удаление НАСТОЯЩЕГО разбора проходило зелёным. Поэтому
// таблица ниже — таблица ТРЕБУЕМЫХ ШАГОВ, а не счётчик вхождений в файл:
// каждая строка называет, что обязано стоять в одном теле `run:` вместе с
// вызовом.
//
// Чем шаг может быть обеззублен, не исчезнув из файла (всё это — правдоподобные
// однострочные правки, каждая предъявлена покрасневшей):
//   - строка с вызовом перенесена в YAML-комментарий;
//   - строка с вызовом закомментирована внутри самого `run:` (shell-комментарий);
//   - шаг стоит под `if:` с условием, которое никогда не истинно;
//   - то же условие стоит этажом выше, на job;
//   - условие ДОПУСТИМОЕ ПО ТЕКСТУ, но ложное по контексту: `matrix.os ==
//     'linux'` в job без матрицы, или значение `linux`, вынутое из матрицы
//     этого job. Текст цел, смысл — ложь; см. allowedActionlintGates;
//   - шаг или job помечен `continue-on-error: true` — тогда он исполняется, но
//     его падение ничего не роняет, то есть проверка есть и не проверяет ничего.
//
// Презумпция по `if:` ИНВЕРТИРОВАНА, и это существенно. Сторож не пытается
// вычислить, ложно ли условие: `matrix.os == 'nonexistent'`,
// `${{ false || false }}`, `github.repository == 'nobody/nothing'` — заведомо
// ложны, но опознать их перечислением лжи нельзя, список лжи бесконечен.
// Поэтому список конечен с другой стороны: сторож знает ЗАКРЫТЫЙ СПИСОК
// допустимых условий, и любое другое условие на шаге с вызовом (или на его
// job) роняет тест с требованием внести условие в таблицу явной строкой. Тот
// же приём уже применён в runnerarch_test.go к меткам раннеров: метка, которой
// нет в таблице, роняет тест, а не пропускается. Законное изменение условия от
// этого не становится невозможным — оно становится ВИДИМЫМ В ДИФФЕ.
//
// ГРАНИЦА, достигнутая на самом деле, и она уже, чем хочется. Сторож НЕ ВИДИТ
// YAML-КОММЕНТАРИЯ (разбор идёт YAML-разборщиком) и НЕ ВИДИТ SHELL-КОММЕНТАРИЯ
// внутри `run:` (строки, у которых первый непробельный символ — `#`,
// отбрасываются). Но ВЫЗОВ ВНУТРИ СТРОКОВОГО ЛИТЕРАЛА ОТЛИЧИТЬ НЕ МОЖЕТ:
// `echo "... /cmd/actionlint@v1.7.12 ..."` в чужом шаге для него неотличим от
// настоящего вызова — для этого нужен разбор shell, а не поиск по тексту.
// Требование совместного вхождения путей workflow (поле mustContain) делает
// такую подделку заметно дороже, но не невозможной. Прежняя формулировка
// «сторож обязан не видеть того, что не исполняется» была обещанием сверх
// сделанного и заменена на эту — на то, что достигнуто.
//
// Про A6. PR-A6 удалил слабый actionlint из release.yml — это ЗАКОННОЕ
// изменение, и строка требования удалена в том же PR видимой строкой
// («вызова больше нет, шаг удалён, проверку несёт ci.yml»). Разница между
// обходом и законным изменением ровно одна: обход молчит, законное изменение
// правит таблицу и видно в диффе. Эта фраза и есть смысл таблицы.
//
// Чего этот сторож НЕ видит и видеть не обязан: СМЫСЛА вызова. Вызов с
// `--version`, без файлов или с `-ignore '.*'` проходит здесь зелёным, если
// пути workflow стоят где-то в том же теле run:. Смысл стережёт
// invocation_test.go (A6, следствие A5 № 2).
// ---------------------------------------------------------------------------

// Вызов через единый источник версии: `@${ACTIONLINT_VERSION}`.
var actionlintVarRe = regexp.MustCompile(regexp.QuoteMeta(actionlintM) + `/cmd/actionlint@\$\{ACTIONLINT_VERSION\}`)

// Любой вызов actionlint, в какой бы форме версия ни стояла. Нужен, чтобы
// отличить «шага нет вовсе» от «шаг есть, но переписан», — сообщение обязано
// называть настоящую причину.
var actionlintAnyRe = regexp.MustCompile(regexp.QuoteMeta(actionlintM) + `/cmd/actionlint@`)

// allowedActionlintGates — ЗАКРЫТЫЙ СПИСОК условий `if:`, при которых шаг с
// вызовом actionlint (или его job) считается исполняемым. Ключ — условие в
// нормализованном виде (снят `${{ }}`, схлопнуты пробелы).
//
// Список закрыт намеренно: перечислить все заведомо ложные условия нельзя, их
// бесконечно много, — а перечислить допустимые можно, их на этой базе одно.
// Значение строки — причина, по которой условие допущено; она печатается в
// сообщении об ошибке, чтобы правящий видел, во что вписывается.
//
// НО ТЕКСТА УСЛОВИЯ НЕДОСТАТОЧНО, и это отдельный урок (ревью, MEDIUM-1/2).
// Допущенное по тексту условие бывает ложным ВСЕГДА — из-за контекста, а не
// из-за текста:
//   - `matrix.os == 'linux'` в job, у которого матрицы нет вовсе (в ci.yml job
//     lint именно такой): ссылка на matrix.os не истинна никогда, шаг молчит,
//     сторож зелёный. Строки между workflow переносят постоянно, так что это
//     самая обычная правка. Цена особая: ci.yml в комментарии к job lint
//     ОБЪЯВЛЯЕТ отсутствие матрицы и `if:` защитным свойством — свойство
//     объявлено, а сторожа у него не было;
//   - то же с другой стороны: условие цело, а `os: linux` вынут из матрицы job
//     test в release.yml — шаг умолкает молча. Соседний сторож это не ловит:
//     matrix_test.go сверяет job `build` против job `checks`, а матрица job
//     `test` не сверяется ничем, хотя именно от неё зависит, запустится ли
//     actionlint на теге.
//
// Поэтому допускается ПАРА «условие + контекст»: если условие ссылается на
// `matrix.<ключ> == '<значение>'`, в матрице ЭТОГО job такое значение обязано
// присутствовать. Нет матрицы или нет значения — красный, с тем же требованием
// внести условие явной строкой. Это тот же приём, только применённый к правой
// части условия.
var allowedActionlintGates = map[string]string{
	"": "условия нет — шаг исполняется всегда",
	// Строка `matrix.os == 'linux'` удалена в A6 вместе с шагом release.yml,
	// которому она принадлежала: допущенное условие без шага — лишняя дверь.
}

// Ссылка на матрицу в условии: `matrix.<ключ> == '<значение>'` (кавычки любые).
var matrixRefRe = regexp.MustCompile(`^matrix\.([A-Za-z0-9_.-]+) == ['"]([^'"]*)['"]$`)

// gateAllowed — допустимо ли условие с учётом матрицы того job, в котором оно
// стоит. Возвращает причину отказа, готовую к печати.
func gateAllowed(gate, jobName string, matrix []map[string]string) (bool, string) {
	if _, ok := allowedActionlintGates[gate]; !ok {
		return false, fmt.Sprintf("условие if: %q, которого НЕТ в закрытом списке allowedActionlintGates — "+
			"сторож не берётся считать такой шаг исполняемым.\n"+
			"      Условие законно? Внеси его в allowedActionlintGates отдельной строкой с причиной — "+
			"тогда это видно в диффе", gate)
	}

	m := matrixRefRe.FindStringSubmatch(gate)
	if m == nil {
		return true, ""
	}
	key, want := m[1], m[2]

	if len(matrix) == 0 {
		return false, fmt.Sprintf("условие if: %q допустимо СПИСКОМ, но у job %s НЕТ МАТРИЦЫ ВОВСЕ — "+
			"ссылка на matrix.%s не истинна никогда, и шаг не исполнится ни разу.\n"+
			"      Текст условия цел, смысл его — ложь. Условие законно в этом контексте? "+
			"Внеси его в allowedActionlintGates отдельной строкой с причиной — тогда это видно в диффе",
			gate, jobName, key)
	}

	var seen []string
	for _, entry := range matrix {
		if v, ok := entry[key]; ok {
			seen = append(seen, v)
			if v == want {
				return true, ""
			}
		}
	}
	sort.Strings(seen)
	return false, fmt.Sprintf("условие if: %q допустимо СПИСКОМ, но в матрице job %s нет элемента с %s: %s "+
		"(есть: %v) — шаг не исполнится ни разу.\n"+
		"      Значение вынули из матрицы, а условие осталось: текст цел, смысл его — ложь. "+
		"Так и задумано? Внеси условие в allowedActionlintGates отдельной строкой с причиной — "+
		"тогда это видно в диффе", gate, jobName, key, want, seen)
}

// actionlintRequirement — один ТРЕБУЕМЫЙ ШАГ: вызов такой-то формы, в одном
// теле `run:` вместе с перечисленным.
type actionlintRequirement struct {
	path        string
	what        string         // как называть требование в сообщении
	call        *regexp.Regexp // форма вызова
	mustContain []string       // что обязано стоять в том же теле run:
	why         string         // чем строка обоснована и что правит её законно
}

// Таблица требуемых шагов заведена ПО ФАКТУ базы, а не по общей формуле «в
// каждом файле не менее одного литерального пина»: в ci.yml литерального пина
// нет и быть не должно — он был бы вторым источником версии, то есть ровно тем
// дефектом, ради которого заведён этот пакет.
var actionlintRequirements = []actionlintRequirement{
	// Строки «разбор release.yml на теге (версия литералом)» здесь больше
	// нет — удалена в A6 законно и видимо: шаг actionlint из release.yml
	// убран целиком, проверку несёт ci.yml (строка «настоящий разбор ОБОИХ
	// workflow» ниже). Смысл того вызова стережёт invocation_test.go.
	{
		path:        ciYML,
		what:        "канарейка: actionlint вправду применяет shellcheck к bash внутри run:",
		call:        actionlintVarRe,
		mustContain: []string{"-shellcheck", "canary"},
		why: "молчащий actionlint без shellcheck этот проект уже проходил; канарейка гоняет линтер " +
			"на собственном временном файле с заведомой ошибкой SC2086 и роняет job, если её не поймали",
	},
	{
		path:        ciYML,
		what:        "настоящий разбор ОБОИХ workflow на PR",
		call:        actionlintVarRe,
		mustContain: []string{".github/workflows/release.yml", ".github/workflows/ci.yml"},
		why: "это и есть проверка, ради которой всё остальное. Требование привязано к ШАГУ, а не к файлу, " +
			"именно потому, что счёт по файлу удовлетворялся одной канарейкой — и удаление настоящего " +
			"разбора проходило зелёным",
	},
}

// wfSteps — ровно та часть схемы workflow-файла, которая нужна этому сторожу.
// If и ContinueOnError берутся как interface{}: `if: false` и
// `continue-on-error: true` — YAML-булевы, в строку они не разбираются, и
// сторож упал бы на разборе вместо того, чтобы засчитать шаг отключённым.
type wfSteps struct {
	Jobs map[string]struct {
		If              interface{} `yaml:"if"`
		ContinueOnError interface{} `yaml:"continue-on-error"`
		Strategy        struct {
			Matrix struct {
				Include []map[string]string `yaml:"include"`
			} `yaml:"matrix"`
		} `yaml:"strategy"`
		Steps []struct {
			If              interface{} `yaml:"if"`
			ContinueOnError interface{} `yaml:"continue-on-error"`
			Run             string      `yaml:"run"`
		} `yaml:"steps"`
	} `yaml:"jobs"`
}

// normalizeGate снимает `${{ }}` и схлопывает пробелы, чтобы условие
// сравнивалось с таблицей по смыслу записи, а не по форматированию.
func normalizeGate(v interface{}) string {
	if v == nil {
		return ""
	}
	s := strings.TrimSpace(fmt.Sprint(v))
	if strings.HasPrefix(s, "${{") && strings.HasSuffix(s, "}}") {
		s = strings.TrimSuffix(strings.TrimPrefix(s, "${{"), "}}")
	}
	return strings.Join(strings.Fields(s), " ")
}

func isTrue(v interface{}) bool {
	if v == nil {
		return false
	}
	return strings.EqualFold(normalizeGate(v), "true")
}

// stripShellComments выбрасывает строки тела `run:`, у которых первый
// непробельный символ — `#`. Без этого закомментированный внутри скрипта вызов
// засчитывался как исполняемый: YAML-разбор видит тело шага целиком и про shell
// ничего не знает.
func stripShellComments(run string) string {
	var kept []string
	for _, line := range strings.Split(run, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		kept = append(kept, line)
	}
	return strings.Join(kept, "\n")
}

// runStep — один шаг с телом `run:` и приговор о том, исполняется ли он.
type runStep struct {
	job    string
	body   string // тело run: без shell-комментариев
	live   bool
	reason string // почему не live — дословно идёт в сообщение
}

func runStepsOf(t *testing.T, path string) []runStep {
	t.Helper()

	data := readSource(t, path)

	var wf wfSteps
	if err := yaml.Unmarshal(data, &wf); err != nil {
		t.Fatalf("не разобрать %s как YAML: %v", path, err)
	}
	if len(wf.Jobs) == 0 {
		t.Fatalf("в %s не найдено ни одного job — тест перестал что-либо проверять", path)
	}

	var out []runStep
	total := 0
	for jobName, job := range wf.Jobs {
		matrix := job.Strategy.Matrix.Include
		jobGate := normalizeGate(job.If)
		jobGateOK, jobGateWhy := gateAllowed(jobGate, jobName, matrix)
		jobCOE := isTrue(job.ContinueOnError)

		for _, step := range job.Steps {
			total++
			if step.Run == "" {
				continue
			}
			stepGate := normalizeGate(step.If)
			stepGateOK, stepGateWhy := gateAllowed(stepGate, jobName, matrix)

			s := runStep{job: jobName, body: stripShellComments(step.Run), live: true}
			switch {
			case jobCOE:
				s.live, s.reason = false, fmt.Sprintf("job %s помечен continue-on-error: true — шаг исполняется, "+
					"но его падение ничего не роняет, то есть проверка есть и не проверяет ничего", jobName)
			case isTrue(step.ContinueOnError):
				s.live, s.reason = false, "шаг помечен continue-on-error: true — он исполняется, "+
					"но его падение ничего не роняет, то есть проверка есть и не проверяет ничего"
			case !jobGateOK:
				s.live, s.reason = false, "job "+jobName+" стоит под условием, которое сторож не принял: "+jobGateWhy
			case !stepGateOK:
				s.live, s.reason = false, "шаг стоит под условием, которое сторож не принял: "+stepGateWhy
			}
			out = append(out, s)
		}
	}
	if total == 0 {
		t.Fatalf("в %s не найдено ни одного шага — тест перестал что-либо проверять", path)
	}
	return out
}

func containsAll(body string, subs []string) bool {
	for _, sub := range subs {
		if !strings.Contains(body, sub) {
			return false
		}
	}
	return true
}

// matches — удовлетворяет ли тело шага требованию: вызов нужной формы И всё,
// что обязано стоять с ним в одном теле run:.
func (r actionlintRequirement) matches(body string) bool {
	return r.call.MatchString(body) && containsAll(body, r.mustContain)
}

func TestActionlintPinnedInEveryExpectedFile(t *testing.T) {
	if len(actionlintRequirements) == 0 {
		t.Fatalf("таблица требуемых шагов actionlintRequirements пуста — тест перестал что-либо проверять")
	}
	if len(allowedActionlintGates) == 0 {
		t.Fatalf("закрытый список allowedActionlintGates пуст — тест перестал что-либо проверять")
	}

	steps := map[string][]runStep{}
	for _, req := range actionlintRequirements {
		if _, done := steps[req.path]; !done {
			steps[req.path] = runStepsOf(t, req.path)
		}

		var blocked []string
		satisfied := false
		for _, s := range steps[req.path] {
			if !req.matches(s.body) {
				continue
			}
			if s.live {
				satisfied = true
				break
			}
			blocked = append(blocked, "    "+s.reason)
		}
		if satisfied {
			continue
		}

		switch {
		case len(blocked) > 0:
			t.Errorf("в %s шаг «%s» найден, но обеззублен — сторож считает его отсутствующим:\n%s\n  %s",
				req.path, req.what, strings.Join(blocked, "\n"), req.why)
		case actionlintAnyRe.MatchString(readFile(t, req.path)):
			t.Errorf("в %s нет исполняемого шага «%s»: вызовы actionlint в файле есть, но ни один не стоит "+
				"в одном теле run: вместе с %v — шаг удалён, переписан или перенесён в комментарий.\n  %s",
				req.path, req.what, req.mustContain, req.why)
		default:
			t.Errorf("в %s не найдено ни одного вызова %s/cmd/actionlint@ — шаг «%s» исчез целиком, "+
				"и тест по этой строке перестал что-либо проверять.\n  %s",
				req.path, actionlintM, req.what, req.why)
		}
	}
}
