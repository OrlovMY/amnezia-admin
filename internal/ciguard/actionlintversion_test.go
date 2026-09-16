// Файл actionlintversion_test.go — сторож второго списка, живущего в двух
// файлах: версии actionlint.
//
// scripts/dev-tools.sh объявлен ЕДИНЫМ источником версий инструментов, но
// release.yml держит свою строку `actionlint@v1.7.12`, и править release.yml
// запрещено. Пока расхождение ничем не краснеет, оно относится ровно к тому
// классу, ради которого заведён этот пакет: два числа в двух файлах, которые
// однажды разъедутся молча — и на теге будет разбирать workflow один линтер,
// а на PR другой.
//
// ci.yml сюда не попадает намеренно: он версию не хардкодит, а берёт её из
// $ACTIONLINT_VERSION, который кладёт в окружение сам dev-tools.sh. Если в
// ci.yml когда-нибудь появится литеральная версия, сторож увидит и её —
// поиск идёт по обоим workflow-файлам. Все три файла здесь только читаются.
package ciguard

import (
	"fmt"
	"os"
	"regexp"
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

func readFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("не прочитать %s: %v", path, err)
	}
	return string(data)
}

func TestActionlintVersionSingleSource(t *testing.T) {
	m := devToolsVersionRe.FindStringSubmatch(readFile(t, devToolsSH))
	if m == nil {
		t.Fatalf("в %s не найдено объявление ACTIONLINT_VERSION=\"vX.Y.Z\" — тест перестал что-либо проверять", devToolsSH)
	}
	want := m[1]

	found := 0
	for _, path := range []string{releaseYML, ciYML} {
		for _, pin := range actionlintPinRe.FindAllStringSubmatch(readFile(t, path), -1) {
			found++
			if pin[1] != want {
				t.Errorf("версия actionlint разошлась: %s требует %s, а scripts/dev-tools.sh объявляет %s.\n"+
					"  На теге и на PR workflow разбирали бы разные линтеры, и ни одна проверка бы этого не показала.",
					path, pin[1], want)
			}
		}
	}

	// Ни одного литерального пина не найдено — значит регулярка перестала
	// попадать в текст (переписали вызов, перенесли строку), и сравнивать
	// больше нечего. Зелёным это быть не имеет права.
	if found == 0 {
		t.Fatalf("ни в %s, ни в %s не найдено ни одного вызова %s/cmd/actionlint@vX.Y.Z — тест перестал что-либо проверять",
			releaseYML, ciYML, actionlintM)
	}
}

// ---------------------------------------------------------------------------
// Второй сторож того же предмета: вызов обязан быть в КАЖДОМ файле, который
// таблица ожиданий требует, — и обязан быть ИСПОЛНЯЕМЫМ.
//
// В чём обход первого сторожа, дословно по механизму. Условие `found == 0`
// выше не требует ничего ПРО КОНКРЕТНЫЙ ФАЙЛ: «найден хотя бы один литерал, и
// все найденные совпадают». Убрать пин из release.yml и закрепить версию
// литералом в ci.yml — found == 1, все найденные совпадают, тест зелёный. При
// этом на теге actionlint либо не запускается вовсе, либо запускается в форме,
// которую сторож не видит, — и ни одна проверка этого не покажет. Два шага,
// каждый по отдельности выглядит безобидно. Проверено прогоном до починки:
// давало PASS.
//
// Второй обход того же класса, дешевле первого: оставить строку с пином, но
// сделать её НЕИСПОЛНЯЕМОЙ — перенести в YAML-комментарий или оставить шаг под
// `if: false`. Поиск регулярным выражением по сырому тексту засчитал бы такой
// пин как присутствующий. Поэтому здесь разбор YAML и счёт только внутри
// строк `run:` исполняемых шагов. Смысл сторожа в одной фразе, и обе стороны
// названы нарочно: сторож обязан НЕ ВИДЕТЬ того, что не исполняется, ровно так
// же, как обязан ВИДЕТЬ то, что исполняется.
//
// Отключённым считается только заведомо ложное условие (`false`,
// `${{ false }}`), и на уровне job — тоже: шаг внутри отключённого job считается
// отсутствующим, этаж, на котором стоит условие, значения не имеет.
// Содержательное условие отключением НЕ является: шаг actionlint в release.yml
// несёт `if: matrix.os == 'linux'` и обязан засчитываться.
//
// Про A6, чтобы починка не стала препятствием. PR-A6 удаляет слабый actionlint
// из release.yml — это ЗАКОННОЕ изменение. После него таблица ожиданий
// правится в том же PR A6, одной видимой строкой: «release.yml — ноль пинов,
// потому что шаг удалён, проверку несёт ci.yml». Разница между обходом и
// законным изменением ровно одна: обход молчит, законное изменение правит
// таблицу и видно в диффе. Эта фраза и есть смысл таблицы ниже.
// ---------------------------------------------------------------------------

// Вызов через единый источник версии: `@${ACTIONLINT_VERSION}`.
var actionlintVarRe = regexp.MustCompile(regexp.QuoteMeta(actionlintM) + `/cmd/actionlint@\$\{ACTIONLINT_VERSION\}`)

// actionlintExpectation — сколько вызовов какого вида файл обязан содержать в
// исполняемых шагах.
type actionlintExpectation struct {
	path       string
	minLiteral int    // вызовов с литеральным пином @vX.Y.Z
	minVarRef  int    // вызовов через @${ACTIONLINT_VERSION}
	why        string // чем эта строка обоснована и что правит её законно
}

// Таблица ожиданий заведена ПО ФАКТУ базы, а не по общей формуле «в каждом
// файле не менее одного литерального пина»: в ci.yml литерального пина нет и
// быть не должно — он был бы вторым источником версии, то есть ровно тем
// дефектом, ради которого заведён этот пакет.
var actionlintExpectations = []actionlintExpectation{
	{
		path:       releaseYML,
		minLiteral: 1,
		minVarRef:  0,
		why: "release.yml не подключает scripts/dev-tools.sh и потому держит версию литералом; " +
			"ноль литералов здесь означает, что на теге actionlint не запускается. " +
			"Строка правится законно в A6, где шаг удаляют целиком — тогда minLiteral становится 0 " +
			"с записью «проверку несёт ci.yml», и это видно в диффе",
	},
	{
		path:       ciYML,
		minLiteral: 0,
		minVarRef:  1,
		why: "ci.yml версию не хардкодит, а берёт из $ACTIONLINT_VERSION, который кладёт в окружение " +
			"сам scripts/dev-tools.sh — литеральный пин здесь был бы вторым источником версии. " +
			"Но и молчать про ci.yml нельзя: без требования minVarRef удаление actionlint из ci.yml " +
			"прошло бы зелёным",
	},
}

// wfSteps — ровно та часть схемы workflow-файла, которая нужна этому сторожу.
// If берётся как interface{}: `if: false` — это YAML-булево, в строку оно не
// разбирается, и сторож упал бы на разборе вместо того, чтобы засчитать шаг
// отключённым.
type wfSteps struct {
	Jobs map[string]struct {
		If    interface{} `yaml:"if"`
		Steps []struct {
			If  interface{} `yaml:"if"`
			Run string      `yaml:"run"`
		} `yaml:"steps"`
	} `yaml:"jobs"`
}

// disabledByIf — условие, заведомо ложное при любом входе. Содержательное
// условие (`matrix.os == 'linux'`) отключением не считается: сторож судит о
// том, что заведомо не исполнится, а не о том, что исполнится не всегда.
func disabledByIf(v interface{}) bool {
	if v == nil {
		return false
	}
	s := strings.TrimSpace(fmt.Sprint(v))
	s = strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(s, "${{"), "}}"))
	return strings.EqualFold(s, "false")
}

// executableRuns возвращает тела `run:` тех шагов, которые на этой базе
// исполнятся, и отдельно — тела шагов, отключённых условием if. Второе нужно
// не для счёта, а для того, чтобы сообщение об ошибке называло настоящую
// причину, а не «не нашли».
func executableRuns(t *testing.T, path string) (live, disabled []string) {
	t.Helper()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("не прочитать %s: %v", path, err)
	}

	var wf wfSteps
	if err := yaml.Unmarshal(data, &wf); err != nil {
		t.Fatalf("не разобрать %s как YAML: %v", path, err)
	}
	if len(wf.Jobs) == 0 {
		t.Fatalf("в %s не найдено ни одного job — тест перестал что-либо проверять", path)
	}

	steps := 0
	for _, job := range wf.Jobs {
		jobOff := disabledByIf(job.If)
		for _, step := range job.Steps {
			steps++
			if step.Run == "" {
				continue
			}
			if jobOff || disabledByIf(step.If) {
				disabled = append(disabled, step.Run)
				continue
			}
			live = append(live, step.Run)
		}
	}
	if steps == 0 {
		t.Fatalf("в %s не найдено ни одного шага — тест перестал что-либо проверять", path)
	}
	return live, disabled
}

func countIn(re *regexp.Regexp, bodies []string) int {
	n := 0
	for _, b := range bodies {
		n += len(re.FindAllString(b, -1))
	}
	return n
}

func TestActionlintPinnedInEveryExpectedFile(t *testing.T) {
	if len(actionlintExpectations) == 0 {
		t.Fatalf("таблица ожиданий actionlintExpectations пуста — тест перестал что-либо проверять")
	}

	for _, exp := range actionlintExpectations {
		live, disabled := executableRuns(t, exp.path)

		gotLiteral := countIn(actionlintPinRe, live)
		if gotLiteral < exp.minLiteral {
			inDisabled := countIn(actionlintPinRe, disabled)
			inRaw := len(actionlintPinRe.FindAllString(readFile(t, exp.path), -1))
			switch {
			case inDisabled > 0:
				t.Errorf("в %s вызов actionlint найден, но шаг (или его job) отключён условием if — "+
					"сторож считает его отсутствующим.\n  Требуется не менее %d в исполняемых run:, найдено %d.\n  %s",
					exp.path, exp.minLiteral, gotLiteral, exp.why)
			case inRaw > 0:
				t.Errorf("в %s вызов %s/cmd/actionlint@vX.Y.Z присутствует в тексте (%d), но НЕ в исполняемом run: "+
					"(перенесён в комментарий или в неисполняемое место) — сторож считает его отсутствующим.\n"+
					"  Требуется не менее %d, найдено %d.\n  %s",
					exp.path, actionlintM, inRaw, exp.minLiteral, gotLiteral, exp.why)
			default:
				t.Errorf("в %s не найдено ни одного вызова %s/cmd/actionlint@vX.Y.Z, хотя таблица ожиданий его требует "+
					"(не менее %d, найдено %d) — либо вызов убрали, либо переписали так, что сторож его не видит.\n  %s",
					exp.path, actionlintM, exp.minLiteral, gotLiteral, exp.why)
			}
		}

		gotVar := countIn(actionlintVarRe, live)
		if gotVar < exp.minVarRef {
			inDisabled := countIn(actionlintVarRe, disabled)
			if inDisabled > 0 {
				t.Errorf("в %s вызов actionlint через ${ACTIONLINT_VERSION} найден, но шаг (или его job) отключён "+
					"условием if — сторож считает его отсутствующим.\n  Требуется не менее %d, найдено %d.\n  %s",
					exp.path, exp.minVarRef, gotVar, exp.why)
				continue
			}
			t.Errorf("в %s не найдено ни одного вызова %s/cmd/actionlint@${ACTIONLINT_VERSION} в исполняемом run:, "+
				"хотя таблица ожиданий его требует (не менее %d, найдено %d).\n  %s",
				exp.path, actionlintM, exp.minVarRef, gotVar, exp.why)
		}
	}
}
