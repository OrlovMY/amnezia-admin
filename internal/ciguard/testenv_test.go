// Файл testenv_test.go — job test (release.yml) до шага go test обязан
// совпадать с job checks (ci.yml) шаг в шаг.
//
// Инцидент v0.3.0-rc.1 (03.10.2026). Шаг «Оболочки для скрипта записи»
// (busybox) был только в ci.yml. На теге TestCASScriptRealShells шёл в
// busybox-static образа ubuntu-24.04, который вызывает апплеты в обход PATH,
// — подмена «утилиты нет» не действовала, и релиз упал.
//
// Первая версия сторожа сверяла только шаги, похожие на подготовку
// окружения (по маркерам), и не смотрела, где они стоят. AU-LOGIC High-1:
// шаг busybox, перенесённый ПОСЛЕ go test, оставлял сторож зелёным. Поэтому
// правило — закрытый список, а не перечень плохого:
//
//  1. ВСЕ шаги от начала job до шага go test включительно (шаг go test
//     находится по команде в теле, а не по имени) совпадают в двух файлах по
//     порядку и содержимому: name, uses, if, shell, env, with, run (без
//     комментариев и отступов). Различия — только из таблиц ниже, у каждой
//     записи причина; неиспользованная запись — красная.
//  2. После go test ни в одном из двух job нет шага подготовки окружения
//     (setup-*, установка пакетов, запись в $GITHUB_PATH/$GITHUB_ENV):
//     такой шаг тестам уже не служит, а выглядит, будто служит.
//  3. env:/defaults: уровня workflow и job совпадают.
package ciguard

import (
	"fmt"
	"sort"
	"strings"
	"testing"
)

// onlyInOne — шаги до go test, которые есть только в одном из двух job.
// Ключ — файл и имя шага.
var onlyInOne = map[string]string{
	releaseYML + "|Гарантировать origin/main для merge-base": "релиз: ссылка origin/main для проверки происхождения тега; на PR тега нет",
	releaseYML + "|Происхождение тега":                       "релиз: тег — предок origin/main и semver; на PR тега нет",
	ciYML + "|Версии инструментов (раннер предъявляет себя)": "ci.yml: печать версий инструментов; окружение не меняет (тело сверено ниже: без маркеров подготовки)",
}

// withDiffs — ключи with:, которым разрешено различаться у шага uses.
// Ключ — префикс uses и имя ключа.
var withDiffs = map[string]string{
	"actions/checkout@|fetch-depth": "релизу нужна полная история для merge-base тега с origin/main; тестам глубина не важна",
}

// envMarkers — признаки тела шага, меняющего окружение следующих шагов.
var envMarkers = []string{
	"apt-get", "apt ", "dpkg", "brew ", "choco ", "pacman", "winget", "pip install", "go install",
	"GITHUB_PATH", "GITHUB_ENV", "curl", "wget",
}

func isEnvStep(s fullStep) bool {
	if strings.HasPrefix(s.Uses, "actions/setup-") {
		return true
	}
	body := stripShellComments(s.Run)
	for _, m := range envMarkers {
		if strings.Contains(body, m) {
			return true
		}
	}
	return false
}

func normBody(run string) string {
	var out []string
	for _, l := range strings.Split(stripShellComments(run), "\n") {
		if l = strings.TrimSpace(l); l != "" {
			out = append(out, l)
		}
	}
	return strings.Join(out, "\n")
}

func mapStr(m map[string]string) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		fmt.Fprintf(&b, "%s=%s;", k, m[k])
	}
	return b.String()
}

func stepTitle(s fullStep) string {
	if s.Name != "" {
		return s.Name
	}
	return s.Uses
}

func stepKey(s fullStep, usedWith map[string]bool) string {
	with := map[string]string{}
	for k, v := range s.With {
		skip := false
		for wk := range withDiffs {
			pre, key, _ := strings.Cut(wk, "|")
			if strings.HasPrefix(s.Uses, pre) && k == key {
				usedWith[wk] = true
				skip = true
			}
		}
		if !skip {
			with[k] = v
		}
	}
	return fmt.Sprintf("имя=%q uses=%q if=%q shell=%q env=%q with=%q\n%s",
		s.Name, s.Uses, normalizeGate(s.If), s.Shell, mapStr(s.Env), mapStr(with), normBody(s.Run))
}

func isGoTestStep(s fullStep) bool {
	for _, l := range strings.Split(stripShellComments(s.Run), "\n") {
		if strings.HasPrefix(strings.TrimSpace(l), "go test") {
			return true
		}
	}
	return false
}

// prefixSteps — шаги до go test включительно (без шагов из onlyInOne) и
// шаги после него.
func prefixSteps(t *testing.T, path string, j fullJob, usedOnly, usedWith map[string]bool) (before []string, after []fullStep) {
	t.Helper()
	gt := -1
	for i, s := range j.Steps {
		if isGoTestStep(s) {
			if gt >= 0 {
				fail(t, "в %s два шага go test — граница «до go test» неоднозначна", path)
			}
			gt = i
		}
	}
	if gt < 0 {
		fatal(t, "в %s не найден шаг go test (по команде в теле) — сторож ничего не сверяет", path)
	}
	for _, s := range j.Steps[:gt+1] {
		k := path + "|" + s.Name
		if _, ok := onlyInOne[k]; ok {
			usedOnly[k] = true
			if isEnvStep(s) {
				fail(t, "%s: шаг «%s» из onlyInOne меняет окружение — исключение выдано только шагу, который окружение не трогает", path, s.Name)
			}
			continue
		}
		before = append(before, stepKey(s, usedWith))
	}
	return before, j.Steps[gt+1:]
}

func TestTestJobEnvironmentMatches(t *testing.T) {
	ciWF, relWF := loadWorkflow(t, ciYML), loadWorkflow(t, releaseYML)
	ciJ, relJ := jobOf(t, ciWF, ciYML, "checks"), jobOf(t, relWF, releaseYML, "test")

	if a, b := mapStr(ciWF.Env), mapStr(relWF.Env); a != b {
		fail(t, "окружение тестов разошлось: env: уровня workflow — ci.yml %q, release.yml %q", a, b)
	}
	if a, b := ciWF.Defaults.Run.Shell, relWF.Defaults.Run.Shell; a != b {
		fail(t, "окружение тестов разошлось: defaults.run.shell — ci.yml %q, release.yml %q", a, b)
	}
	if a, b := mapStr(ciJ.Env), mapStr(relJ.Env); a != b {
		fail(t, "окружение тестов разошлось: env: job — ci.yml checks %q, release.yml test %q", a, b)
	}
	if a, b := ciJ.Defaults.Run.Shell, relJ.Defaults.Run.Shell; a != b {
		fail(t, "окружение тестов разошлось: defaults.run.shell job — ci.yml checks %q, release.yml test %q", a, b)
	}

	usedOnly, usedWith := map[string]bool{}, map[string]bool{}
	inCI, afterCI := prefixSteps(t, ciYML, ciJ, usedOnly, usedWith)
	inRel, afterRel := prefixSteps(t, releaseYML, relJ, usedOnly, usedWith)

	for name, after := range map[string][]fullStep{"ci.yml checks": afterCI, "release.yml test": afterRel} {
		for _, s := range after {
			if isEnvStep(s) {
				fail(t, "%s: шаг подготовки окружения «%s» стоит ПОСЛЕ go test — тестам он не служит "+
					"(повтор v0.3.0-rc.1: тесты идут без него)", name, stepTitle(s))
			}
		}
	}
	// Оба файла могут потерять шаг одновременно — равенство этого не заметит.
	for name, steps := range map[string][]string{"ci.yml checks": inCI, "release.yml test": inRel} {
		found := false
		for _, s := range steps {
			if strings.Contains(s, "sudo apt-get install -y busybox") && strings.Contains(s, `if="matrix.os == 'linux'"`) {
				found = true
			}
		}
		if !found {
			fail(t, "в %s до go test нет шага установки busybox под if: matrix.os == 'linux' — TestCASScriptRealShells "+
				"пойдёт в busybox-static образа, где подмена утилит не действует (инцидент v0.3.0-rc.1)", name)
		}
	}
	for k := range onlyInOne {
		if !usedOnly[k] {
			fail(t, "запись onlyInOne «%s» не использована (шага нет до go test) — убери её", k)
		}
	}
	for k := range withDiffs {
		if !usedWith[k] {
			fail(t, "запись withDiffs «%s» не использована — убери её", k)
		}
	}
	n := len(inCI)
	if len(inRel) > n {
		n = len(inRel)
	}
	for i := 0; i < n; i++ {
		var a, b string
		if i < len(inCI) {
			a = inCI[i]
		}
		if i < len(inRel) {
			b = inRel[i]
		}
		if a != b {
			fail(t, "шаги job до go test разошлись (№%d по порядку, без onlyInOne) — на теге тесты идут не в том "+
				"окружении, что на PR:\n  ci.yml, job checks:\n%s\n  release.yml, job test:\n%s", i+1, indent(a), indent(b))
			return
		}
	}
}

func indent(s string) string {
	if s == "" {
		return "    (шага нет)"
	}
	return "    " + strings.ReplaceAll(s, "\n", "\n    ")
}
