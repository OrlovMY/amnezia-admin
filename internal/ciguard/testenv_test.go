// Файл testenv_test.go — окружение job test (release.yml) обязано совпадать
// с окружением job checks (ci.yml).
//
// Инцидент v0.3.0-rc.1 (03.10.2026). Шаг «Оболочки для скрипта записи»
// (busybox) появился только в ci.yml. На PR тест TestCASScriptRealShells шёл
// в пакете busybox и был зелёным; на теге тот же тест шёл в busybox-static
// из образа ubuntu-24.04, который вызывает свои апплеты в обход PATH, —
// подмена «утилиты нет» не действовала, и релиз упал. Списки go test
// сверялись (TestGoTestPackagesMatch), а то, ЧЕМ подготовлено окружение
// этих тестов, — нет.
//
// Правило: шаг подготовки окружения — любой шаг с uses: actions/setup-*,
// любой шаг, чьё тело ставит пакеты или пишет в $GITHUB_PATH/$GITHUB_ENV, —
// обязан стоять в обоих job, в том же порядке, с тем же условием if:, тем же
// телом (без комментариев и отступов), теми же env:/with:/shell:. Окружение
// уровня workflow и job (env:, defaults:) — тоже. Признак «подготовка» —
// по содержимому шага, а не по имени из списка: новый шаг установки,
// добавленный в один файл, краснеет сам, без правки сторожа.
package ciguard

import (
	"fmt"
	"sort"
	"strings"
	"testing"
)

// envMarkers — признаки тела шага, меняющего окружение следующих шагов.
var envMarkers = []string{
	"apt-get", "apt ", "dpkg", "brew ", "choco ", "pacman", "winget", "pip install", "go install",
	"GITHUB_PATH", "GITHUB_ENV",
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

func envStepKey(s fullStep) string {
	return fmt.Sprintf("имя=%q uses=%q if=%q shell=%q env=%q with=%q\n%s",
		s.Name, s.Uses, normalizeGate(s.If), s.Shell, mapStr(s.Env), mapStr(s.With), normBody(s.Run))
}

func envStepsOfJob(j fullJob) []string {
	var out []string
	for _, s := range j.Steps {
		if isEnvStep(s) {
			out = append(out, envStepKey(s))
		}
	}
	return out
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

	inCI, inRel := envStepsOfJob(ciJ), envStepsOfJob(relJ)
	// Оба списка могут потерять шаг одновременно — равенство этого не
	// заметит. Шаг busybox нужен TestCASScriptRealShells: без него тест идёт
	// в busybox-static образа, где подмена утилит не действует.
	for name, steps := range map[string][]string{"ci.yml checks": inCI, "release.yml test": inRel} {
		if len(steps) == 0 {
			fatal(t, "в %s не найдено ни одного шага подготовки окружения — сторож ничего не сверяет", name)
		}
		found := false
		for _, s := range steps {
			if strings.Contains(s, "sudo apt-get install -y busybox") && strings.Contains(s, `if="matrix.os == 'linux'"`) {
				found = true
			}
		}
		if !found {
			fail(t, "в %s нет шага установки busybox под if: matrix.os == 'linux' — TestCASScriptRealShells "+
				"пойдёт в busybox-static образа, где подмена утилит не действует (инцидент v0.3.0-rc.1)", name)
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
			fail(t, "шаги подготовки окружения тестов разошлись (№%d по порядку) — на теге тесты идут не в том "+
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
