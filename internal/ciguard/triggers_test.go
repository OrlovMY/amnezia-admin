// Файл triggers_test.go — закрытые списки триггеров `on:` и ссылок `uses:`
// (долги CI до релиза, 30.09.2026; ревью SEC-01/QA-01 раунда 7).
//
// Триггеры. release.yml исполняется с правом записи и аттестации; его
// единственный законный вход — push тега v*. workflow_dispatch собрал бы
// релиз не из тега (происхождение тега на это не рассчитано),
// workflow_call отдал бы цепочку чужому workflow, pull_request_target —
// секреты и токен чужому коду. ci.yml — pull_request и push в main. Сверка —
// ЦЕЛИКОМ с эталоном: не только имена событий, но и их настройки (branches,
// tags, paths …). Незнакомое событие или настройка — красное.
//
// uses:. Метка (@v7) и ветка — изменяемые ссылки: владелец action, или тот,
// кто захватил его учётную запись, подменяет код под нашей подписью
// аттестации. Поэтому каждый `uses:` — ровно `<владелец>/<репо>[/путь]@<40
// hex>`. Локальный `./…` и `docker://…` — тоже красные: первый исполняет код
// из проверяемой ветки как action (в обход закрытых списков тела run:),
// второй — образ по изменяемой метке. Комментарий версии (`# v7.0.1`) YAML
// отрезает сам — он допустим.
//
// ГРАНИЦА. Что внутри закреплённого SHA — не проверяется: SHA сверяется с
// таблицей allowedActions, а таблица правится человеком вместе с workflow
// (связная правка, см. комментарий к ней). `uses:` на уровне
// job (переиспользуемый workflow) закрыт списком ключей job
// (TestWorkflowKeysClosedList), но и здесь проверяется, если появится.
package ciguard

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// wantTriggers — эталон `on:` каждого workflow, в форме, которую отдаёт
// yaml.v3 при разборе в interface{}.
var wantTriggers = map[string]map[string]interface{}{
	releaseYML: {
		"push": map[string]interface{}{"tags": []interface{}{"v*"}},
	},
	ciYML: {
		"pull_request": nil,
		"push":         map[string]interface{}{"branches": []interface{}{"main"}},
	},
}

func rawWorkflow(t *testing.T, path string) map[string]interface{} {
	t.Helper()
	var raw map[string]interface{}
	if err := yaml.Unmarshal(readSource(t, path), &raw); err != nil {
		fatal(t, "не разобрать %s как YAML: %v", path, err)
	}
	return raw
}

func TestWorkflowTriggersClosedList(t *testing.T) {
	checked := 0
	for _, path := range []string{releaseYML, ciYML} {
		want := wantTriggers[path]
		on, ok := rawWorkflow(t, path)["on"].(map[string]interface{})
		if !ok {
			fail(t, "%s: `on:` не в форме словаря событий — вне закрытого списка", path)
			continue
		}
		var names []string
		for ev := range on {
			names = append(names, ev)
		}
		for ev := range want {
			if _, ok := on[ev]; !ok {
				names = append(names, ev)
			}
		}
		sort.Strings(names)
		for _, ev := range names {
			checked++
			got, has := on[ev]
			exp, known := want[ev]
			switch {
			case !known:
				fail(t, "%s: событие «%s» вне закрытого списка триггеров. Законно? Внеси в wantTriggers с обоснованием", path, ev)
			case !has:
				fail(t, "%s: нет события «%s» — эталон триггеров разошёлся с файлом", path, ev)
			case !reflect.DeepEqual(got, exp):
				fail(t, "%s: событие «%s»: настройка %v вне закрытого списка (ждали %v)", path, ev, got, exp)
			}
		}
	}
	if checked == 0 {
		fatal(t, "не сверено ни одного события — тест перестал что-либо проверять")
	}
}

// pinnedUsesRe — `<владелец>/<репо>[/путь]@<40 hex>`; владелец и репо
// начинаются с буквы или цифры (ревью SEC-01, С-1: иначе `./x@<sha>` —
// локальный action из проверяемой ветки — проходил как «закреплённый»).
var pinnedUsesRe = regexp.MustCompile(`^([A-Za-z0-9][A-Za-z0-9_.-]*/[A-Za-z0-9][A-Za-z0-9_.-]*((?:/[A-Za-z0-9_.-]+)*))@[0-9a-f]{40}$`)

// allowedActions — ЗАКРЫТЫЙ список источников и их SHA (QA-01 рек. 3,
// AU-LOGIC F4). Пара owner/repo защищает от смены владельца
// (`evil-org/setup-go@…`), SHA — от коммита из форка под разрешённым
// именем (impostor commit: GitHub разрешает `owner/repo@<sha>` и для
// коммита из форка) и от подмены тега. Любой другой SHA — красный.
//
// СВЯЗНАЯ ПРАВКА (CLAUDE.md, «Выпуск»): PR Dependabot, обновляющий action,
// обязан в том же PR поменять строку здесь — иначе CI красный. Это
// намеренно: новый SHA проходит ревью человеком, а не только бота.
var allowedActions = map[string]struct{ sha, why string }{
	"actions/checkout":                {"3d3c42e5aac5ba805825da76410c181273ba90b1", "выгрузка репозитория (оба workflow), v7.0.1"},
	"actions/setup-go":                {"b7ad1dad31e06c5925ef5d2fc7ad053ef454303e", "Go по go.mod (оба workflow), v7.0.0"},
	"actions/upload-artifact":         {"043fb46d1a93c77aae656e7c1c64a875d1fc6a0a", "передача сборок build → release, v7.0.1"},
	"actions/download-artifact":       {"3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c", "приём сборок в job release, v8.0.1"},
	"actions/attest-build-provenance": {"4d101475d8b20a2381f78447822ac1eab6504dd8", "аттестация происхождения релиза, v4.2.2"},
	"softprops/action-gh-release":     {"efb35369e0ad2afab669f228072c1b0d510eae64", "публикация релиза на GitHub, v3.0.3"},
}

// usesProblem — пусто, если ссылка закреплена по SHA и источник из списка.
func usesProblem(v interface{}) string {
	s, _ := v.(string)
	m := pinnedUsesRe.FindStringSubmatch(s)
	if m == nil {
		return fmt.Sprintf("uses «%v» не закреплён по SHA — допустимо только <владелец>/<репо>[/путь]@<40 hex>; "+
			"метка и ветка изменяемы, ./, ../ и docker:// вне списка", v)
	}
	for _, seg := range strings.Split(m[1], "/") {
		if seg == "." || seg == ".." {
			return fmt.Sprintf("uses «%v»: сегмент «%s» в пути — выход из репозитория action запрещён", v, seg)
		}
	}
	a, ok := allowedActions[m[1]]
	if !ok {
		return fmt.Sprintf("uses «%v»: источник «%s» вне закрытого списка allowedActions", v, m[1])
	}
	if sha := s[strings.LastIndexByte(s, '@')+1:]; sha != a.sha {
		return fmt.Sprintf("uses «%v»: SHA %s не совпадает с закреплённым %s для %s — обновите таблицу "+
			"allowedActions в internal/ciguard вместе с workflow", v, sha, a.sha, m[1])
	}
	return ""
}

func TestActionsPinnedBySHA(t *testing.T) {
	checked := 0
	for _, path := range []string{releaseYML, ciYML} {
		jobs, _ := rawWorkflow(t, path)["jobs"].(map[string]interface{})
		for _, jn := range sortedKeys(jobs) {
			job, _ := jobs[jn].(map[string]interface{})
			if u, ok := job["uses"]; ok {
				checked++
				if pr := usesProblem(u); pr != "" {
					fail(t, "%s: job %s: %s", path, jn, pr)
				}
			}
			steps, _ := job["steps"].([]interface{})
			for i, st := range steps {
				step, _ := st.(map[string]interface{})
				u, ok := step["uses"]
				if !ok {
					continue
				}
				checked++
				if pr := usesProblem(u); pr != "" {
					fail(t, "%s: job %s, шаг №%d: %s", path, jn, i+1, pr)
				}
			}
		}
	}
	// Точное число: исчезновение шагов uses: (или разбор, переставший их
	// видеть) — тоже сигнал.
	if checked == 0 {
		fatal(t, "не найдено ни одной ссылки uses: — разбор пуст, тест ничего не проверил")
	}
	if checked != wantUses {
		fail(t, "ссылок uses: найдено %d, ожидалось %d — законно изменилось — поправь wantUses", checked, wantUses)
	}
}

// wantUses — сколько `uses:` сейчас в обоих workflow (ci.yml 4, release.yml 9).
const wantUses = 13

// Состав .github (ревью SEC-01, С-2). Закрытые списки выше читают только
// ci.yml и release.yml; третий файл workflow с pull_request_target и
// uses: foo/bar@main не проверял бы никто. Поэтому состав закрыт: в
// .github/workflows ровно эти два файла, в .github — только перечисленное;
// каталога .github/actions нет (локальные action закрыты и в uses:).
var wantWorkflowFiles = []string{"ci.yml", "release.yml"}

var allowedGithubEntries = map[string]string{
	"workflows":      "ci.yml и release.yml",
	"dependabot.yml": "обновления go-модулей и SHA actions",
}

const githubDir = "../../.github"

func TestWorkflowFilesClosedList(t *testing.T) {
	list := func(dir string) []string {
		ents, err := os.ReadDir(dir)
		if err != nil {
			fatal(t, "не прочитать каталог %s: %v", dir, err)
		}
		var names []string
		for _, e := range ents {
			names = append(names, e.Name())
		}
		// Подсадки канарейки — лишний или пропавший файл в результате обхода.
		for _, f := range plantedExtraFiles(t) {
			if filepath.ToSlash(filepath.Dir(f)) == filepath.ToSlash(dir) {
				names = append(names, filepath.Base(f))
			}
		}
		hidden := map[string]bool{}
		for _, f := range plantedHiddenFiles(t) {
			if filepath.ToSlash(filepath.Dir(f)) == filepath.ToSlash(dir) {
				hidden[filepath.Base(f)] = true
			}
		}
		var kept []string
		for _, n := range names {
			if !hidden[n] {
				kept = append(kept, n)
			}
		}
		sort.Strings(kept)
		return kept
	}
	// Сравнение множествами в обе стороны, без счёта и без сравнения строк:
	// ослабить его подменой оператора нельзя (AU-LOGIC F3).
	wf := list(githubDir + "/workflows")
	got := map[string]bool{}
	for _, n := range wf {
		got[n] = true
		if !contains(wantWorkflowFiles, n) {
			fail(t, "в .github/workflows лишний файл %s, допустимо ровно %v — файл вне списка не проверяет ни один сторож "+
				"(триггеры, uses:, ключи, тела run:)", n, wantWorkflowFiles)
		}
	}
	for _, n := range wantWorkflowFiles {
		if !got[n] {
			fail(t, "в .github/workflows нет %s — сторожа читали бы несуществующий файл", n)
		}
	}
	top := list(githubDir)
	for _, n := range top {
		if _, ok := allowedGithubEntries[n]; !ok {
			fail(t, ".github/%s вне закрытого списка содержимого .github (локальные action, чужие workflow)", n)
		}
	}
	if len(top) == 0 {
		fatal(t, "каталог .github пуст — тест перестал что-либо проверять")
	}
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}
