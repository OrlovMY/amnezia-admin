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
// ГРАНИЦА. Что внутри закреплённого SHA — не проверяется; SHA берётся с
// тега релиза action при обновлении (Dependabot/руками). `uses:` на уровне
// job (переиспользуемый workflow) закрыт списком ключей job
// (TestWorkflowKeysClosedList), но и здесь проверяется, если появится.
package ciguard

import (
	"reflect"
	"regexp"
	"sort"
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

// pinnedUsesRe — `<владелец>/<репо>[/путь]@<40 hex>`.
var pinnedUsesRe = regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(/[A-Za-z0-9_./-]+)?@[0-9a-f]{40}$`)

func TestActionsPinnedBySHA(t *testing.T) {
	checked := 0
	for _, path := range []string{releaseYML, ciYML} {
		jobs, _ := rawWorkflow(t, path)["jobs"].(map[string]interface{})
		for _, jn := range sortedKeys(jobs) {
			job, _ := jobs[jn].(map[string]interface{})
			if u, ok := job["uses"]; ok {
				checked++
				if s, _ := u.(string); !pinnedUsesRe.MatchString(s) {
					fail(t, "%s: job %s: uses «%v» не закреплён по SHA", path, jn, u)
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
				s, _ := u.(string)
				if !pinnedUsesRe.MatchString(s) {
					fail(t, "%s: job %s, шаг №%d: uses «%v» не закреплён по SHA — допустимо только "+
						"<владелец>/<репо>[/путь]@<40 hex>; метка и ветка изменяемы, ./ и docker:// вне списка",
						path, jn, i+1, u)
				}
			}
		}
	}
	// Точное число: исчезновение шагов uses: (или разбор, переставший их
	// видеть) — тоже сигнал.
	if checked != wantUses {
		fail(t, "ссылок uses: найдено %d, ожидалось %d — законно изменилось — поправь wantUses", checked, wantUses)
	}
}

// wantUses — сколько `uses:` сейчас в обоих workflow (ci.yml 4, release.yml 9).
const wantUses = 13
