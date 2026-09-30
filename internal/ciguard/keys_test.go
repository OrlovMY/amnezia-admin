// Файл keys_test.go — закрытые списки КЛЮЧЕЙ workflow, job и шага (ревью
// QA-01, раунд 7).
//
// Зачем. Каждый сторож этого пакета читает структуру workflow через свою
// схему, а yaml.v3 молча пропускает ключи, которых в схеме нет. Так в
// раунде 7 нашлись `container:` (весь job в чужом образе, со своим env —
// в обход закрытого списка имён) и `services:`. Это тот же класс, что GO*,
// PATH и BASH_ENV: ключ, о котором сторож не знает. Лечится не запретом
// двух ключей, а тем, что незнакомый ключ на любом из трёх уровней —
// красный.
//
// В каждый список внесено ровно то, что сейчас стоит в ci.yml и release.yml,
// с обоснованием. Ключ, который читают другие сторожа, но которого в файлах
// сейчас нет (continue-on-error, shell у шага, defaults у job, if у job),
// в список НЕ внесён: появится законно — появится видимой строкой здесь.
//
// Сюда же — значение `runs-on`: у job с матрицей ровно `${{ matrix.runner }}`
// (сами метки сверяют matrix_test.go и runnerarch_test.go), у job без
// матрицы — метка из таблицы runnerArch. До раунда 7 runs-on не сверял никто:
// сторожа матриц читали strategy.matrix.include и не смотрели, берёт ли job
// метку оттуда.
//
// ГРАНИЦА. Ключи ниже уровня шага (with: конкретного action, подключи
// strategy, concurrency, defaults.run кроме shell) сторожем не
// перечисляются. Содержимое `on:` сверяет целиком
// TestWorkflowTriggersClosedList, значение `uses:` — TestActionsPinnedBySHA
// (triggers_test.go). defaults.run.shell сверяет shellProblem, with: у
// attest-build-provenance — TestReleaseAttestsChecksums, у checkout —
// TestCheckoutsDoNotPersistCredentials.
package ciguard

import (
	"fmt"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

var allowedWorkflowKeys = map[string]string{
	"name":        "имя workflow в интерфейсе GitHub",
	"on":          "триггеры: pull_request/push у ci.yml, push тегов у release.yml",
	"permissions": "права токена по умолчанию — только чтение",
	"defaults":    "defaults.run.shell: bash — значение сверяет shellProblem",
	"concurrency": "очередь прогонов одного ref",
	"jobs":        "сами job",
}

var allowedJobKeys = map[string]string{
	"name":            "имя job в интерфейсе",
	"runs-on":         "метка раннера — значение сверяется ниже",
	"strategy":        "матрица ОС — сверяют matrix_test.go и runnerarch_test.go",
	"steps":           "шаги",
	"timeout-minutes": "предел времени job в ci.yml (ревью З7)",
	"needs":           "порядок test → build → release в release.yml",
	"permissions":     "contents: write и права аттестации у job release",
	"env":             "ATTEST_SUBJECTS у job release — имя из allowedEnvNames",
}

var allowedStepKeys = map[string]string{
	"name": "имя шага",
	"uses": "закреплённый по SHA action",
	"with": "входы action",
	"run":  "тело шага — сверяют закрытые списки тела и окружения",
	"if":   "условие по matrix.os — допустимые условия перечисляет allowedActionlintGates и stepLive",
	"env":  "имена из allowedEnvNames",
}

func sortedKeys(m map[string]interface{}) []string {
	var ks []string
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

// TestWorkflowKeysClosedList — незнакомый ключ на уровне workflow, job или
// шага — красный; runs-on — из закрытого набора.
func TestWorkflowKeysClosedList(t *testing.T) {
	checked := 0
	for _, path := range []string{releaseYML, ciYML} {
		var raw map[string]interface{}
		if err := yaml.Unmarshal(readSource(t, path), &raw); err != nil {
			fatal(t, "не разобрать %s как YAML: %v", path, err)
		}
		var hits []string
		for _, k := range sortedKeys(raw) {
			checked++
			if _, ok := allowedWorkflowKeys[k]; !ok {
				hits = append(hits, "workflow: ключ «"+k+"» вне закрытого списка")
			}
		}
		jobs, _ := raw["jobs"].(map[string]interface{})
		if len(jobs) == 0 {
			fatal(t, "в %s не найдено ни одного job — тест перестал что-либо проверять", path)
		}
		for _, jn := range sortedKeys(jobs) {
			job, _ := jobs[jn].(map[string]interface{})
			for _, k := range sortedKeys(job) {
				checked++
				if _, ok := allowedJobKeys[k]; !ok {
					hits = append(hits, "job "+jn+": ключ «"+k+"» вне закрытого списка")
				}
			}
			// runs-on: у job с матрицей — из матрицы, у прочих — метка из
			// таблицы runnerArch.
			ro := fmt.Sprint(job["runs-on"])
			_, hasStrategy := job["strategy"]
			switch {
			case hasStrategy && strings.Join(strings.Fields(ro), "") != "${{matrix.runner}}":
				hits = append(hits, "job "+jn+": runs-on «"+ro+"» при матрице — допустимо только ${{ matrix.runner }}")
			case !hasStrategy && runnerArch[ro] == "":
				hits = append(hits, "job "+jn+": runs-on «"+ro+"» — метки нет в таблице runnerArch")
			}
			steps, _ := job["steps"].([]interface{})
			for i, st := range steps {
				step, _ := st.(map[string]interface{})
				for _, k := range sortedKeys(step) {
					checked++
					if _, ok := allowedStepKeys[k]; !ok {
						hits = append(hits, fmt.Sprintf("job %s, шаг №%d: ключ «%s» вне закрытого списка", jn, i+1, k))
					}
				}
			}
		}
		for _, h := range hits {
			fail(t, "в %s %s. Незнакомое сторожа не видят: yaml молча пропускает ключи вне схемы "+
				"(container:, services: …). Законно? Внеси строкой с обоснованием", path, h)
		}
	}
	if checked == 0 {
		fatal(t, "не найдено ни одного ключа — тест перестал что-либо проверять")
	}
}
