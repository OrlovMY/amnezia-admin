// Файл plant_test.go — канарейки сторожей этого пакета, идущие ТЕМ ЖЕ
// ПУТЁМ, что и сами сторожа (седьмая ступень; образец —
// TestOsmotrCanaryFormsGateWired в cmd/gui/osmotr_test.go).
//
// Зачем процесс. Сторожа этого пакета можно обезвредить, не тронув логику
// детекции: t.Logf вместо t.Errorf, счёт через `>` вместо `>=`. Канарейка,
// которая зовёт функцию детекции со своим сборщиком ошибок, этого не
// увидит. Поэтому здесь гоняются НАСТОЯЩИЕ тесты пакета — тем же тестовым
// бинарником, в дочернем процессе, — а дефект подсаживается в ТЕКСТ
// workflow-файла в единственной точке чтения (readSource). Провал обязан
// дойти до того самого *testing.T, который видит go test.
//
// Разведение. Каждая подсадка обязана уронить РОВНО ОДИН тест — свой — и с
// ожидаемым сообщением; остальные тесты того же прогона обязаны пройти. Так
// видно и «краснеет на своей причине», и «молчит на соседних». Ожидаемые
// тест и сообщение записаны литералами в таблице, а не выведены из
// подменяемого места.
package ciguard

import (
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"testing"
)

const plantEnv = "CIGUARD_PLANT"

// plant — один подсаживаемый дефект: в файле path ровно одно вхождение old
// заменяется на new.
type plant struct {
	name     string
	path     string
	old, new string
	wantTest string // единственный тест, который обязан упасть
	wantMsg  string // что обязано быть в его выводе
}

// ciRealLint — настоящий вызов actionlint в ci.yml, дословно. Три формы
// обеззубливания ниже сохраняют в том же теле run: оба пути workflow (в
// echo), поэтому старый сторож шагов (actionlintversion_test.go) их не
// видит — и обязан не видеть: это предмет invocation_test.go.
const ciRealLint = `          go run "github.com/rhysd/actionlint/cmd/actionlint@${ACTIONLINT_VERSION}" \
            -shellcheck "$SHELLCHECK_BIN" \
            .github/workflows/release.yml \
            .github/workflows/ci.yml
`

const ciLintEcho = `          echo "разбираю .github/workflows/release.yml .github/workflows/ci.yml"
`

var plants = []plant{
	{
		name: "actionlint-version", path: ciYML, old: ciRealLint,
		new:      ciLintEcho + `          go run "github.com/rhysd/actionlint/cmd/actionlint@${ACTIONLINT_VERSION}" --version` + "\n",
		wantTest: "TestActionlintInvocationMeaning", wantMsg: "флаг --version",
	},
	{
		name: "actionlint-noargs", path: ciYML, old: ciRealLint,
		new:      ciLintEcho + `          go run "github.com/rhysd/actionlint/cmd/actionlint@${ACTIONLINT_VERSION}" -shellcheck "$SHELLCHECK_BIN"` + "\n",
		wantTest: "TestActionlintInvocationMeaning", wantMsg: "без файлов",
	},
	{
		name: "actionlint-ignore", path: ciYML, old: `            -shellcheck "$SHELLCHECK_BIN" \
            .github/workflows/release.yml`,
		new: `            -shellcheck "$SHELLCHECK_BIN" -ignore '.*' \
            .github/workflows/release.yml`,
		wantTest: "TestActionlintInvocationMeaning", wantMsg: "флаг -ignore",
	},
	{
		name: "actionlint-shellcheck-off", path: ciYML, old: `            -shellcheck "$SHELLCHECK_BIN" \
            .github/workflows/release.yml`,
		new: `            -shellcheck= \
            .github/workflows/release.yml`,
		wantTest: "TestActionlintInvocationMeaning", wantMsg: "-shellcheck с пустым значением",
	},
	{
		name: "actionlint-step-coe", path: ciYML,
		old: `      - name: actionlint (оба workflow)
`,
		new: `      - name: actionlint (оба workflow)
        continue-on-error: true
`,
		wantTest: "TestActionlintPinnedInEveryExpectedFile", wantMsg: "найден, но обеззублен",
	},
	{
		name: "actionlint-literal-pin", path: releaseYML,
		old:      "  test:\n",
		new:      "  # go run github.com/rhysd/actionlint/cmd/actionlint@v1.7.11 .github/workflows/release.yml\n  test:\n",
		wantTest: "TestActionlintVersionSingleSource", wantMsg: "литеральная версия actionlint v1.7.11",
	},
	{
		name: "checks-matrix", path: ciYML,
		old:      "          - os: macos\n            runner: macos-26\n",
		new:      "          - os: macos\n            runner: macos-15\n",
		wantTest: "TestCIMatrixMatchesReleaseBuild", wantMsg: "матрицы ОС разошлись",
	},
	{
		name: "test-matrix", path: releaseYML,
		old:      "          - os: macos\n            runner: macos-26\n    steps:\n",
		new:      "    steps:\n",
		wantTest: "TestReleaseTestMatrixMatchesBuild", wantMsg: "матрица job test разошлась с job build",
	},
	{
		name: "arch-table", path: releaseYML,
		old:      "            runner: macos-26\n            arch: arm64\n",
		new:      "            runner: macos-26\n            arch: amd64\n",
		wantTest: "TestReleaseMatrixArchMatchesRunnerTable", wantMsg: "таблица runnerArch говорит arm64",
	},
	{
		name: "arch-step-defanged", path: releaseYML,
		old:      `test "$actual" = "$DECLARED_ARCH" ||`,
		new:      `test -n "$actual" ||`,
		wantTest: "TestReleaseRunnerArchStep", wantMsg: "RUNNER_ARCH=X64, matrix.arch=arm64: шаг прошёл",
	},
	{
		name: "packages", path: releaseYML,
		old: "./cmd/cli/ ./cmd/gui/\n", new: "./cmd/cli/\n",
		wantTest: "TestGoTestPackagesMatch", wantMsg: "списки go test разошлись",
	},
	{
		name: "attest-subjects", path: releaseYML,
		old:      "        dist/amnezia-admin-*\n        dist/SHA256SUMS\n",
		new:      "        dist/amnezia-admin-*\n",
		wantTest: "TestReleaseAttestsChecksums", wantMsg: "СТОП: субъектов аттестации 8, ожидалось 9",
	},
	{
		name: "persist-credentials", path: releaseYML,
		old: "          persist-credentials: false\n", new: "",
		wantTest: "TestWriteJobsDoNotPersistCredentials", wantMsg: "persist-credentials",
	},
}

// mainTests — все сторожа пакета. Чистый прогон обязан показать PASS
// каждого: иначе фильтр мог ничего не найти, и «провал» значил бы не то.
var mainTests = []string{
	"TestActionlintInvocationMeaning",
	"TestActionlintPinnedInEveryExpectedFile",
	"TestActionlintVersionSingleSource",
	"TestCIMatrixMatchesReleaseBuild",
	"TestGoTestPackagesMatch",
	"TestReleaseAttestsChecksums",
	"TestReleaseMatrixArchMatchesRunnerTable",
	"TestReleaseRunnerArchStep",
	"TestReleaseTestMatrixMatchesBuild",
	"TestWriteJobsDoNotPersistCredentials",
}

// readSource — ЕДИНСТВЕННАЯ точка чтения файлов сторожами пакета. В
// дочернем процессе канарейки сюда подсаживается дефект; подсадка, которая
// не легла (нет ровно одного вхождения), роняет процесс — иначе канарейка
// проверяла бы нетронутый файл.
func readSource(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("не прочитать %s: %v", path, err)
	}
	name := os.Getenv(plantEnv)
	if name == "" || name == "нет" {
		return data
	}
	for _, p := range plants {
		if p.name != name {
			continue
		}
		if p.path != path {
			return data
		}
		text := strings.ReplaceAll(string(data), "\r\n", "\n")
		if n := strings.Count(text, p.old); n != 1 {
			t.Fatalf("ПОДСАДКА %s НЕ ЛЕГЛА: в %s %d вхождений подменяемого текста вместо одного", name, path, n)
		}
		return []byte(strings.Replace(text, p.old, p.new, 1))
	}
	t.Fatalf("неизвестная подсадка %s=%q", plantEnv, name)
	return nil
}

var failLineRe = regexp.MustCompile(`(?m)^\s*--- FAIL: (Test[A-Za-z0-9_]+)`)
var passLineRe = regexp.MustCompile(`(?m)^\s*--- PASS: (Test[A-Za-z0-9_]+)`)

func runChild(plantName string) (string, error) {
	cmd := exec.Command(os.Args[0], "-test.run", "^Test", "-test.skip", "^TestCanary", "-test.count=1", "-test.v")
	cmd.Env = append(os.Environ(), plantEnv+"="+plantName)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func uniqSorted(ms [][]string) []string {
	set := map[string]bool{}
	for _, m := range ms {
		set[m[1]] = true
	}
	var out []string
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func TestCanaryPlantsReachMainTests(t *testing.T) {
	if os.Getenv(plantEnv) != "" {
		t.Skip("дочерний процесс канарейки")
	}

	clean, err := runChild("нет")
	passed := uniqSorted(passLineRe.FindAllStringSubmatch(clean, -1))
	if err != nil || strings.Join(passed, " ") != strings.Join(mainTests, " ") {
		t.Fatalf("без подсадки не все сторожа прошли или не все нашлись (err=%v)\n  прошли: %v\n  ждали:  %v\n%s",
			err, passed, mainTests, clean)
	}

	for _, p := range plants {
		t.Run(p.name, func(t *testing.T) {
			out, err := runChild(p.name)
			failed := uniqSorted(failLineRe.FindAllStringSubmatch(out, -1))
			if err == nil || len(failed) != 1 || failed[0] != p.wantTest || !strings.Contains(out, p.wantMsg) {
				t.Errorf("подсадка %s: ждали провала ровно %s с «%s» (err=%v), упали: %v\n%s",
					p.name, p.wantTest, p.wantMsg, err, failed, out)
				return
			}
			for _, l := range strings.Split(out, "\n") {
				if strings.Contains(l, p.wantMsg) {
					t.Log("ДОЧЕРНИЙ: " + strings.TrimSpace(l))
					break
				}
			}
		})
	}
}
