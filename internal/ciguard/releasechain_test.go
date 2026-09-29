// Файл releasechain_test.go — сторожа цепочки выпуска, заведённые в A6.
//
//   - TestReleaseTestMatrixMatchesBuild — матрица job test в release.yml
//     (следствие A5 № 3: до A6 она не сверялась ни с чем);
//   - TestReleaseRunnerArchStep — шаг, сверяющий RUNNER_ARCH с matrix.arch
//     (следствие A5 № 1), существует, исполняется и ПАДАЕТ на расхождении —
//     его тело гоняется настоящим bash;
//   - TestGoTestPackagesMatch — списки пакетов `go test` в ci.yml и
//     release.yml совпадают и покрывают каждый каталог с тестами;
//   - TestReleaseAttestsChecksums — SHA256SUMS входит в субъекты
//     аттестации; шаг проверки субъектов гоняется настоящим bash над
//     каталогом-образцом;
//   - TestCheckoutsDoNotPersistCredentials — ни один checkout в обоих файлах
//     не оставляет токен в рабочем каталоге.
//
// ГРАНИЦА. Всё здесь — про ТЕКСТ workflow и про поведение его шагов на
// подставленных данных. Что GitHub на теге исполнит их так же (что
// attest-build-provenance примет список из двух строк, что RUNNER_ARCH на
// раннере такой, как мы ждём), проверяется только прогоном на rc-теге.
package ciguard

import (
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

type fullStep struct {
	Name            string            `yaml:"name"`
	Uses            string            `yaml:"uses"`
	Run             string            `yaml:"run"`
	If              interface{}       `yaml:"if"`
	ContinueOnError interface{}       `yaml:"continue-on-error"`
	Env             map[string]string `yaml:"env"`
	With            map[string]string `yaml:"with"`
}

type fullJob struct {
	If              interface{}       `yaml:"if"`
	ContinueOnError interface{}       `yaml:"continue-on-error"`
	Permissions     interface{}       `yaml:"permissions"`
	Env             map[string]string `yaml:"env"`
	Strategy        struct {
		Matrix struct {
			Include []map[string]string `yaml:"include"`
		} `yaml:"matrix"`
	} `yaml:"strategy"`
	Steps []fullStep `yaml:"steps"`
}

type fullWorkflow struct {
	Permissions interface{}        `yaml:"permissions"`
	Jobs        map[string]fullJob `yaml:"jobs"`
}

func loadWorkflow(t *testing.T, path string) fullWorkflow {
	t.Helper()
	var wf fullWorkflow
	if err := yaml.Unmarshal(readSource(t, path), &wf); err != nil {
		t.Fatalf("не разобрать %s как YAML: %v", path, err)
	}
	if len(wf.Jobs) == 0 {
		t.Fatalf("в %s не найдено ни одного job — тест перестал что-либо проверять", path)
	}
	return wf
}

func jobOf(t *testing.T, wf fullWorkflow, path, name string) fullJob {
	t.Helper()
	j, ok := wf.Jobs[name]
	if !ok {
		t.Fatalf("в %s нет job %q — тест перестал что-либо проверять", path, name)
	}
	if len(j.Steps) == 0 {
		t.Fatalf("в %s у job %s нет шагов — тест перестал что-либо проверять", path, name)
	}
	return j
}

// stepLive — исполняется ли шаг безусловно и роняет ли job его падение.
func stepLive(j fullJob, s fullStep) (bool, string) {
	switch {
	case normalizeGate(j.If) != "":
		return false, "job стоит под условием if: " + normalizeGate(j.If)
	case isTrue(j.ContinueOnError):
		return false, "job помечен continue-on-error: true"
	case normalizeGate(s.If) != "":
		return false, "шаг стоит под условием if: " + normalizeGate(s.If)
	case isTrue(s.ContinueOnError):
		return false, "шаг помечен continue-on-error: true"
	}
	return true, ""
}

// --- следствие A5 № 3 --------------------------------------------------------

// TestReleaseTestMatrixMatchesBuild — job test в release.yml идёт на тех же
// парах «ОС/раннер», что job build. Вместе с TestCIMatrixMatchesReleaseBuild
// (build против checks в ci.yml) это замыкает три матрицы в одно множество:
// на теге тесты идут там же, где собирается релиз и где гонялся PR.
func TestReleaseTestMatrixMatchesBuild(t *testing.T) {
	inTest := matrixPairsOf(t, releaseYML, "test")
	inBuild := matrixPairsOf(t, releaseYML, "build")
	if strings.Join(inTest, " ") != strings.Join(inBuild, " ") {
		t.Fatalf("матрица job test разошлась с job build в %s — релиз соберётся там, где тесты не шли:\n"+
			"  job test:  %v\n  job build: %v", releaseYML, inTest, inBuild)
	}
}

// --- следствие A5 № 1 --------------------------------------------------------

func bashPath(t *testing.T) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		// Тот же bash, которым раннер исполняет `shell: bash` на Windows (Git
		// for Windows). exec.LookPath здесь опасен: первым в PATH бывает
		// System32\bash.exe — WSL, совсем другая среда.
		for _, p := range []string{`C:\Program Files\Git\bin\bash.exe`, `C:\Program Files (x86)\Git\bin\bash.exe`} {
			if _, err := os.Stat(p); err == nil {
				return p
			}
		}
		t.Fatalf("не найден bash из Git for Windows — шаги workflow гонять нечем, тест не может ничего проверить")
	}
	p, err := exec.LookPath("bash")
	if err != nil {
		t.Fatalf("не найден bash — шаги workflow гонять нечем, тест не может ничего проверить: %v", err)
	}
	return p
}

// runStepBody исполняет тело run: так же, как раннер при `shell: bash`
// (`bash --noprofile --norc -eo pipefail {0}`), в каталоге dir. Переменные,
// которые шаг читает, задаются только из vars — унаследованные из окружения
// раннера вычищаются, иначе тест на раннере проверял бы не то.
func runStepBody(t *testing.T, body, dir string, vars map[string]string) (string, error) {
	t.Helper()
	script := filepath.Join(t.TempDir(), "step.sh")
	if err := os.WriteFile(script, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bashPath(t), "--noprofile", "--norc", "-eo", "pipefail", filepath.ToSlash(script))
	cmd.Dir = dir
	for _, kv := range os.Environ() {
		k := kv[:max(strings.IndexByte(kv, '='), 0)]
		if k == "RUNNER_ARCH" || k == "DECLARED_ARCH" || k == "ATTEST_SUBJECTS" {
			continue
		}
		cmd.Env = append(cmd.Env, kv)
	}
	for k, v := range vars {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// TestReleaseRunnerArchStep — в job build есть шаг, сверяющий измеренную
// раннером архитектуру (RUNNER_ARCH) с объявленной (matrix.arch); он
// исполняется безусловно, стоит до сборки и ПАДАЕТ на расхождении и на
// незнании. Последнее проверяется настоящим bash на теле шага: текст шага
// может быть цел, а сравнение обеззублено.
func TestReleaseRunnerArchStep(t *testing.T) {
	wf := loadWorkflow(t, releaseYML)
	build := jobOf(t, wf, releaseYML, "build")

	archIdx, buildIdx := -1, -1
	for i, s := range build.Steps {
		if strings.Contains(s.Run, "RUNNER_ARCH") && archIdx < 0 {
			archIdx = i
		}
		if strings.Contains(s.Run, "scripts/build-release.sh") && buildIdx < 0 {
			buildIdx = i
		}
	}
	if archIdx < 0 {
		t.Fatalf("в %s (job build) нет шага, читающего RUNNER_ARCH — поле matrix.arch снова справочное, "+
			"его не сверяет с раннером ничто (следствие A5 № 1)", releaseYML)
	}
	if buildIdx < 0 || archIdx > buildIdx {
		t.Fatalf("в %s (job build) шаг сверки архитектуры (№%d) обязан стоять ДО сборки (№%d)", releaseYML, archIdx+1, buildIdx+1)
	}
	step := build.Steps[archIdx]
	if live, why := stepLive(build, step); !live {
		t.Fatalf("в %s шаг сверки архитектуры обеззублен: %s", releaseYML, why)
	}
	if got := strings.Join(strings.Fields(step.Env["DECLARED_ARCH"]), ""); got != "${{matrix.arch}}" {
		t.Fatalf("в %s шаг сверки архитектуры берёт DECLARED_ARCH не из matrix.arch: %q", releaseYML, step.Env["DECLARED_ARCH"])
	}

	dir := t.TempDir()
	cases := []struct {
		runner, declared string
		ok               bool
		msg              string
	}{
		{"X64", "amd64", true, "архитектура раннера: X64 = matrix.arch amd64"},
		{"ARM64", "arm64", true, "архитектура раннера: ARM64 = matrix.arch arm64"},
		{"X64", "arm64", false, "СТОП: раннер измерен как X64 (amd64), а matrix.arch объявляет arm64"},
		{"ARM64", "amd64", false, "СТОП: раннер измерен как ARM64 (arm64), а matrix.arch объявляет amd64"},
		{"", "amd64", false, "СТОП: RUNNER_ARCH пуста"},
		{"X86", "amd64", false, "СТОП: RUNNER_ARCH=X86 — значение, которого этот шаг не знает"},
		{"X64", "", false, "СТОП: matrix.arch пуст"},
	}
	for _, c := range cases {
		vars := map[string]string{"DECLARED_ARCH": c.declared}
		if c.runner != "" {
			vars["RUNNER_ARCH"] = c.runner
		}
		out, err := runStepBody(t, step.Run, dir, vars)
		// Одна точка сообщения на три причины: иначе подсадка будит две
		// ветки сразу, и немота одной прикрыта другой (ревью QA-01).
		problem := ""
		switch {
		case c.ok && err != nil:
			problem = fmt.Sprintf("шаг упал, а должен пройти (%v)", err)
		case !c.ok && err == nil:
			problem = "шаг прошёл, а должен упасть — сверка обеззублена"
		case !strings.Contains(out, c.msg):
			problem = "в выводе нет «" + c.msg + "»"
		}
		if problem != "" {
			t.Errorf("RUNNER_ARCH=%s, matrix.arch=%s: %s:\n%s", c.runner, c.declared, problem, out)
		}
	}
}

// --- долг A4в: списки пакетов ------------------------------------------------

// goTestCommand — токены единственного исполняемого шага `go test` в job.
func goTestCommand(t *testing.T, path, job string) []string {
	t.Helper()
	j := jobOf(t, loadWorkflow(t, path), path, job)
	var found [][]string
	for _, s := range j.Steps {
		body := strings.TrimSpace(stripShellComments(s.Run))
		if !strings.HasPrefix(body, "go test") {
			continue
		}
		if live, why := stepLive(j, s); !live {
			t.Errorf("в %s (job %s) шаг go test обеззублен: %s", path, job, why)
		}
		first, rest, multi := strings.Cut(body, "\n")
		words := shellWords(first)
		p := goTestProblem(words)
		if multi {
			p = "тело шага не одна команда (дальше: «" + strings.TrimSpace(rest) + "») — сторож сравнивает команду целиком"
		}
		if p != "" {
			t.Errorf("в %s (job %s) команда go test ничего не гарантирует: %s\n  команда: %s", path, job, p, body)
		}
		found = append(found, texts(words))
	}
	if len(found) != 1 {
		t.Fatalf("в %s (job %s) шагов go test %d, ожидался ровно один — тест перестал что-либо проверять", path, job, len(found))
	}
	return found[0]
}

// allowedGoTestFlags — закрытый список флагов go test (ревью QA-01,
// поднято координатором до обязательного). Одинаковая порча в ОБОИХ файлах
// (`|| true`, `-run NOTHING`, `-list .`) оставляет команды равными, и
// сравнение их между собой её не видит. Поэтому смысл команды проверяется
// отдельно: флаги только отсюда, оба обязательны, после пакетов ничего.
var allowedGoTestFlags = map[string]bool{"-race": true, "-count=1": true}

// goTestProblem — первая причина, по которой команда go test ничего не
// гарантирует, или пустая строка. Одна точка сообщения на все причины.
func goTestProblem(words []shword) string {
	if len(words) < 2 || words[0].text != "go" || words[1].text != "test" {
		return "команда не начинается с `go test`"
	}
	seen := map[string]bool{}
	pkgs := 0
	for _, w := range words[2:] {
		switch {
		case w.op:
			return "после команды стоит «" + w.text + "» — `|| true`, `;`, перенаправление или `&` глушат провал тестов"
		case strings.HasPrefix(w.text, "./"):
			pkgs++
		case allowedGoTestFlags[w.text]:
			seen[w.text] = true
		default:
			return "аргумент «" + w.text + "» вне закрытого списка allowedGoTestFlags и не пакет ./… — " +
				"`-run`, `-skip`, `-list`, `-short` отключают тесты молча. Законен? Внеси его в список"
		}
	}
	for f := range allowedGoTestFlags {
		if !seen[f] {
			return "нет обязательного флага " + f
		}
	}
	if pkgs == 0 {
		return "нет ни одного пакета"
	}
	return ""
}

// TestGoTestPackagesMatch — команда `go test` на PR (ci.yml, checks) и на
// теге (release.yml, test) одна и та же, и её пакеты покрывают КАЖДЫЙ
// каталог репозитория с *_test.go. До A6 в release.yml не было ./cmd/gui/:
// тесты GUI на релизной сборке не выполнялись вовсе.
func TestGoTestPackagesMatch(t *testing.T) {
	inCI := goTestCommand(t, ciYML, "checks")
	inRelease := goTestCommand(t, releaseYML, "test")
	if strings.Join(inCI, " ") != strings.Join(inRelease, " ") {
		t.Errorf("списки go test разошлись — на теге проверяется не то, что на PR:\n"+
			"  ci.yml, job checks:   %s\n  release.yml, job test: %s", strings.Join(inCI, " "), strings.Join(inRelease, " "))
	}

	// Покрытие: каждый каталог с тестами обязан попасть под какой-то шаблон
	// в ОБОИХ файлах. Равенство двух списков само по себе не мешает обоим
	// одновременно потерять пакет.
	root := filepath.Join("..", "..")
	dirs := map[string]bool{}
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && p != root && (strings.HasPrefix(d.Name(), ".") || d.Name() == "testdata" || d.Name() == "vendor") {
			return filepath.SkipDir
		}
		if !d.IsDir() && strings.HasSuffix(d.Name(), "_test.go") {
			rel, _ := filepath.Rel(root, filepath.Dir(p))
			dirs[filepath.ToSlash(rel)] = true
		}
		return nil
	})
	if err != nil {
		t.Fatalf("обход репозитория: %v", err)
	}
	// Канарейка ветки покрытия подсаживает каталог с тестами сюда, в
	// результат обхода: файл в дереве репозитория она создавать не вправе.
	if d := plantedTestDir(t); d != "" {
		dirs[d] = true
	}
	if len(dirs) == 0 {
		t.Fatalf("не найдено ни одного каталога с *_test.go — тест перестал что-либо проверять")
	}
	var sorted []string
	for d := range dirs {
		sorted = append(sorted, d)
	}
	sort.Strings(sorted)
	for name, cmd := range map[string][]string{"ci.yml": inCI, "release.yml": inRelease} {
		for _, d := range sorted {
			if !covered(d, cmd) {
				t.Errorf("списки go test разошлись с репозиторием: каталог %s с тестами не входит в go test файла %s: %s",
					d, name, strings.Join(cmd, " "))
			}
		}
	}
}

func covered(dir string, cmd []string) bool {
	for _, tok := range cmd {
		if !strings.HasPrefix(tok, "./") {
			continue
		}
		pat := strings.TrimSuffix(strings.TrimPrefix(tok, "./"), "/")
		if rest, ok := strings.CutSuffix(pat, "/..."); ok {
			if dir == rest || strings.HasPrefix(dir, rest+"/") {
				return true
			}
			continue
		}
		if pat == "..." || dir == pat {
			return true
		}
	}
	return false
}

// --- SHA256SUMS в аттестации -------------------------------------------------

var releaseAssets = []string{
	"amnezia-admin-linux-amd64", "amnezia-admin-linux-arm64", "amnezia-admin-windows-amd64.exe",
	"amnezia-admin-macos-amd64", "amnezia-admin-macos-arm64", "amnezia-admin-gui-linux-amd64",
	"amnezia-admin-gui-windows-amd64.exe", "amnezia-admin-gui-macos-arm64", "SHA256SUMS",
}

func sampleDist(t *testing.T, names []string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "dist"), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, n := range names {
		if err := os.WriteFile(filepath.Join(dir, "dist", n), []byte(n), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// TestReleaseAttestsChecksums — SHA256SUMS подписывается вместе с бинарями.
//
// Статически: множество субъектов живёт в одном месте (env ATTEST_SUBJECTS
// job release), attest-build-provenance берёт именно его, шаг проверки
// субъектов стоит после сумм и до аттестации. Поведенчески: тело шага
// проверки гоняется bash над каталогом-образцом из девяти файлов — и обязано
// пройти, а на образце с лишним или без SHA256SUMS — упасть.
func TestReleaseAttestsChecksums(t *testing.T) {
	wf := loadWorkflow(t, releaseYML)
	rel := jobOf(t, wf, releaseYML, "release")

	subjects := rel.Env["ATTEST_SUBJECTS"]
	if strings.TrimSpace(subjects) == "" {
		t.Fatalf("в %s (job release) нет env ATTEST_SUBJECTS — множество субъектов аттестации не в одном месте", releaseYML)
	}

	sumsIdx, checkIdx, attestIdx := -1, -1, -1
	for i, s := range rel.Steps {
		switch {
		case strings.Contains(s.Run, "sha256sum") && strings.Contains(s.Run, "SHA256SUMS"):
			sumsIdx = i
		case strings.Contains(s.Run, "ATTEST_SUBJECTS"):
			checkIdx = i
		case strings.HasPrefix(s.Uses, "actions/attest-build-provenance@"):
			attestIdx = i
			if got := strings.Join(strings.Fields(s.With["subject-path"]), ""); got != "${{env.ATTEST_SUBJECTS}}" {
				t.Errorf("attest-build-provenance берёт subject-path %q, а не ${{ env.ATTEST_SUBJECTS }} — "+
					"проверяется одно множество, подписывается другое", s.With["subject-path"])
			}
		}
	}
	if sumsIdx < 0 || checkIdx < 0 || attestIdx < 0 {
		t.Fatalf("в %s (job release) не найдены шаги: сумм №%d, проверки субъектов №%d, аттестации №%d (0 — нет)",
			releaseYML, sumsIdx+1, checkIdx+1, attestIdx+1)
	}
	if !(sumsIdx < checkIdx && checkIdx < attestIdx) {
		t.Errorf("порядок шагов нарушен: суммы №%d, проверка субъектов №%d, аттестация №%d — "+
			"аттестация обязана идти после сумм, проверка — между ними", sumsIdx+1, checkIdx+1, attestIdx+1)
	}
	check := rel.Steps[checkIdx]
	if live, why := stepLive(rel, check); !live {
		t.Errorf("шаг проверки субъектов обеззублен: %s", why)
	}

	vars := map[string]string{"ATTEST_SUBJECTS": subjects}
	out, err := runStepBody(t, check.Run, sampleDist(t, releaseAssets), vars)
	if err != nil || !strings.Contains(out, "субъект: dist/SHA256SUMS") {
		t.Errorf("на образце из девяти файлов шаг проверки субъектов не прошёл (err=%v):\n%s", err, out)
	}
	for _, bad := range []struct {
		name  string
		files []string
		msg   string
	}{
		{"лишний файл", append(append([]string{}, releaseAssets...), "extra.txt"), "СТОП: dist/extra.txt публикуется, но не входит в субъекты аттестации"},
		{"нет SHA256SUMS", releaseAssets[:8], "СТОП: субъект аттестации 'dist/SHA256SUMS' (шаблон 'dist/SHA256SUMS') — нет такого файла"},
	} {
		out, err := runStepBody(t, check.Run, sampleDist(t, bad.files), vars)
		if err == nil || !strings.Contains(out, bad.msg) {
			t.Errorf("образец «%s»: шаг проверки субъектов обязан упасть с «%s» (err=%v):\n%s", bad.name, bad.msg, err, out)
		}
	}
}

// --- persist-credentials -----------------------------------------------------

// TestCheckoutsDoNotPersistCredentials — КАЖДЫЙ actions/checkout в обоих
// workflow стоит с persist-credentials: false (A6, ревью SEC-01 поднято
// координатором до обязательного). Даже токен только на чтение, оставленный
// в .git/config, доступен любому следующему шагу — сборке, cgo, сторонним
// модулям. Правка дешёвая и закрывает класс целиком, а не job с правом
// записи.
func TestCheckoutsDoNotPersistCredentials(t *testing.T) {
	checkouts := 0
	for _, path := range []string{releaseYML, ciYML} {
		wf := loadWorkflow(t, path)
		for name, j := range wf.Jobs {
			for i, s := range j.Steps {
				if !strings.HasPrefix(s.Uses, "actions/checkout@") {
					continue
				}
				checkouts++
				if s.With["persist-credentials"] != "false" {
					t.Errorf("в %s (job %s) checkout шагом №%d без persist-credentials: false — "+
						"токен остаётся в .git/config и доступен любому следующему шагу", path, name, i+1)
				}
			}
		}
	}
	if checkouts == 0 {
		t.Fatalf("ни в %s, ни в %s не найдено ни одного actions/checkout — тест перестал что-либо проверять", releaseYML, ciYML)
	}
}
