// Файл matrix_test.go — сторож против расхождения двух списков пар
// «ОС / раннер»: матрицы job build в .github/workflows/release.yml и матрицы
// job checks в .github/workflows/ci.yml.
//
// Зачем: числа и списки, живущие в двух файлах, расходятся — в этом проекте
// это уже дважды роняло релиз. Расхождение матриц означает, что на теге
// впервые исполнится то, чего не видел ни один pull request, — ровно ради
// этого CI и заводился.
//
// Почему сторож здесь, а не шагом внутри ci.yml. Во-первых, этот тест попадает
// в уже существующую команду `go test -race -count=1 ./core/ ./internal/...
// ./cmd/cli/`, которую гоняют И ci.yml, И release.yml, — значит расхождение
// ловится ещё и на теге, куда ci.yml не приходит. Во-вторых, шаг внутри ci.yml
// самореферентен: ошибка в ci.yml, из-за которой workflow не стартует, унесла
// бы сторож вместе с собой, а это ровно тот случай, ради которого сторож
// заводится. Оба workflow-файла здесь только читаются.
package ciguard

import (
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// Заголовок job — ключ на двух пробелах отступа: `  build:`, `  checks:`.
var jobHeaderRe = regexp.MustCompile(`^ {2}([A-Za-z0-9_-]+):\s*$`)

// Строки матрицы. Отступ снят TrimSpace, поэтому ведущий `- ` у первой строки
// элемента списка разбирается явно.
var (
	osRe     = regexp.MustCompile(`^(?:-\s+)?os:\s*([A-Za-z0-9._-]+)\s*$`)
	runnerRe = regexp.MustCompile(`^(?:-\s+)?runner:\s*([A-Za-z0-9._-]+)\s*$`)
)

// pairsOf возвращает пары «ос/раннер» из матрицы указанного job. Разбор
// построчный и через strings.TrimSpace — на атрибут `.github/**/*.yml text
// eol=lf` сторож не опирается: лишний `\r` не должен превращать сторож в
// зелёный.
func pairsOf(t *testing.T, path, job string) []string {
	t.Helper()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("не прочитать %s: %v", path, err)
	}

	var (
		pairs     []string
		inJob     bool
		pendingOS string
	)
	for _, raw := range strings.Split(string(data), "\n") {
		if m := jobHeaderRe.FindStringSubmatch(strings.TrimRight(raw, "\r")); m != nil {
			// Начался следующий job — разбор нужного закончен.
			if inJob && m[1] != job {
				break
			}
			inJob = m[1] == job
			continue
		}
		if !inJob {
			continue
		}

		line := strings.TrimSpace(raw)
		if strings.HasPrefix(line, "#") {
			continue
		}
		if m := osRe.FindStringSubmatch(line); m != nil {
			pendingOS = m[1]
			continue
		}
		if m := runnerRe.FindStringSubmatch(line); m != nil {
			if pendingOS == "" {
				t.Errorf("в %s (job %s) раннер %q встретился без предшествующей строки os:", path, job, m[1])
				continue
			}
			pairs = append(pairs, pendingOS+"/"+m[1])
			pendingOS = ""
		}
	}

	// Сравнение пустого с пустым зелёным быть не имеет права: если разбор
	// перестал находить пары (переименовали ключ, перенесли строку, сменили
	// форму записи), сторож обязан покраснеть, а не отрапортовать совпадение.
	if len(pairs) == 0 {
		t.Fatalf("в %s не найдено ни одной пары os/runner — тест перестал что-либо проверять", path)
	}
	sort.Strings(pairs)
	return pairs
}

func TestCIMatrixMatchesReleaseBuild(t *testing.T) {
	const (
		releaseYML = "../../.github/workflows/release.yml"
		ciYML      = "../../.github/workflows/ci.yml"
	)

	inRelease := pairsOf(t, releaseYML, "build")
	inCI := pairsOf(t, ciYML, "checks")

	if strings.Join(inRelease, " ") != strings.Join(inCI, " ") {
		t.Fatalf("матрицы ОС разошлись — на теге исполнится то, чего не видел ни один PR:\n"+
			"  release.yml, job build:  %v\n"+
			"  ci.yml, job checks:      %v", inRelease, inCI)
	}
}
