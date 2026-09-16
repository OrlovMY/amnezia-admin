// Файл matrix_test.go — сторожа против расхождения того, что записано в двух
// файлах сразу: матрицы пар «ОС / раннер» (job build в release.yml против job
// checks в ci.yml) и версии actionlint (scripts/dev-tools.sh против
// release.yml).
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
//
// Разбор — настоящим YAML-разборщиком, а НЕ построчными регулярками (ревью,
// З1). Построчный разбор давал ложно-зелёный: пара ключей os:/runner:,
// встреченная где угодно внутри job — например в env: шага «Сборка», —
// засчитывалась как элемент матрицы, и удаление macOS из настоящей матрицы
// проходило молча. Обратная слепота того же класса: переменная окружения с
// именем runner давала бы ложную тревогу. Оба случая лечатся тем, что путь к
// данным задан структурой (jobs.<job>.strategy.matrix.include), а не тем, на
// что похожа строка.
package ciguard

import (
	"os"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// workflow — ровно та часть схемы workflow-файла, которая нужна сторожу.
// Остальное yaml.v3 молча пропускает.
type workflow struct {
	Jobs map[string]struct {
		Strategy struct {
			Matrix struct {
				Include []map[string]string `yaml:"include"`
			} `yaml:"matrix"`
		} `yaml:"strategy"`
	} `yaml:"jobs"`
}

// matrixPairsOf возвращает пары «ос/раннер» из jobs.<job>.strategy.matrix.include
// указанного файла — и ниоткуда больше.
func matrixPairsOf(t *testing.T, path, job string) []string {
	t.Helper()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("не прочитать %s: %v", path, err)
	}

	var wf workflow
	if err := yaml.Unmarshal(data, &wf); err != nil {
		t.Fatalf("не разобрать %s как YAML: %v", path, err)
	}

	j, ok := wf.Jobs[job]
	if !ok {
		names := make([]string, 0, len(wf.Jobs))
		for name := range wf.Jobs {
			names = append(names, name)
		}
		sort.Strings(names)
		t.Fatalf("в %s нет job %q (есть: %v) — тест перестал что-либо проверять", path, job, names)
	}

	var pairs []string
	for i, entry := range j.Strategy.Matrix.Include {
		osName, hasOS := entry["os"]
		runner, hasRunner := entry["runner"]
		if !hasOS || !hasRunner {
			t.Errorf("в %s (job %s) элемент матрицы №%d не содержит пары os/runner: %v", path, job, i+1, entry)
			continue
		}
		pairs = append(pairs, osName+"/"+runner)
	}

	// Сравнение пустого с пустым зелёным быть не имеет права: если разбор
	// перестал находить пары (переименовали ключ, перенесли матрицу, сменили
	// форму записи), сторож обязан покраснеть, а не отрапортовать совпадение.
	if len(pairs) == 0 {
		t.Fatalf("в %s не найдено ни одной пары os/runner — тест перестал что-либо проверять", path)
	}
	sort.Strings(pairs)
	return pairs
}

func TestCIMatrixMatchesReleaseBuild(t *testing.T) {
	inRelease := matrixPairsOf(t, releaseYML, "build")
	inCI := matrixPairsOf(t, ciYML, "checks")

	if strings.Join(inRelease, " ") != strings.Join(inCI, " ") {
		t.Fatalf("матрицы ОС разошлись — на теге исполнится то, чего не видел ни один PR:\n"+
			"  release.yml, job build:  %v\n"+
			"  ci.yml, job checks:      %v", inRelease, inCI)
	}
}
