// Файл pipes_test.go — сторож формы «ранний выход читателя конвейера»
// (раунд SIGPIPE, main f0febbd).
//
// Что случилось. `printf '%s\n' "${subjects[@]}" | grep -qxF -- "$f"` в шаге
// «Субъекты аттестации». grep -q выходит на первом совпадении; если printf
// ещё пишет, он получает SIGPIPE (код 141), а под pipefail (раннер исполняет
// run: как `bash -eo pipefail`, наши тела сами ставят set -euo pipefail)
// провал пишущего становится провалом всего конвейера: «входит» читается как
// «не входит». Сбой плавающий — зависит от того, успел ли printf дописать до
// выхода grep. На Linux CI main покраснел; на релизе это ронял бы выпуск.
//
// Правило — запрет ФОРМЫ, а не списка мест: в теле run: обоих workflow и в
// scripts/*.sh после одиночного `|` не может стоять читатель, выходящий
// раньше конца ввода: `grep` с -q/-m (в любом сочетании букв), --quiet,
// --silent, --max-count, а также `head`. Проверка принадлежности делается
// here-string (`grep -q … <<< "$x"`), циклом по массиву или сначала в
// переменную. Закрытый список исключений пуст.
//
// ГРАНИЦА. Не опознаются: `sed … q`, `awk '… exit'`, `read` в цикле с
// break, читатель в подоболочке или функции, конвейер, собранный из
// переменных. Все эти формы в файлах сейчас не встречаются.
package ciguard

import (
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// earlyReaderRe — одиночный `|` (не `||`), за ним grep с ранним выходом или
// head. `command grep` и `\grep` — то же самое.
var earlyReaderRe = regexp.MustCompile(`(?:^|[^|])\|\s*(?:command\s+|\\)?(?:grep\b[^|;&]*?\s(?:-[A-Za-z]*[qm][A-Za-z]*|--quiet|--silent|--max-count\S*)(?:\s|$)|head\b)`)

func TestNoEarlyExitPipeReader(t *testing.T) {
	type src struct{ where, body string }
	var srcs []src
	for _, path := range []string{releaseYML, ciYML} {
		wf := loadWorkflow(t, path)
		for jn, j := range wf.Jobs {
			for i, s := range j.Steps {
				body := strings.ReplaceAll(stripShellComments(s.Run), "\\\n", " ")
				srcs = append(srcs, src{fmtStep(path, jn, i, s.Name), body})
			}
		}
	}
	scripts, err := filepath.Glob(filepath.Join("..", "..", "scripts", "*.sh"))
	if err != nil || len(scripts) == 0 {
		fatal(t, "не найдено ни одного scripts/*.sh (err=%v) — тест перестал что-либо проверять", err)
	}
	sort.Strings(scripts)
	for _, p := range scripts {
		srcs = append(srcs, src{filepath.ToSlash(p), stripShellComments(string(readSource(t, filepath.ToSlash(p))))})
	}
	lines := 0
	for _, s := range srcs {
		for _, l := range strings.Split(s.body, "\n") {
			lines++
			if earlyReaderRe.MatchString(l) {
				fail(t, "%s: «%s» — читатель конвейера выходит раньше конца ввода; пишущий ловит SIGPIPE, "+
					"и под pipefail «нашёл» становится «не нашёл» (плавающий сбой, main f0febbd). "+
					"Принадлежность — here-string `grep -q … <<< \"$x\"`, циклом или через переменную",
					s.where, strings.TrimSpace(l))
			}
		}
	}
	if lines == 0 {
		fatal(t, "не прочитано ни одной строки run: и scripts/*.sh — тест перестал что-либо проверять")
	}
}

func fmtStep(path, job string, i int, name string) string {
	return fmt.Sprintf("%s (job %s, шаг №%d «%s»)", path, job, i+1, name)
}
