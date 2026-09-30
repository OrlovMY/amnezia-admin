// Файл programs_test.go — закрытый список ПРОГРАММ в позиции команды
// (долги CI, раунд 4; AU-LOGIC R1–R3).
//
// Почему. Код, попадающий в оболочку мимо лексера, нашёлся в четвёртой
// форме подряд: heredoc в bash, `$SHELL -c`, `"$1" -c` через функцию,
// интерпретаторы (python3 -c, perl -e, awk system, trap "…"). Запрещать их
// по одной — перечень плохого (память closed-list-over-blacklist).
// Перевёрнуто: слово в позиции команды (после присваиваний VAR=…) в каждом
// run: обоих workflow и в scripts/*.sh — из allowedPrograms, с
// обоснованием и проверкой аргументов, где она нужна; либо имя функции,
// определённой в том же источнике (её тело проверяется тем же правилом);
// либо, если имя — подстановка ("$SHELLCHECK_BIN"), — точное МЕСТО из
// allowedDynPlaces (файл, текст строки, слово). Всё прочее — красное:
// trap, eval, source, ., env, exec, command, xargs, find, python3, perl,
// node, ash, mksh, …
//
// Дополнительно:
//   - bash — только точной записью из allowedShellCalls и без
//     перенаправления входа (heredoc/here-string);
//   - оболочка словом-аргументом (в кавычках или без) — красная вне
//     allowedShellCalls: `find -exec "bash"`, `sudo sh`;
//   - определение функции с защищённым именем — красное (F2);
//   - список не немой: запись, которая больше не встречается в файлах, —
//     красная; число разных программ сверяется точно (wantPrograms).
//
// ГРАНИЦА. Аргументы программ из списка не разбираются как код, кроме
// перечисленных проверок (awk без system/getline/вывода в трубу, sudo —
// только apt-get, bash — allowedShellCalls). `go run` исполняет Go-код
// модуля по версии — это инструмент проекта, его версии закреплены
// отдельно (TestActionlintVersionSingleSource).
package ciguard

import (
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// shDef — определение функции в форме имя() (тело { } или ( )).
type shDef struct {
	name string
	line int
}

// shells — имена оболочек: их появление аргументом — тоже вызов.
var shells = map[string]bool{"bash": true, "sh": true, "dash": true, "zsh": true, "ksh": true,
	"ash": true, "mksh": true, "yash": true, "posh": true, "busybox": true, "fish": true, "csh": true, "tcsh": true}

// allowedShellCalls — ЗАКРЫТЫЙ список вызовов bash (раунд 3, F1).
var allowedShellCalls = map[string]string{
	`bash scripts/check-version-growth.sh "$GITHUB_REF_NAME"`: "release.yml, три job: рост версии тега",
	`bash scripts/build-release.sh ${{ matrix.os }}`:          "ci.yml и release.yml: сборка",
	`bash scripts/dev-tools.sh`:                               "ci.yml: пиновый shellcheck",
}

type progRule struct {
	why   string
	check func(args []shWord) string // nil — аргументы не проверяются
}

func noArgWord(bad ...string) func([]shWord) string {
	return func(args []shWord) string {
		for _, a := range args {
			for _, b := range bad {
				if strings.Contains(a.lit, b) {
					return "в аргументе есть «" + b + "» — код в обход лексера"
				}
			}
		}
		return ""
	}
}

// allowedPrograms — ЗАКРЫТЫЙ список: ровно то, что сейчас стоит в позиции
// команды в файлах (снято разбором 30.09.2026).
var allowedPrograms = map[string]progRule{
	// встроенные bash
	"[":        {why: "проверка условия (test)"},
	"[[":       {why: "условие bash; содержимое — не команды"},
	"cd":       {why: "смена каталога"},
	"continue": {why: "цикл"},
	"declare":  {why: "объявление массивов"},
	"echo":     {why: "вывод сообщений"},
	"exit":     {why: "код выхода"},
	"export":   {why: "переменные для следующих команд; GO*/BASH_ENV сверяет TestNoToolEnvironmentOverrides"},
	"for":      {why: "цикл"},
	"local":    {why: "локальные переменные функций"},
	"printf":   {why: "вывод"},
	"read":     {why: "чтение строк в цикле"},
	"return":   {why: "выход из функции"},
	"set":      {why: "set -euo pipefail"},
	"shift":    {why: "сдвиг аргументов"},
	"shopt":    {why: "nullglob и подобные"},
	"test":     {why: "проверка условия"},
	"true":     {why: "пустая команда в || true"},
	// внешние программы
	"awk": {why: "фильтр; без system/getline/вывода в трубу — иначе запускает оболочку",
		check: noArgWord("system", "getline", "| \"", "|\"")},
	"base64":    {why: "образец канарейки в check-history-keys.sh"},
	"bash":      {why: "только allowedShellCalls — наши scripts/*.sh, разбираемые сторожем"},
	"cat":       {why: "склейка потоков"},
	"chmod":     {why: "права на скачанный shellcheck"},
	"curl":      {why: "загрузка shellcheck в dev-tools.sh (суммы сверяются)"},
	"fold":      {why: "образцы канарейки"},
	"gcc":       {why: "проверка наличия C-компилятора для GUI (cgo)"},
	"git":       {why: "происхождение тега, история"},
	"go":        {why: "сборка, тесты, vet, go run actionlint по закреплённой версии"},
	"gofmt":     {why: "проверка формата"},
	"grep":      {why: "поиск; как читатель конвейера — ещё и pipeReaders"},
	"head":      {why: "только писателем (head -c /dev/zero); читателем запрещён pipeReaders"},
	"ls":        {why: "список файлов"},
	"mkdir":     {why: "каталоги"},
	"mv":        {why: "переименование"},
	"sed":       {why: "фильтр; читателем — без q/Q (pipeReaders)", check: noArgWord("e ", "/e")},
	"sha256sum": {why: "контрольные суммы"},
	"sort":      {why: "сортировка"},
	"sudo": {why: "только sudo apt-get update|install на Linux-раннере", check: func(args []shWord) string {
		if len(args) < 2 || args[0].lit != "apt-get" || (args[1].lit != "update" && args[1].lit != "install") {
			return "sudo допустим только как `sudo apt-get update|install …`"
		}
		return ""
	}},
	"tail":  {why: "последние строки"},
	"tar":   {why: "распаковка shellcheck"},
	"tr":    {why: "фильтр символов"},
	"uname": {why: "определение цели в dev-tools.sh"},
	"unzip": {why: "распаковка shellcheck под Windows"},
	"wc":    {why: "счёт строк"},
}

// wantPrograms — сколько РАЗНЫХ программ из списка сейчас встречается.
const wantPrograms = 44

// allowedDynPlaces — ЗАКРЫТЫЙ список МЕСТ, где имя команды — подстановка
// (AU-LOGIC R1: ключ без места разрешал `"$1" -c` в любом файле). Ключ —
// файл, текст строки целиком (без отступа) и само слово. Каждое место
// обязано встречаться ровно один раз: пропавшее — красное.
var allowedDynPlaces = map[string]string{
	`../../.github/workflows/ci.yml|sc_out="$("$SHELLCHECK_BIN" --version 2>&1)" || { echo "СТОП: $SHELLCHECK_BIN не запускается" >&2; exit 1; }|"$SHELLCHECK_BIN"`: "пиновый shellcheck по пути из dev-tools.sh",
	`../../.github/workflows/ci.yml|"$SHELLCHECK_BIN" "${files[@]}"|"$SHELLCHECK_BIN"`:                                                                              "shellcheck по scripts/*.sh",
	`../../.github/workflows/ci.yml|out="$("$@" 2>&1)" || { echo "СТОП: '$*' не выполнилась — инструмента нет" >&2; exit 1; }|"$@"`:                                 "функция проверки наличия инструмента; её вызовы — слова из этого же шага, проверяются здесь",
	`../../.github/workflows/release.yml|out="$("./$bin" version)"|"./$bin"`:                                                                                        "запуск собранного бинаря (version)",
}

var assignRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*(\[[^]]*\])?\+?=`)

// protectedNames — имена, которые нельзя переопределять функцией (F2).
var protectedNames = func() map[string]bool {
	m := map[string]bool{"eval": true, "source": true, "alias": true, "trap": true, "exec": true, "env": true}
	for k := range pipeReaders {
		m[k] = true
	}
	for k := range shells {
		m[k] = true
	}
	for k := range allowedPrograms {
		m[k] = true
	}
	return m
}()

type shellSrc struct{ file, where, body string }

func shellSources(t *testing.T) []shellSrc {
	t.Helper()
	var srcs []shellSrc
	for _, path := range []string{releaseYML, ciYML} {
		wf := loadWorkflow(t, path)
		var jobs []string
		for jn := range wf.Jobs {
			jobs = append(jobs, jn)
		}
		sort.Strings(jobs)
		for _, jn := range jobs {
			for i, s := range wf.Jobs[jn].Steps {
				srcs = append(srcs, shellSrc{path, fmtStep(path, jn, i, s.Name), s.Run})
			}
		}
	}
	scripts := scriptPaths(t)
	for _, p := range scripts {
		srcs = append(srcs, shellSrc{p, p, string(readSource(t, p))})
	}
	return srcs
}

func TestCommandProgramsClosedList(t *testing.T) {
	seen := map[string]int{}
	distinct := map[string]bool{} // все буквальные имена в позиции команды, кроме функций
	placeUsed := map[string]int{}
	cmds := 0
	for _, s := range shellSources(t) {
		p := parseShell(s.body)
		// ошибки разбора сообщает TestNoEarlyExitPipeReader
		lines := strings.Split(strings.ReplaceAll(s.body, "\r\n", "\n"), "\n")
		defined := map[string]bool{}
		for _, d := range p.defs {
			defined[d.name] = true
			if protectedNames[d.name] {
				fail(t, "%s: строка %d: определение функции «%s» переопределяет имя из закрытого списка — "+
					"программа под этим именем уже не та, которую проверяет сторож", s.where, d.line, d.name)
			}
		}
		for _, c := range p.cmds {
			k := 0
			for k < len(c.words) && assignRe.MatchString(c.words[k].raw) {
				k++
			}
			if k == len(c.words) {
				continue
			}
			cmds++
			w := c.words[k]
			args := c.words[k+1:]
			var raws []string
			for _, x := range c.words[k:] {
				raws = append(raws, x.raw)
			}
			call := strings.Join(raws, " ")
			line := ""
			if c.line-1 < len(lines) && c.line > 0 {
				line = strings.TrimSpace(lines[c.line-1])
			}
			where := s.where + ": строка " + strconv.Itoa(c.line)
			literal := !(w.dyn || w.quoted || w.raw != w.lit)
			if literal && !(defined[w.lit] && !protectedNames[w.lit]) {
				distinct[w.lit] = true
			}
			if !literal {
				key := s.file + "|" + line + "|" + w.raw
				if _, ok := allowedDynPlaces[key]; !ok {
					fail(t, "%s: команда с подстановкой или кавычками в имени «%s» вне закрытого списка мест "+
						"allowedDynPlaces — что исполнится, сторож не знает", where, call)
				} else {
					placeUsed[key]++
				}
			} else if defined[w.lit] && !protectedNames[w.lit] {
				// функция этого же источника — её тело проверено этим же циклом
			} else if rule, ok := allowedPrograms[w.lit]; !ok {
				fail(t, "%s: программа «%s» вне закрытого списка allowedPrograms («%s»). Законно? Внеси строкой "+
					"с обоснованием; интерпретатор или оболочка исполняет код мимо лексера", where, w.lit, call)
			} else {
				seen[w.lit]++
				if rule.check != nil {
					if pr := rule.check(args); pr != "" {
						fail(t, "%s: «%s»: %s", where, call, pr)
					}
				}
				if w.lit == "bash" {
					if _, ok := allowedShellCalls[call]; !ok {
						fail(t, "%s: вызов оболочки «%s» вне закрытого списка allowedShellCalls", where, call)
					} else if c.inRedir != "" {
						fail(t, "%s: вход оболочки перенаправлен «%s» — код через heredoc/here-string", where, c.inRedir)
					}
				}
			}
			// оболочка аргументом — в кавычках или без
			if w.lit != "bash" {
				for _, a := range args {
					if b := a.lit[strings.LastIndexByte(a.lit, '/')+1:]; !a.dyn && shells[b] {
						fail(t, "%s: оболочка «%s» аргументом в «%s» — код мимо лексера", where, a.raw, call)
					}
				}
			}
		}
	}
	if cmds == 0 {
		fatal(t, "не найдено ни одной команды — разбор пуст, тест ничего не проверил")
	}
	for key := range allowedDynPlaces {
		if placeUsed[key] != 1 {
			fail(t, "место allowedDynPlaces «%s» встречается %d раз вместо одного — запись устарела или место размножено",
				key, placeUsed[key])
		}
	}
	for n := range allowedPrograms {
		if seen[n] == 0 {
			fail(t, "программа «%s» из allowedPrograms больше не встречается — запись устарела, убери её", n)
		}
	}
	if len(seen) == 0 {
		fatal(t, "не встречено ни одной программы из списка — тест ничего не проверил")
	}
	if len(distinct) != wantPrograms {
		fail(t, "разных программ найдено %d, ожидалось %d — законно изменилось — поправь wantPrograms и allowedPrograms",
			len(distinct), wantPrograms)
	}
}

// scriptPaths — scripts/*.sh в порядке имён, с «/» на любой ОС.
func scriptPaths(t *testing.T) []string {
	t.Helper()
	scripts, err := filepath.Glob(filepath.Join("..", "..", "scripts", "*.sh"))
	if err != nil || len(scripts) == 0 {
		fatal(t, "не найдено ни одного scripts/*.sh (err=%v) — тест перестал что-либо проверять", err)
	}
	sort.Strings(scripts)
	for i := range scripts {
		scripts[i] = filepath.ToSlash(scripts[i])
	}
	return scripts
}
