// Файл shparse_table_test.go — табличный тест лексера конвейеров в обе
// стороны (ревью QA-01 долгов CI, п.2). Точный счёт в
// TestNoEarlyExitPipeReader страхует только конструкции, которые уже стоят
// в файлах; эта таблица — те, которых там нет.
//
//   - «не конвейер» — страховка от ложно-красного;
//   - «конвейер» — страховка от ложно-чистого, главного риска.
//
// Строки взяты из таблицы п.1 РЕВЬЮ-ДОЛГИ-CI-QA.md. Канарейка
// (plant_test.go, подсадка tbl-wrong) добавляет строку с заведомо неверным
// ожиданием: вердикт таблицы обязан дойти до go test.
package ciguard

import (
	"strings"
	"testing"
)

type parseCase struct {
	src  string
	want string // первые слова читателей через пробел; "" — конвейера нет
}

var parseTable = []parseCase{
	// --- не конвейер ---
	{`a || b`, ""},
	{`v=${x//|/}`, ""},
	{`echo 'a|b'`, ""},
	{`echo "a|b"`, ""},
	{"cat <<'E'\na | grep -q b\nE", ""},
	{"cat <<-E\n\ta | grep -q b\n\tE", ""},
	{"# a | grep -q b", ""},
	{"echo x # a | grep -q b", ""},
	{`grep -q y <<< "$x"`, ""},
	{`v=$(grep -q y <<< "$x")`, ""},
	{"case $x in\na | b) echo ;;\nc) echo ;&\n*) : ;;\nesac", ""},
	{`[[ $x =~ ^(a|b)$ ]]`, ""},
	{`(( a | b ))`, ""},
	{`echo $(( a | b ))`, ""},
	{`echo "${{ a || b }}"`, ""},
	{`IFS='|' read -r a b <<< "$row"`, ""},
	// --- конвейер ---
	{`a | b`, "b"},
	{`a |& grep -q y`, "grep"},
	{"a |\n  grep -q y", "grep"},
	{"a | # c\n  grep -q y", "grep"},
	{"a \\\n  | grep -q y", "grep"},
	{`v="$(a | grep -q y)"`, "grep"},
	{`v=$(a | b)`, "b"},
	{"v=`a | b`", "b"},
	{`( a | b )`, "b"},
	{`{ a | b; }`, "b"},
	{"f() {\n  a | b\n}", "b"},
	{"case $x in\ny) a | b ;;\nesac", "b"},
	{`a=1; a | grep -q y`, "grep"},
	{`true && a | grep -q y`, "grep"},
	{`cat - <(a | b)`, "b"},
	{`a | b | c`, "b c"},
	{`a | (grep -q y)`, "("},
	{`a | { grep -q y; }`, "{"},
	{`a | while read -r v; do :; done`, "while"},
	{`a | LC_ALL=C grep -q y`, "LC_ALL=C"},
	{`a | \grep y`, "grep"},
}

func TestShellParserTable(t *testing.T) {
	rows := append([]parseCase{}, parseTable...)
	if p := activePlant(t); p != nil && p.parseRow != nil {
		rows = append(rows, *p.parseRow)
	}
	for _, c := range rows {
		p := parseShell(c.src)
		if len(p.errs) > 0 {
			fail(t, "таблица лексера: %q не разобрано: %v", c.src, p.errs)
			continue
		}
		var got []string
		for _, r := range p.readers {
			if len(r.words) > 0 {
				got = append(got, r.words[0].lit)
			}
		}
		if strings.Join(got, " ") != c.want {
			fail(t, "таблица лексера: %q — читатели «%s», ждали «%s»", c.src, strings.Join(got, " "), c.want)
		}
	}
	if len(rows) == 0 {
		fatal(t, "таблица лексера пуста — тест перестал что-либо проверять")
	}
}
