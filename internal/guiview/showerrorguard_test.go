package guiview

// Сторож A3б PR-3 (рекомендация QA-01, раунд 2): в cmd/gui прямой вызов
// dialog.ShowError разрешён только внутри (u *ui).showError и в ЗАКРЫТОМ
// списке исключений с обоснованием. Зачем: новый путь записи, вызвавший
// dialog.ShowError напрямую, покажет исход записи безликим диалогом Fyne —
// без «что делать» и с неверной доступностью повтора, — и ни один тест
// этого не заметит (TestPR3GUIApplyOutcomes смотрит только окно изменений).
//
// Граница: сторож синтаксический — он видит вызов dialog.ShowError по имени
// пакета «dialog». Вызов через псевдоним импорта или обёртку он не увидит;
// обёртка вне showError — та же находка ревью, что и прямой вызов.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// showErrorHome — функция, внутри которой прямой вызов — норма.
const showErrorHome = "showError"

// showErrorExceptions — закрытый список: функция → обоснование. Каждое
// исключение обязано встретиться (неиспользованное — тоже находка:
// список не должен обрастать мёртвыми строками).
var showErrorExceptions = map[string]string{
	"regenerateSelected": "отказ ДО записи (core.EnabledUnknownError: включён ли клиент, неизвестно) — не исход записи на сервер, текст ядра полон сам по себе",
}

// findShowError — функции, в которых стоит прямой вызов dialog.ShowError, по
// одному вхождению на вызов.
func findShowError(fset *token.FileSet, f *ast.File) []string {
	var found []string
	for _, d := range f.Decls {
		fd, ok := d.(*ast.FuncDecl)
		if !ok || fd.Body == nil {
			continue
		}
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "ShowError" {
				return true
			}
			if id, ok := sel.X.(*ast.Ident); ok && id.Name == "dialog" {
				found = append(found, fd.Name.Name)
			}
			return true
		})
	}
	return found
}

// TestShowErrorOnlyInShowError — сторож по настоящему cmd/gui.
func TestShowErrorOnlyInShowError(t *testing.T) {
	files, err := filepath.Glob(filepath.Join(guiPkgFiles, "*.go"))
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	parsed := 0
	count := map[string]int{}
	for _, p := range files {
		if strings.HasSuffix(p, "_test.go") {
			continue
		}
		src, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		f, err := parser.ParseFile(fset, p, src, 0)
		if err != nil {
			t.Fatalf("разбор %s: %v", p, err)
		}
		parsed++
		for _, fn := range findShowError(fset, f) {
			count[fn]++
		}
	}
	// Канарейка: пустой разбор — не «нарушений нет». Внутри showError вызов
	// есть всегда (прочие ошибки); не нашли его — сторож ослеп.
	if parsed == 0 || count[showErrorHome] != 1 {
		t.Fatalf("проверка ПЕРЕСТАЛА ЧТО-ЛИБО ЗНАЧИТЬ: разобрано файлов %d, вызовов в %s %d (ожидался ровно 1)",
			parsed, showErrorHome, count[showErrorHome])
	}
	// Второй, независимый сторож (выборка немоты): общее число прямых вызовов
	// — ровно showError плюс по одному на исключение.
	total := 0
	for _, n := range count {
		total += n
	}
	if want := 1 + len(showErrorExceptions); total != want {
		t.Errorf("прямых dialog.ShowError в cmd/gui %d, допустимо ровно %d (showError + исключения): %v", total, want, count)
	}
	var bad []string
	for fn, n := range count {
		if fn == showErrorHome {
			continue
		}
		if _, ok := showErrorExceptions[fn]; !ok {
			bad = append(bad, fn)
			continue
		}
		if n != 1 {
			t.Errorf("исключение %s: вызовов %d, в списке обосновано ровно одно", fn, n)
		}
	}
	sort.Strings(bad)
	for _, fn := range bad {
		t.Errorf("прямой dialog.ShowError в %s — исход записи был бы показан безликим диалогом; используйте u.showError(err) "+
			"или внесите исключение в showErrorExceptions с обоснованием", fn)
	}
	for fn := range showErrorExceptions {
		if count[fn] == 0 {
			t.Errorf("исключение %s в списке, а вызова нет — строку убрать", fn)
		}
	}
}

// TestShowErrorGuardCatchesPlanted — подсадка: новый прямой вызов в новой
// функции и в существующем пути записи — находится.
func TestShowErrorGuardCatchesPlanted(t *testing.T) {
	const src = `package main
func (u *ui) showError(err error) { dialog.ShowError(err, u.win) }
func (u *ui) addDialog() { if err != nil { dialog.ShowError(err, u.win) } }
func (u *ui) newWritePath() { go func() { dialog.ShowError(err, u.win) }() }
func (u *ui) fine() { u.showError(err); other.ShowError(err) }
`
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "planted.go", src, 0)
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join(findShowError(fset, f), ",")
	if want := "showError,addDialog,newWritePath"; got != want {
		t.Fatalf("подсадка: найдено %q, ожидалось %q", got, want)
	}
}
