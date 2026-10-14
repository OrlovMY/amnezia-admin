package guiview

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Сторож: ВНУТРИ goSafe виджеты трогают только внутри fyne.Do.
//
// ЗАЧЕМ ОН ИМЕННО СЕЙЧАС. В cmd/gui появился счётчик фоновых операций
// (guiGoroutines), и тесты ждут по нему завершения goSafe. Это правильная
// точка синхронизации для ТЕСТА — но она же глушитель: если кто-то заведёт
// goSafe, который пишет в виджет МИМО fyne.Do, в бою появится настоящая
// гонка (боевой драйвер сериализует только то, что отдано через fyne.Do), а
// `-race` в тестах её не увидит, потому что ожидание уберёт параллельность.
// Сегодня все вызовы goSafe правило соблюдают; сторож делает это свойством,
// а не сегодняшним состоянием.
//
// ГРАНИЦЫ, признанные прямо:
//   - сверка ПО ИМЕНАМ методов, а не по типам: сторож не знает, что перед
//     ним виджет, и опознаёт обращение по имени метода из widgetMethods.
//     Вызов через переменную с другим именем метода он пропустит;
//   - он не заходит в функции, вызванные из goSafe: нарушение, спрятанное в
//     отдельный метод (u.updateLabel()), останется невидимым. Это цена
//     разбора одного тела, и она названа, а не умолчана;
//   - запуск горутины ВНУТРИ fyne.Do/uiDo — fyne.Do(func(){ go func(){
//     label.SetText(…) }() }) — не ловится: всё внутри аргумента fyne.Do
//     считается безопасным (как и до обёртки uiDo);
//   - обёртка uiDo признаётся по закрытому списку позиций имени в
//     не-тестовых файлах cmd/gui; тестовые файлы (шов serialUI) сторож не
//     читает. Подмена значения через рефлексию, unsafe или go:linkname — вне
//     синтаксического разбора и не ловится;
//   - он проверяет cmd/gui/main.go — единственный файл GUI. Появится второй
//     файл с goSafe, сторож про него не узнает (тогда правится путь здесь).

// widgetMethods — методы, которые МЕНЯЮТ состояние интерфейса. Перечень
// поимённый: новый метод в этом ряду вносится сюда видимой строкой диффа.
var widgetMethods = map[string]bool{
	"SetText":          true,
	"SetContent":       true,
	"Show":             true,
	"Hide":             true,
	"Enable":           true,
	"Disable":          true,
	"Refresh":          true,
	"SetColumnWidth":   true,
	"ScrollToTop":      true,
	"UnselectAll":      true,
	"SetSelectedIndex": true,
	"SetChecked":       true,
	"SetPlaceHolder":   true,
	"Focus":            true,
}

// doWrappers — ЗАКРЫТЫЙ список обёрток, равных fyne.Do (одна запись).
// uiDo — шов теста диалога пина (аудит р2 H1 по PR #57). Обёртка признаётся,
// только если сторож САМ увидел её боевое определение — ровно
// `var uiDo = fyne.Do` в не-тестовом файле cmd/gui — и имя нигде больше
// не стоит, кроме вызова uiDo(…) (закрытый список позиций,
// verifiedWrappers). Новая обёртка с другим именем сюда не
// входит и считается нарушением, пока не внесена видимой строкой диффа.
var doWrappers = []string{"uiDo"}

const guiDir = "../../cmd/gui"

// verifiedWrappers — какие обёртки из doWrappers признаны в files;
// problems — почему обёртка не признана.
//
// ЗАКРЫТЫЙ СПИСОК ПОЗИЦИЙ (аудит р6 по PR #57: перечислять обходы —
// присваивание, &, скобки, range, затенение… — бесконечно, поэтому
// перечисляется разрешённое). Идентификатор с именем обёртки — любой
// *ast.Ident, независимо от области видимости — допустим ровно в двух
// позициях:
//
//	(1) имя в ЕДИНСТВЕННОМ объявлении уровня пакета `var uiDo = fyne.Do`:
//	    одно имя, без типа, одно значение — ровно селектор fyne.Do, и файл
//	    импортирует fyne.io/fyne/v2 под именем fyne;
//	(2) непосредственно Fun у вызова: uiDo(…), не (uiDo)(…).
//
// Любое иное появление — обёртка не признана.
func verifiedWrappers(files []*ast.File) (ok map[string]bool, problems []string) {
	ok = map[string]bool{}
	for _, name := range doWrappers {
		defs, other := 0, 0
		for _, f := range files {
			var stack []ast.Node
			ast.Inspect(f, func(n ast.Node) bool {
				if n == nil {
					stack = stack[:len(stack)-1]
					return true
				}
				if id, isID := n.(*ast.Ident); isID && id.Name == name {
					switch {
					case isWrapperDef(f, stack, id):
						defs++
					case isCallFun(stack, id):
					default:
						other++
					}
				}
				stack = append(stack, n)
				return true
			})
		}
		switch {
		case defs == 0 && other == 0:
			// обёртки нет — и не признаётся
		case defs != 1:
			problems = append(problems, fmt.Sprintf("%s: объявлений `var %s = fyne.Do` уровня пакета — %d, а не одно", name, name, defs))
		case other != 0:
			problems = append(problems, fmt.Sprintf("%s: имя стоит вне разрешённых позиций (%d раз): только объявление и вызов %s(…)", name, other, name))
		default:
			ok[name] = true
		}
	}
	return ok, problems
}

// isWrapperDef — позиция (1): stack — предки id (последний — родитель).
func isWrapperDef(f *ast.File, stack []ast.Node, id *ast.Ident) bool {
	if len(stack) < 3 {
		return false
	}
	spec, ok := stack[len(stack)-1].(*ast.ValueSpec)
	if !ok || len(spec.Names) != 1 || spec.Names[0] != id || spec.Type != nil || len(spec.Values) != 1 {
		return false
	}
	gd, ok := stack[len(stack)-2].(*ast.GenDecl)
	if !ok || gd.Tok != token.VAR {
		return false
	}
	if _, top := stack[len(stack)-3].(*ast.File); !top {
		return false
	}
	return isFyneDo(spec.Values[0]) && importsFyne(f)
}

// isCallFun — позиция (2): id — непосредственно Fun у вызова.
func isCallFun(stack []ast.Node, id *ast.Ident) bool {
	if len(stack) == 0 {
		return false
	}
	call, ok := stack[len(stack)-1].(*ast.CallExpr)
	return ok && call.Fun == ast.Expr(id)
}

func importsFyne(f *ast.File) bool {
	for _, im := range f.Imports {
		if im.Path.Value == `"fyne.io/fyne/v2"` && (im.Name == nil || im.Name.Name == "fyne") {
			return true
		}
	}
	return false
}

func isFyneDo(e ast.Expr) bool {
	sel, ok := e.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Do" {
		return false
	}
	pkg, ok := sel.X.(*ast.Ident)
	return ok && pkg.Name == "fyne"
}

// guiProdFiles — не-тестовые .go файлы cmd/gui.
func guiProdFiles(t *testing.T) []*ast.File {
	t.Helper()
	names, err := filepath.Glob(filepath.Join(guiDir, "*.go"))
	if err != nil || len(names) == 0 {
		t.Fatalf("сторож ПЕРЕСТАЛ ЧТО-ЛИБО ПРОВЕРЯТЬ: нет .go в %s (%v)", guiDir, err)
	}
	var files []*ast.File
	fset := token.NewFileSet()
	for _, n := range names {
		if strings.HasSuffix(n, "_test.go") {
			continue
		}
		raw, err := os.ReadFile(n)
		if err != nil {
			t.Fatal(err)
		}
		f, err := parser.ParseFile(fset, n, raw, 0)
		if err != nil {
			t.Fatalf("сторож ПЕРЕСТАЛ ЧТО-ЛИБО ПРОВЕРЯТЬ: %s не разбирается: %v", n, err)
		}
		files = append(files, f)
	}
	return files
}

// insideFyneDo — множество узлов, лежащих внутри вызова fyne.Do(...) или
// проверенной обёртки (wrappers) в данном поддереве.
func insideFyneDo(root ast.Node, wrappers map[string]bool) map[ast.Node]bool {
	safe := map[ast.Node]bool{}
	ast.Inspect(root, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if id, isID := call.Fun.(*ast.Ident); isID && wrappers[id.Name] {
			for _, arg := range call.Args {
				ast.Inspect(arg, func(m ast.Node) bool {
					safe[m] = true
					return true
				})
			}
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "Do" && sel.Sel.Name != "DoAndWait" {
			return true
		}
		pkg, ok := sel.X.(*ast.Ident)
		if !ok || pkg.Name != "fyne" {
			return true
		}
		for _, arg := range call.Args {
			ast.Inspect(arg, func(m ast.Node) bool {
				safe[m] = true
				return true
			})
		}
		return true
	})
	return safe
}

// TestGoSafeTouchesWidgetsOnlyInsideFyneDo — в теле каждого goSafe(func(){…})
// вызовы методов из widgetMethods стоят только внутри fyne.Do.
func TestGoSafeTouchesWidgetsOnlyInsideFyneDo(t *testing.T) {
	raw, _, _ := readGUIMain(t)
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, guiMainPath, raw, 0)
	if err != nil {
		t.Fatalf("сторож ПЕРЕСТАЛ ЧТО-ЛИБО ПРОВЕРЯТЬ: %s не разбирается: %v", guiMainPath, err)
	}

	wrappers, problems := verifiedWrappers(guiProdFiles(t))
	for _, p := range problems {
		t.Errorf("обёртка fyne.Do не признана: %s — вызовы через неё считаются нарушением", p)
	}
	checked := 0
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || len(call.Args) != 1 {
			return true
		}
		id, ok := call.Fun.(*ast.Ident)
		if !ok || id.Name != "goSafe" {
			return true
		}
		lit, ok := call.Args[0].(*ast.FuncLit)
		if !ok {
			return true
		}
		checked++
		safe := insideFyneDo(lit.Body, wrappers)
		ast.Inspect(lit.Body, func(m ast.Node) bool {
			inner, ok := m.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := inner.Fun.(*ast.SelectorExpr)
			if !ok || !widgetMethods[sel.Sel.Name] {
				return true
			}
			if safe[inner] {
				return true
			}
			t.Errorf("%s:%d: в теле goSafe вызван %s(...) МИМО fyne.Do — запись в интерфейс из "+
				"фоновой goroutine. Боевой драйвер сериализует только то, что отдано через "+
				"fyne.Do, значит это настоящая гонка; а ожидание goSafe в тестах спрячет её "+
				"от -race. Оберните вызов в fyne.Do",
				guiMainPath, fset.Position(inner.Pos()).Line, sel.Sel.Name)
			return true
		})
		return true
	})

	if checked == 0 {
		t.Fatalf("сторож ПЕРЕСТАЛ ЧТО-ЛИБО ПРОВЕРЯТЬ: в %s не найдено ни одного goSafe(func(){…}) — "+
			"либо фоновые операции запускают иначе, либо изменилась форма записи", guiMainPath)
	}
	t.Logf("проверено вызовов goSafe: %d", checked)
}

// TestGoSafeGuardSeesViolation — КАНАРЕЙКА САМОГО СТОРОЖА: на подложенном
// нарушении он обязан сработать. Иначе «сторож зелёный» значило бы только,
// что он ничего не смотрит.
func TestGoSafeGuardSeesViolation(t *testing.T) {
	for _, c := range []struct {
		name      string
		def       string
		imp       bool // импорт fyne.io/fyne/v2
		bad, good int
	}{
		{"законная обёртка", "var uiDo = fyne.Do\n", true, 2, 2},
		{"поддельное определение", "var uiDo = func(f func()) { f() }\n", true, 3, 1},
		{"второе определение", "var uiDo = fyne.Do\nvar uiDo = fyne.Do\n", true, 3, 1},
		{"типизированное определение", "var uiDo func(func()) = fyne.Do\n", true, 3, 1},
		{"без импорта fyne", "var uiDo = fyne.Do\n", false, 3, 1},
		{"присваивание в init", "var uiDo = fyne.Do\nfunc init() { uiDo = func(f func()) { f() } }\n", true, 3, 1},
		{"присваивание в скобках", "var uiDo = fyne.Do\nfunc init() { (uiDo) = func(f func()) { f() } }\n", true, 3, 1},
		{"взят адрес", "var uiDo = fyne.Do\nfunc init() { p := &uiDo; *p = func(f func()) { f() } }\n", true, 3, 1},
		{"взят адрес в скобках", "var uiDo = fyne.Do\nfunc init() { p := &(uiDo); *p = func(f func()) { f() } }\n", true, 3, 1},
		{"for range присваивание", "var uiDo = fyne.Do\nfunc init() { var xs []func(func()); for _, uiDo = range xs {} }\n", true, 3, 1},
		{"параметр", "var uiDo = fyne.Do\nfunc g(uiDo func(func())) {}\n", true, 3, 1},
		{"именованный результат", "var uiDo = fyne.Do\nfunc g() (uiDo func(func())) { return }\n", true, 3, 1},
		{"for :=", "var uiDo = fyne.Do\nfunc init() { for _, uiDo := range []int{} { _ = uiDo } }\n", true, 3, 1},
		{"локальный var", "var uiDo = fyne.Do\nfunc init() { var uiDo = 1; _ = uiDo }\n", true, 3, 1},
		{"вызов в скобках", "var uiDo = fyne.Do\nfunc init() { (uiDo)(func() {}) }\n", true, 3, 1},
	} {
		t.Run(c.name, func(t *testing.T) {
			bad, good := goSafeCanary(t, c.def, c.imp)
			if bad != c.bad || good != c.good {
				t.Errorf("сторож насчитал нарушений %d, законных %d; ждали %d и %d — он не сработает и на настоящем",
					bad, good, c.bad, c.good)
			}
		})
	}
}

// goSafeCanary — сторож на подложенном файле: прямой SetText (нарушение),
// SetText в fyne.Do (законно), в uiDo (законно, если обёртка проверена),
// в незнакомой обёртке uiCall (нарушение всегда).
func goSafeCanary(t *testing.T, def string, imp bool) (bad, good int) {
	t.Helper()
	head := "package main\n"
	if imp {
		head += "import \"fyne.io/fyne/v2\"\n"
	}
	src := head + def + `var uiCall = fyne.Do
func f() {
	goSafe(func() {
		label.SetText("прямо из фоновой goroutine")
		fyne.Do(func() { label.SetText("а так можно") })
		uiDo(func() { label.SetText("через проверенную обёртку") })
		uiCall(func() { label.SetText("через обёртку вне списка") })
	})
}`
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "поддельный.go", src, 0)
	if err != nil {
		t.Fatalf("образец не разбирается: %v", err)
	}
	wrappers, _ := verifiedWrappers([]*ast.File{file})
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || len(call.Args) != 1 {
			return true
		}
		if id, ok := call.Fun.(*ast.Ident); !ok || id.Name != "goSafe" {
			return true
		}
		lit := call.Args[0].(*ast.FuncLit)
		safe := insideFyneDo(lit.Body, wrappers)
		ast.Inspect(lit.Body, func(m ast.Node) bool {
			inner, ok := m.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := inner.Fun.(*ast.SelectorExpr)
			if !ok || !widgetMethods[sel.Sel.Name] {
				return true
			}
			if safe[inner] {
				good++
			} else {
				bad++
			}
			return true
		})
		return true
	})
	return bad, good
}

// TestGoSafeGuardNamesTheDrivers — пояснение у счётчика фоновых операций
// ссылается на ОБА файла драйверов Fyne, а не утверждает про гонку в
// продукте. Замечание QA-01: прежняя редакция комментария говорила, что
// `-race` показывает гонку между фоновой перерисовкой и чтением виджетов, —
// и следующий читатель решал бы, что в продукте есть дефект, прикрытый
// WaitGroup. Это проверяемое утверждение, поэтому оно проверяется.
func TestGoSafeGuardNamesTheDrivers(t *testing.T) {
	raw, _, _ := readGUIMain(t)
	text := string(raw)
	i := strings.Index(text, "var guiGoroutines")
	if i < 0 {
		t.Fatalf("сторож ПЕРЕСТАЛ ЧТО-ЛИБО ПРОВЕРЯТЬ: в %s нет guiGoroutines", guiMainPath)
	}
	head := text[max0(i-3000):i]
	for _, want := range []string{
		"internal/driver/glfw/driver.go",
		"test/driver.go",
	} {
		if !strings.Contains(head, want) {
			t.Errorf("пояснение к guiGoroutines не ссылается на %s — утверждение «гонка есть только "+
				"в тестовом драйвере» остаётся непроверяемым на слово", want)
		}
	}
}

func max0(i int) int {
	if i < 0 {
		return 0
	}
	return i
}
