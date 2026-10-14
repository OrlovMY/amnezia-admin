package guiview

import (
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
// `var uiDo = fyne.Do` в не-тестовом файле cmd/gui — и ни одного
// присваивания ей в боевом коде. Новая обёртка с другим именем сюда не
// входит и считается нарушением, пока не внесена видимой строкой диффа.
var doWrappers = []string{"uiDo"}

const guiDir = "../../cmd/gui"

// verifiedWrappers — какие обёртки из doWrappers проверены по боевому
// определению в files; problems — почему обёртка не признана.
func verifiedWrappers(files []*ast.File) (ok map[string]bool, problems []string) {
	ok = map[string]bool{}
	for _, name := range doWrappers {
		decls, good, assigns := 0, 0, 0
		for _, f := range files {
			ast.Inspect(f, func(n ast.Node) bool {
				switch x := n.(type) {
				case *ast.ValueSpec:
					for i, id := range x.Names {
						if id.Name != name {
							continue
						}
						decls++
						if i < len(x.Values) && isFyneDo(x.Values[i]) && x.Type == nil {
							good++
						}
					}
				case *ast.AssignStmt:
					for _, l := range x.Lhs {
						if id, isID := l.(*ast.Ident); isID && id.Name == name {
							assigns++
						}
					}
				}
				return true
			})
		}
		switch {
		case decls == 0:
			// обёртка не объявлена — и не признаётся
		case decls != 1 || good != 1:
			problems = append(problems, name+": боевое определение — не ровно `var "+name+" = fyne.Do`")
		case assigns != 0:
			problems = append(problems, name+": в боевом коде ей присваивают другое значение")
		default:
			ok[name] = true
		}
	}
	return ok, problems
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
		bad, good int
	}{
		// uiDo = fyne.Do — вызов через неё законен; uiCall — не в списке
		{"обёртка проверена", "var uiDo = fyne.Do\nvar uiCall = fyne.Do", 2, 2},
		// подмена (а): боевое uiDo — не fyne.Do; вызов через неё — нарушение
		{"обёртка подменена", "var uiDo = func(f func()) { f() }\nvar uiCall = fyne.Do", 3, 1},
	} {
		t.Run(c.name, func(t *testing.T) {
			bad, good := goSafeCanary(t, c.def)
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
func goSafeCanary(t *testing.T, def string) (bad, good int) {
	t.Helper()
	src := `package main
` + def + `
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
