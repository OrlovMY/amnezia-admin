package guiview

import (
	"go/ast"
	"go/parser"
	"go/token"
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

// insideFyneDo — множество узлов, лежащих внутри вызова fyne.Do(...) в
// данном поддереве.
func insideFyneDo(root ast.Node) map[ast.Node]bool {
	safe := map[ast.Node]bool{}
	ast.Inspect(root, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
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
		safe := insideFyneDo(lit.Body)
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
	src := `package main
func f() {
	goSafe(func() {
		label.SetText("прямо из фоновой goroutine")
		fyne.Do(func() { label.SetText("а так можно") })
	})
}`
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "поддельный.go", src, 0)
	if err != nil {
		t.Fatalf("образец не разбирается: %v", err)
	}
	var bad, good int
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || len(call.Args) != 1 {
			return true
		}
		if id, ok := call.Fun.(*ast.Ident); !ok || id.Name != "goSafe" {
			return true
		}
		lit := call.Args[0].(*ast.FuncLit)
		safe := insideFyneDo(lit.Body)
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
	if bad != 1 {
		t.Errorf("сторож не увидел подложенного нарушения (насчитал %d) — он не сработает и на настоящем", bad)
	}
	if good != 1 {
		t.Errorf("сторож принял законный вызов внутри fyne.Do за нарушение (насчитал законных %d) — "+
			"такой сторож ослабят первой же правкой", good)
	}
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
