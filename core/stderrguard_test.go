package core

// Структурный сторож (A2, Г4(б)): захват вывода сервера, попадающий в текст
// ошибки, обязан быть ровно в ОДНОМ месте пакета core — в назначенной точке
// core/runner.go, где стоит маскировка. Любое второе такое место — обход
// маскировки, который тест на звенья пропустит: он проводит по цепочке одну
// конкретную ошибку, а не все, какие в пакете бывают.
//
// Приём тот же, что сработал в A5 трижды: перечисляем ДОПУСТИМОЕ (одно
// место), а не пытаемся описать все недопустимые.
//
// ГРАНИЦА СТОРОЖА — здесь, в коде, а не в отчёте, потому что завышенное
// достижение опаснее скромного: читатель, уверенный, что сторож ловит всё,
// перестанет искать обход.
//
// Он ловит один конкретный вид: вызов .String() на переменной, объявленной
// В ТОЙ ЖЕ ФУНКЦИИ как bytes.Buffer или strings.Builder, в аргументах
// fmt.Errorf. Всё остальное он пропускает. Поимённо, а не общей фразой
// (ревью SEC-01, замечание 5):
//   - ЗАХВАТ ЧЕРЕЗ ПРОМЕЖУТОЧНУЮ ПЕРЕМЕННУЮ: s := errb.String(), затем
//     fmt.Errorf("…: %s", s). Поток данных сторож не разбирает.
//   - ЗАХВАТ ЧЕРЕЗ МЕТОД СВОЕГО ТИПА: func (r *runner) stderr() string
//     { return r.errb.String() }, затем fmt.Errorf("…: %s", r.stderr()).
//     Вызов .String() при этом стоит не в аргументах fmt.Errorf, а в чужом
//     теле, и сторожем не связывается с ним.
//   - БУФЕР КАК ПОЛЕ СТРУКТУРЫ: fmt.Errorf("…: %s", r.errb.String()).
//     Получатель .String() — не идентификатор, а селектор, и объявления
//     r.errb в теле функции нет; сторож такую пару не узнаёт.
//   - ОБЫЧНАЯ СТРОКОВАЯ ПЕРЕМЕННАЯ, в которую stderr доехал через три
//     присваивания: от любой другой строки сторож её не отличит.
//
// СТОРОЖ СКАНИРУЕТ ТОЛЬКО КАТАЛОГ core. Сегодня захвата вывода сервера в
// других пакетах нет — проверено, — но это ГРАНИЦА СТОРОЖА, А НЕ ГРАНИЦА
// ПРОДУКТА: точка захвата, заведённая в cmd/ или internal/, им не ловится.
//
// Сторож проверяет ДВЕ вещи, а не одну: что мест захвата ровно одно и что оно
// в назначенной точке, И что захват там обёрнут в maskFreeText. Без второй
// проверки снятие маскировки оставило бы сторож зелёным — место захвата от
// этого не двигается.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// designatedPointFile — назначенная точка маскировки (Г2). Путь относительно
// каталога пакета core; в сообщениях называется как core/runner.go.
const designatedPointFile = "runner.go"

// captureSite — найденное место захвата вывода в аргументах fmt.Errorf.
type captureSite struct {
	file   string // имя файла относительно каталога пакета
	line   int
	expr   string // например "errb.String()"
	masked bool   // захват обёрнут в maskFreeText(...)
}

// maskFuncName — функция маскировки свободного текста, которой обязан быть
// обёрнут захват в назначенной точке. Без этой проверки сторож зеленел бы на
// снятой маскировке: место захвата остаётся там же, где было.
const maskFuncName = "maskFreeText"

// captureBufferTypes — типы, которые считаются буфером захвата вывода.
var captureBufferTypes = map[string]bool{
	"bytes.Buffer":    true,
	"strings.Builder": true,
}

// collectCaptureSites разбирает все .go-файлы пакета core (кроме _test.go) и
// собирает места, где вызов .String() на буфере захвата вывода попадает в
// аргументы fmt.Errorf.
func collectCaptureSites(t *testing.T, dir string) []captureSite {
	t.Helper()

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("не удалось прочитать каталог пакета %q: %v — сторож перестал что-либо проверять", dir, err)
	}

	fset := token.NewFileSet()
	var sites []captureSite
	scanned := 0

	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(dir, name), nil, 0)
		if err != nil {
			t.Fatalf("не удалось разобрать %s: %v — сторож перестал что-либо проверять", name, err)
		}
		scanned++

		ast.Inspect(f, func(n ast.Node) bool {
			fn, ok := n.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				return true
			}
			buffers := captureBuffersIn(fn)
			if len(buffers) == 0 {
				return true
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok || !isFmtErrorf(call.Fun) {
					return true
				}
				for _, arg := range call.Args {
					findCaptures(arg, buffers, false, fset, &sites)
				}
				return true
			})
			return true
		})
	}

	if scanned == 0 {
		t.Fatalf("в %q не разобрано ни одного не-тестового .go-файла — сторож перестал что-либо проверять", dir)
	}
	return sites
}

// findCaptures рекурсивно ищет в выражении вызовы <буфер>.String(), помечая
// найденные признаком «обёрнут в maskFreeText». Флаг masked наследуется вниз:
// maskFreeText(errb.String()) даёт masked=true, errb.String() без обёртки —
// masked=false.
func findCaptures(e ast.Expr, buffers map[string]bool, masked bool, fset *token.FileSet, sites *[]captureSite) {
	call, ok := e.(*ast.CallExpr)
	if ok {
		if id, isIdent := call.Fun.(*ast.Ident); isIdent && id.Name == maskFuncName {
			for _, a := range call.Args {
				findCaptures(a, buffers, true, fset, sites)
			}
			return
		}
		if recv, isStr := bufferStringCall(call, buffers); isStr {
			pos := fset.Position(call.Pos())
			*sites = append(*sites, captureSite{
				file:   filepath.Base(pos.Filename),
				line:   pos.Line,
				expr:   recv + ".String()",
				masked: masked,
			})
			return
		}
	}
	// Прочие выражения — обходим дочерние узлы, сохраняя флаг.
	ast.Inspect(e, func(n ast.Node) bool {
		child, isCall := n.(*ast.CallExpr)
		if !isCall || child == e {
			return true
		}
		findCaptures(child, buffers, masked, fset, sites)
		return false
	})
}

// captureBuffersIn собирает имена переменных функции, объявленных как буфер
// захвата вывода: "var out, errb bytes.Buffer", "b := bytes.Buffer{}",
// "b := new(strings.Builder)", "var b = &bytes.Buffer{}".
func captureBuffersIn(fn *ast.FuncDecl) map[string]bool {
	out := map[string]bool{}
	ast.Inspect(fn, func(n ast.Node) bool {
		switch d := n.(type) {
		case *ast.ValueSpec:
			if typeName(d.Type) != "" && captureBufferTypes[typeName(d.Type)] {
				for _, id := range d.Names {
					out[id.Name] = true
				}
			}
			for i, v := range d.Values {
				if i < len(d.Names) && isCaptureBufferValue(v) {
					out[d.Names[i].Name] = true
				}
			}
		case *ast.AssignStmt:
			for i, v := range d.Rhs {
				if i >= len(d.Lhs) || !isCaptureBufferValue(v) {
					continue
				}
				if id, ok := d.Lhs[i].(*ast.Ident); ok {
					out[id.Name] = true
				}
			}
		}
		return true
	})
	return out
}

// isCaptureBufferValue — выражение вида bytes.Buffer{}, &bytes.Buffer{},
// new(bytes.Buffer) (и то же для strings.Builder).
func isCaptureBufferValue(v ast.Expr) bool {
	switch e := v.(type) {
	case *ast.UnaryExpr:
		if e.Op == token.AND {
			return isCaptureBufferValue(e.X)
		}
	case *ast.CompositeLit:
		return captureBufferTypes[typeName(e.Type)]
	case *ast.CallExpr:
		if id, ok := e.Fun.(*ast.Ident); ok && id.Name == "new" && len(e.Args) == 1 {
			return captureBufferTypes[typeName(e.Args[0])]
		}
	}
	return false
}

// bufferStringCall — вызов вида <буфер>.String(); возвращает имя буфера.
func bufferStringCall(call *ast.CallExpr, buffers map[string]bool) (string, bool) {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "String" || len(call.Args) != 0 {
		return "", false
	}
	id, ok := sel.X.(*ast.Ident)
	if !ok || !buffers[id.Name] {
		return "", false
	}
	return id.Name, true
}

func isFmtErrorf(fun ast.Expr) bool {
	sel, ok := fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Errorf" {
		return false
	}
	pkg, ok := sel.X.(*ast.Ident)
	return ok && pkg.Name == "fmt"
}

func typeName(e ast.Expr) string {
	sel, ok := e.(*ast.SelectorExpr)
	if !ok {
		return ""
	}
	pkg, ok := sel.X.(*ast.Ident)
	if !ok {
		return ""
	}
	return pkg.Name + "." + sel.Sel.Name
}

// TestStderrCaptureSinglePoint — множество мест захвата вывода в аргументах
// fmt.Errorf по пакету core равно ровно одному, и это назначенная точка
// core/runner.go.
//
// Сторож падает словами «перестал что-либо проверять» на ДВУХ входах:
//  1. не найдено ни одного места захвата вообще — образец исчез, сверять
//     нечего (покраснение 8);
//  2. файл назначенной точки не найден или единственное найденное место
//     лежит не в нём — переименование файла или перенос функции в другой
//     пакет (покраснение 8а). Этот вход вероятнее первого.
func TestStderrCaptureSinglePoint(t *testing.T) {
	const dir = "."

	if _, err := os.Stat(filepath.Join(dir, designatedPointFile)); err != nil {
		t.Fatalf("назначенная точка core/%s не найдена (%v) — сторож перестал что-либо проверять",
			designatedPointFile, err)
	}

	sites := collectCaptureSites(t, dir)

	if len(sites) == 0 {
		t.Fatalf("не найдено ни одного места захвата вывода сервера в fmt.Errorf во всём пакете core — "+
			"образец исчез, сверять нечего; сторож перестал что-либо проверять "+
			"(ожидалась ровно одна такая точка в core/%s)", designatedPointFile)
	}

	if len(sites) == 1 && sites[0].file != designatedPointFile {
		t.Fatalf("назначенная точка core/%s не найдена (или захват переехал в %s:%d) — "+
			"сторож перестал что-либо проверять",
			designatedPointFile, sites[0].file, sites[0].line)
	}

	for _, s := range sites {
		if s.file == designatedPointFile && !s.masked {
			t.Errorf("захват вывода сервера в назначенной точке core/%s:%d (%s) НЕ обёрнут в %s — "+
				"маскировка снята, и весь stderr сервера уходит в текст ошибки открытым. "+
				"Именно ради этого назначенная точка и назначена.",
				s.file, s.line, s.expr, maskFuncName)
		}
		if s.file != designatedPointFile {
			t.Errorf("захват вывода сервера в fmt.Errorf вне назначенной точки: core/%s:%d (%s). "+
				"Маскировка stderr стоит только в core/%s — здесь секрет уйдёт в текст ошибки "+
				"без маскировки. Либо проводите ошибку через назначенную точку, либо переносите "+
				"маскировку туда решением ядра, а не на месте.",
				s.file, s.line, s.expr, designatedPointFile)
		}
	}

	if len(sites) > 1 {
		t.Errorf("мест захвата вывода сервера в fmt.Errorf: %d, допускается ровно одно (core/%s). "+
			"Найдено: %s", len(sites), designatedPointFile, formatSites(sites))
	}
}

func formatSites(sites []captureSite) string {
	parts := make([]string, 0, len(sites))
	for _, s := range sites {
		parts = append(parts, s.file+":"+itoa(s.line)+" ("+s.expr+")")
	}
	return strings.Join(parts, ", ")
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
