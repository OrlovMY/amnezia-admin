package main

// Структурный сторож на единственность точки печати конфига (A2, ревью
// SEC-01, замечание 1 — блокирующее).
//
// ЧТО ОН ЗАКРЫВАЕТ И ПОЧЕМУ ОН ВООБЩЕ ПОНАДОБИЛСЯ. Списки configAllowedKeys/
// configDeniedKeys охраняют ЗНАЧЕНИЯ на одном пути — через redactConfig.
// Через списки открыть password нельзя: запрещающий проверяется первым, и
// это предъявлено покраснением 2а. Но МИМО списков — можно: достаточно
// завести вторую точку печати, которая зовёт json.MarshalIndent(cfg)
// напрямую. Ревьюер это сделал на копии, и весь набор тестов остался
// ЗЕЛЁНЫМ, а пароль root печатался открытым.
//
// Асимметрия, которую это чинит: stderr (там PSK чужого клиента) охранялся
// назначенной точкой и AST-сторожем, а печать конфига (там пароль root либо
// приватный SSH-ключ владельца — секрет несравнимо дороже) охранялась только
// тем, что сегодня обе точки зовут printConfig. «Сегодня зовут» — это не
// защита, а совпадение.
//
// ПРИЁМ ТОТ ЖЕ, ЧТО В core/stderrguard_test.go: перечисляем ДОПУСТИМОЕ. Любое
// кодирование в JSON внутри cmd/cli допускается ровно в одной функции —
// printConfig, — и ровно с одним аргументом: redactConfig(...). Правило
// намеренно шире предмета: оно ловит не «печать конфига», а ЛЮБОЕ
// JSON-кодирование в пакете. Понадобится когда-нибудь законное второе —
// его придётся внести в allowedJSONFuncs видимой строкой диффа, и это
// свойство, а не неудобство.
//
// ГРАНИЦА СТОРОЖА — здесь, в коде, а не в отчёте.
// Сторож НЕ ВИДИТ:
//   - печати конфига не через encoding/json — fmt.Printf("%v", cfg),
//     fmt.Println(cfg), шаблон text/template, ручная склейка строк;
//   - передачи cfg в другой пакет, который напечатает его сам;
//   - кодирования через сторонний JSON-пакет;
//   - потока данных: он не проверяет, что в redactConfig пришёл именно тот
//     cfg, который собирались печатать.
//
// Он сканирует ТОЛЬКО каталог cmd/cli. Сегодня конфиг больше нигде не
// печатается, но это граница сторожа, а не граница продукта: точка печати,
// заведённая в другом пакете, им не ловится.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// printConfigFuncName — единственная функция, которой разрешено кодировать
// в JSON, и redactConfigFuncName — единственный допустимый аргумент.
const (
	printConfigFuncName  = "printConfig"
	redactConfigFuncName = "redactConfig"
)

// jsonSite — найденное место JSON-кодирования.
type jsonSite struct {
	fn       string // функция, в которой оно стоит
	file     string
	line     int
	expr     string // "json.MarshalIndent", "enc.Encode", …
	redacted bool   // аргумент — вызов redactConfig(...)
	hasArg   bool   // у вызова есть аргумент-значение (у NewEncoder его нет)
}

// collectJSONSites разбирает .go-файлы пакета (кроме _test.go) и собирает все
// места кодирования в JSON: json.Marshal, json.MarshalIndent, json.NewEncoder
// и вызовы .Encode на переменной, полученной из json.NewEncoder.
func collectJSONSites(t *testing.T, dir string) []jsonSite {
	t.Helper()

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("не удалось прочитать каталог пакета %q: %v — сторож перестал что-либо проверять", dir, err)
	}

	fset := token.NewFileSet()
	var sites []jsonSite
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
			encoders := encoderVarsIn(fn)
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				expr, hasArg := jsonEncodeCall(call, encoders)
				if expr == "" {
					return true
				}
				pos := fset.Position(call.Pos())
				sites = append(sites, jsonSite{
					fn:       fn.Name.Name,
					file:     filepath.Base(pos.Filename),
					line:     pos.Line,
					expr:     expr,
					redacted: hasArg && len(call.Args) > 0 && isCallTo(call.Args[0], redactConfigFuncName),
					hasArg:   hasArg,
				})
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

// encoderVarsIn собирает имена переменных, полученных из json.NewEncoder.
func encoderVarsIn(fn *ast.FuncDecl) map[string]bool {
	out := map[string]bool{}
	ast.Inspect(fn, func(n ast.Node) bool {
		as, ok := n.(*ast.AssignStmt)
		if !ok {
			return true
		}
		for i, v := range as.Rhs {
			if i >= len(as.Lhs) || !isPkgCall(v, "json", "NewEncoder") {
				continue
			}
			if id, ok := as.Lhs[i].(*ast.Ident); ok {
				out[id.Name] = true
			}
		}
		return true
	})
	return out
}

// jsonEncodeCall — вызов кодирования в JSON; возвращает его запись и признак
// «у вызова есть аргумент-значение».
func jsonEncodeCall(call *ast.CallExpr, encoders map[string]bool) (string, bool) {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return "", false
	}
	recv, ok := sel.X.(*ast.Ident)
	if !ok {
		return "", false
	}
	if recv.Name == "json" {
		switch sel.Sel.Name {
		case "Marshal", "MarshalIndent":
			return "json." + sel.Sel.Name, true
		case "NewEncoder":
			return "json.NewEncoder", false
		}
		return "", false
	}
	if sel.Sel.Name == "Encode" && encoders[recv.Name] {
		return recv.Name + ".Encode", true
	}
	return "", false
}

func isPkgCall(e ast.Expr, pkg, fn string) bool {
	call, ok := e.(*ast.CallExpr)
	if !ok {
		return false
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != fn {
		return false
	}
	id, ok := sel.X.(*ast.Ident)
	return ok && id.Name == pkg
}

func isCallTo(e ast.Expr, fn string) bool {
	call, ok := e.(*ast.CallExpr)
	if !ok {
		return false
	}
	id, ok := call.Fun.(*ast.Ident)
	return ok && id.Name == fn
}

// TestConfigPrintSinglePoint — все места JSON-кодирования в cmd/cli лежат в
// printConfig, и значение, которое там кодируется, проходит через
// redactConfig.
//
// Сторож падает словами «перестал что-либо проверять» на двух входах:
//  1. не найдено ни одного места кодирования вообще — образец исчез;
//  2. функция printConfig не найдена или единственное найденное место лежит
//     не в ней.
func TestConfigPrintSinglePoint(t *testing.T) {
	const dir = "."

	sites := collectJSONSites(t, dir)

	if len(sites) == 0 {
		t.Fatalf("в пакете cmd/cli не найдено ни одного места кодирования в JSON — "+
			"образец исчез, сверять нечего; сторож перестал что-либо проверять "+
			"(ожидались вызовы внутри %s)", printConfigFuncName)
	}

	inPrintConfig := 0
	for _, s := range sites {
		if s.fn == printConfigFuncName {
			inPrintConfig++
		}
	}
	if inPrintConfig == 0 {
		t.Fatalf("функция %s не найдена (или кодирование конфига переехало в %s:%d:%s) — "+
			"сторож перестал что-либо проверять",
			printConfigFuncName, sites[0].file, sites[0].line, sites[0].fn)
	}

	var redactedFound bool
	for _, s := range sites {
		if s.fn != printConfigFuncName {
			t.Errorf("кодирование конфига в JSON вне единственной точки печати: %s:%d, функция %s (%s). "+
				"Маскировка значений стоит только в %s → %s; здесь пароль root либо приватный "+
				"SSH-ключ владельца напечатается ОТКРЫТЫМ. Печатайте через %s, а не заводите "+
				"вторую точку печати.",
				s.file, s.line, s.fn, s.expr, printConfigFuncName, redactConfigFuncName, printConfigFuncName)
			continue
		}
		if s.hasArg && !s.redacted {
			t.Errorf("в %s (%s:%d, %s) кодируется значение, НЕ пропущенное через %s — "+
				"маскировка снята, и конфиг печатается как есть.",
				printConfigFuncName, s.file, s.line, s.expr, redactConfigFuncName)
		}
		if s.hasArg && s.redacted {
			redactedFound = true
		}
	}

	if !redactedFound {
		t.Errorf("в %s не найдено ни одного кодирования значения, пропущенного через %s — "+
			"проверять нечего", printConfigFuncName, redactConfigFuncName)
	}
}
