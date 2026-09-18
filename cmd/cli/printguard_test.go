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
// ПРИЁМ ТОТ ЖЕ, ЧТО В core/stderrguard_test.go: перечисляем ДОПУСТИМОЕ.
// Кодирование в JSON внутри cmd/cli допускается ровно в одной функции —
// printConfig, — и ровно с одним аргументом: redactConfig(...). Правило
// намеренно шире предмета: оно ловит не «печать конфига», а всякое
// кодирование через encoding/json в пакете. Понадобится когда-нибудь
// законное второе — его придётся внести видимой строкой диффа, и это
// свойство, а не неудобство.
//
// Имя пакета берётся ИЗ ИМПОРТОВ ФАЙЛА, а не сравнивается с литералом
// "json": иначе `import js "encoding/json"` обходил сторож целиком (ревью
// SEC-01, Новое-1). Отдельными правилами запрещены точечный импорт
// encoding/json (делает вызовы безымянными) и любой сторонний пакет
// кодирования JSON (сторож знает только encoding/json).
//
// ГРАНИЦА СТОРОЖА — здесь, в коде, а не в отчёте. Сторож НЕ ВИДИТ:
//  1. печати конфига НЕ через encoding/json — fmt.Printf("%v", cfg),
//     fmt.Println(cfg), шаблон text/template, ручная склейка строк;
//  2. передачи cfg в другой пакет, который напечатает его сам;
//  3. кодирования через сторонний JSON-пакет — сам факт его импорта теперь
//     запрещён отдельной проверкой, но если пакет уже импортирован под
//     видом не-JSON имени пути, сторож его не узнает;
//  4. потока данных: он не проверяет, что в redactConfig пришёл именно тот
//     cfg, который собирались печатать;
//  5. КОДИРОВАНИЯ ЗА ПРЕДЕЛАМИ cmd/cli. Сторож сканирует только этот
//     каталог. Это граница сторожа, а не граница продукта.
//     ЧТО ЗДЕСЬ БЫЛО НАПИСАНО РАНЬШЕ И ПОЧЕМУ ПЕРЕПИСАНО (A2б): «вторая
//     точка печати, заведённая в cmd/gui, не будет поймана ничем». Это
//     больше не так: в cmd/gui заведён свой сторож —
//     cmd/gui/printguard_test.go. Он устроен ИНАЧЕ и намеренно: там
//     запрещено не кодирование (пакет законно кодирует ui.json), а
//     попадание серверного конфига и его ДЕРЖАТЕЛЕЙ (строка ключа
//     vpn://…, cfg, creds, путь через .Creds/.Password/.Key/поле сессии)
//     в вывод. Строка переписана, а не удалена, потому что утверждение о
//     том, чего сторож не ловит, опаснее умолчания: читатель, нашедший
//     здесь устаревшее «не поймает ничто», перестал бы искать сторож там,
//     где он есть.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// jsonImportPath — единственный допустимый в cmd/cli пакет кодирования JSON.
const jsonImportPath = "encoding/json"

// jsonNamesIn возвращает имена, под которыми в файле импортирован
// encoding/json (обычно одно — "json", но может быть алиас), и список
// нарушений импорта.
//
// Имя берётся ИЗ ИМПОРТОВ, а не сравнивается с литералом "json" (ревью
// SEC-01, Новое-1). Прежняя редакция ловила вызовы, у которых получатель
// записан буквально как json, и `import js "encoding/json"` её не задевал:
// пароль печатался открытым, набор оставался зелёным. Это прямо
// противоречило объявленной области «ловит ЛЮБОЕ JSON-кодирование в
// пакете», а расхождение между объявленной областью сторожа и настоящей
// опаснее узкой области, честно названной.
func jsonNamesIn(f *ast.File) (names map[string]bool, problems []string) {
	names = map[string]bool{}
	for _, imp := range f.Imports {
		path, err := strconv.Unquote(imp.Path.Value)
		if err != nil {
			problems = append(problems, "не разобран путь импорта "+imp.Path.Value)
			continue
		}
		local := ""
		if imp.Name != nil {
			local = imp.Name.Name
		}
		if path == jsonImportPath {
			switch local {
			case ".":
				// Точечный импорт делает вызовы безымянными (Marshal(...)),
				// и сторож их не разбирает. Запрещаем прямо, а не
				// умалчиваем.
				problems = append(problems, "точечный импорт "+jsonImportPath+
					" запрещён: сторож не разбирает безымянные вызовы Marshal/Encode")
			case "_":
				// Импорт ради побочного эффекта — вызовов нет.
			case "":
				names["json"] = true
			default:
				names[local] = true
			}
			continue
		}
		// Сторонний пакет кодирования JSON обошёл бы сторож целиком.
		if strings.Contains(strings.ToLower(path), "json") {
			problems = append(problems, "сторонний пакет кодирования JSON запрещён в cmd/cli: "+path+
				" — сторож знает только "+jsonImportPath)
		}
	}
	return names, problems
}

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
func collectJSONSites(t *testing.T, dir string) ([]jsonSite, []string) {
	t.Helper()
	var importProblems []string

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

		jsonNames, probs := jsonNamesIn(f)
		for _, p := range probs {
			importProblems = append(importProblems, name+": "+p)
		}

		ast.Inspect(f, func(n ast.Node) bool {
			fn, ok := n.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				return true
			}
			encoders := encoderVarsIn(fn, jsonNames)
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				expr, hasArg := jsonEncodeCall(call, encoders, jsonNames)
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
	return sites, importProblems
}

// encoderVarsIn собирает имена переменных, полученных из <json>.NewEncoder.
func encoderVarsIn(fn *ast.FuncDecl, jsonNames map[string]bool) map[string]bool {
	out := map[string]bool{}
	ast.Inspect(fn, func(n ast.Node) bool {
		as, ok := n.(*ast.AssignStmt)
		if !ok {
			return true
		}
		for i, v := range as.Rhs {
			if i >= len(as.Lhs) || !isPkgCall(v, jsonNames, "NewEncoder") {
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
func jsonEncodeCall(call *ast.CallExpr, encoders, jsonNames map[string]bool) (string, bool) {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return "", false
	}
	recv, ok := sel.X.(*ast.Ident)
	if !ok {
		return "", false
	}
	if jsonNames[recv.Name] {
		switch sel.Sel.Name {
		case "Marshal", "MarshalIndent":
			return recv.Name + "." + sel.Sel.Name, true
		case "NewEncoder":
			return recv.Name + ".NewEncoder", false
		}
		return "", false
	}
	if sel.Sel.Name == "Encode" && encoders[recv.Name] {
		return recv.Name + ".Encode", true
	}
	return "", false
}

func isPkgCall(e ast.Expr, pkgNames map[string]bool, fn string) bool {
	call, ok := e.(*ast.CallExpr)
	if !ok {
		return false
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != fn {
		return false
	}
	id, ok := sel.X.(*ast.Ident)
	return ok && pkgNames[id.Name]
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

	sites, importProblems := collectJSONSites(t, dir)

	for _, p := range importProblems {
		t.Errorf("нарушение правила импорта JSON в cmd/cli: %s", p)
	}

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

// TestJSONImportPolicy — две ветви правила импорта (ревью SEC-01, Новое-1).
//
// Здесь проверяется сама функция jsonNamesIn на входах, какими их увидел бы
// сторож на настоящем файле. Прежняя редакция этой шапки утверждала, что
// компилирующейся подмены для этих двух ветвей НЕ БЫВАЕТ, — утверждение
// снято как неверное (ревью SEC-01, V3): обе предъявляются сквозной
// подменой, и обе предъявлены.
//   - точечный импорт: подменяется САМ импорт, а не добавляется второй —
//     `"encoding/json"` → `. "encoding/json"` и `json.NewEncoder(w)` →
//     `NewEncoder(w)`. Собирается, сторож краснеет.
//   - сторонний пакет: новая зависимость не нужна, потому что правило
//     смотрит на подстроку «json» в ПУТИ, а путь может быть своим —
//     internal/jsonwire как обёртка над encoding/json. Собирается, сторож
//     краснеет.
//
// Эти подтесты оставлены рядом с ними: они проверяют ту же логику на всех
// формах импорта сразу и не требуют трогать main.go.
func TestJSONImportPolicy(t *testing.T) {
	parse := func(t *testing.T, src string) *ast.File {
		t.Helper()
		f, err := parser.ParseFile(token.NewFileSet(), "x.go", src, 0)
		if err != nil {
			t.Fatalf("разбор образца: %v", err)
		}
		return f
	}

	t.Run("алиас распознаётся как имя пакета json", func(t *testing.T) {
		names, probs := jsonNamesIn(parse(t, `package main
import js "encoding/json"
`))
		if !names["js"] {
			t.Errorf("алиас js не распознан: %v", names)
		}
		if names["json"] {
			t.Errorf("имя json не импортировано, но распознано: %v", names)
		}
		if len(probs) != 0 {
			t.Errorf("алиас — не нарушение: %v", probs)
		}
	})

	t.Run("точечный импорт encoding/json запрещён", func(t *testing.T) {
		_, probs := jsonNamesIn(parse(t, `package main
import . "encoding/json"
`))
		if len(probs) == 0 {
			t.Error("точечный импорт encoding/json не помечен нарушением — сторож не разбирает безымянные вызовы, и это обход")
		}
	})

	t.Run("сторонний пакет кодирования JSON запрещён", func(t *testing.T) {
		_, probs := jsonNamesIn(parse(t, `package main
import jsoniter "github.com/json-iterator/go"
`))
		if len(probs) == 0 {
			t.Error("сторонний пакет кодирования JSON не помечен нарушением — сторож знает только encoding/json")
		}
	})

	t.Run("обычные импорты нарушением не считаются", func(t *testing.T) {
		_, probs := jsonNamesIn(parse(t, `package main
import (
	"encoding/json"
	"fmt"
	"os"
)
`))
		if len(probs) != 0 {
			t.Errorf("ложное нарушение на обычных импортах: %v", probs)
		}
	})
}
