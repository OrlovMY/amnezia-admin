package guiview

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// Сторож признака 2 правила П-НЕЗНАНИЕ — ОТБРОШЕННОЙ ОШИБКИ — в cmd/gui
// (задание A1, Г5).
//
// ЗАЧЕМ. Признак 2 («значение по умолчанию вместо ответа»: ошибка отброшена,
// переменная осталась нулевой, и ноль ушёл к человеку как измеренная
// величина) — единственный из четырёх, распознаваемый по AST. Место № 2
// этого PR было ровно им: `if s, statErr := u.sess.GetPeerStats(cur);
// statErr == nil { stats = s }` без ветви на ошибку. Правка без сторожа
// устаревает с первым же коммитом — довод не новый, он из A2б.
//
// ОХВАТ — cmd/gui, И ТОЛЬКО ОН. core в охват НЕ входит, хотя PR правит и его:
// PR правит в core ОДНУ функцию, а сторож накрыл бы пакет целиком —
// транзакции, хранилище, работу с сервером — и превратил бы закрытый
// перечень мест в сплошную проверку. Сплошная сверка — предмет A1б.
//
// КРИТЕРИЙ ЗАВЕДЕНИЯ И ЕГО ПРОГОН (Г5). Сторож не заводится, если перечень
// исключений оказывается длиннее перечня мест, которые чинит PR: иначе он
// охраняет преимущественно долг, а не результат. Перечень ВЫВЕДЕН ПРОГОНОМ,
// а не написан по памяти (урок A2б): разбор напечатал по cmd/gui РОВНО ОДНО
// место (`abs, _ := filepath.Abs(fileName)`), а мест, которые чинит A1-I,
// четыре. 1 ≤ 4 — сторож заводится.
//
// ПРИЗНАК ПРЕДЪЯВЛЕН НА ДВУХ СЛУЧАЯХ РАЗНОЙ ФОРМЫ (правило «признак
// описывает форму последнего примера, а не свойство класса»):
//   - форма A, ПОРОДИВШАЯ: `if s, statErr := f(); statErr == nil { … }` без
//     else — ast.IfStmt с инициализацией;
//   - форма B: `_ = err` — ast.AssignStmt, другая синтаксическая
//     конструкция, за которую цепляется признак;
//   - форма C: `x, _ := f()` — блэнк на последнем возвращаемом значении;
//     ею и найдено единственное существующее исключение.
//
// ГРАНИЦЫ, названные прямо, а не умолчанные:
//   - сторож РАБОТАЕТ БЕЗ ТИПОВ и потому судит по имени: err, statErr,
//     hsErr… Ошибка, названная `e` или `problem`, им не видна. Типы здесь
//     означали бы загрузку пакета с Fyne и cgo в тест, который сегодня
//     идёт без gcc, — это цена, а не недосмотр;
//   - он не видит `if err != nil { return }`, после которого печатается
//     нулевое значение: это признак того же класса, но распознаётся он не
//     формой, а смыслом ветви;
//   - он не видит вызова-выражения, результат которого не берут вовсе
//     (`f()`), — без типов «не возвращает error» и «отбросил error»
//     неотличимы, а сторож, краснеющий на каждом `u.table.Refresh()`,
//     ослабили бы первым же действием.

// guiPkgFiles — разбираемый пакет. Сторож живёт в internal/guiview, а не в
// cmd/gui, по той же причине, что и сторож A3а: пакет без Fyne и без cgo
// идёт в обычном `go test`, а cmd/gui — только там, где стоит gcc.
const guiPkgFiles = "../../cmd/gui"

// discardExceptions — ИСКЛЮЧЕНИЯ, ВЫВЕДЕННЫЕ ПРОГОНОМ, а не по памяти.
// Каждое — поимённо и с причиной; новое вносится видимой строкой диффа.
var discardExceptions = map[string]string{
	"writeConfigFile/filepath.Abs": "abs, _ := filepath.Abs(fileName): " +
		"ошибка Abs означает, что не удалось определить текущий каталог; путь уже " +
		"записан и показывается человеку как есть. Место найдено ПРОГОНОМ этого " +
		"сторожа, а не составлено заранее; починка его — предмет A1б, не A1.",
}

// discardFinding — одно найденное место.
type discardFinding struct {
	fn   string // функция, в которой оно стоит
	what string // короткое имя места: функция/вызов
	line int
	form string // A, B или C — какой формой найдено
	file string
}

func (d discardFinding) key() string { return d.fn + "/" + d.what }

// errLike — имя, по которому сторож узнаёт ошибку. Без типов другого
// признака нет; граница названа в шапке.
func errLike(name string) bool {
	l := strings.ToLower(name)
	return l == "err" || strings.HasSuffix(l, "err")
}

// callName — короткое имя вызова для отчёта: filepath.Abs, u.sess.GetPeerStats.
func callName(e ast.Expr) string {
	switch x := e.(type) {
	case *ast.CallExpr:
		return callName(x.Fun)
	case *ast.SelectorExpr:
		if base := callName(x.X); base != "" {
			return base + "." + x.Sel.Name
		}
		return x.Sel.Name
	case *ast.Ident:
		return x.Name
	}
	return ""
}

// findDiscarded разбирает один файл и возвращает все места отброшенной
// ошибки трёх форм.
func findDiscarded(t *testing.T, path string) []discardFinding {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		t.Fatalf("сторож Г5 ПЕРЕСТАЛ ЧТО-ЛИБО ПРОВЕРЯТЬ: %s не разбирается как Go: %v", path, err)
	}

	var out []discardFinding
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		fnName := fn.Name.Name
		add := func(pos token.Pos, what, form string) {
			out = append(out, discardFinding{
				fn: fnName, what: what, form: form,
				line: fset.Position(pos).Line, file: path,
			})
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			switch x := n.(type) {
			// Форма A: if v, err := f(); err == nil { … } без else.
			case *ast.IfStmt:
				as, ok := x.Init.(*ast.AssignStmt)
				if !ok || x.Else != nil {
					return true
				}
				bin, ok := x.Cond.(*ast.BinaryExpr)
				if !ok || bin.Op != token.EQL {
					return true
				}
				id, ok := bin.X.(*ast.Ident)
				if !ok || !errLike(id.Name) {
					return true
				}
				if nilIdent, ok := bin.Y.(*ast.Ident); !ok || nilIdent.Name != "nil" {
					return true
				}
				what := id.Name
				if len(as.Rhs) == 1 {
					if c := callName(as.Rhs[0]); c != "" {
						what = c
					}
				}
				add(x.Pos(), what, "A")
			case *ast.AssignStmt:
				for i, l := range x.Lhs {
					id, ok := l.(*ast.Ident)
					if !ok || id.Name != "_" {
						continue
					}
					// Форма B: _ = err.
					if len(x.Rhs) == len(x.Lhs) {
						if r, ok := x.Rhs[i].(*ast.Ident); ok && errLike(r.Name) {
							add(x.Pos(), r.Name, "B")
						}
						continue
					}
					// Форма C: v, _ := f() — блэнк на последнем значении.
					if len(x.Rhs) == 1 && i == len(x.Lhs)-1 {
						if c := callName(x.Rhs[0]); c != "" {
							add(x.Pos(), c, "C")
						}
					}
				}
			}
			return true
		})
	}
	return out
}

func guiGoFiles(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir(guiPkgFiles)
	if err != nil {
		t.Fatalf("сторож Г5 ПЕРЕСТАЛ ЧТО-ЛИБО ПРОВЕРЯТЬ: не читается %s: %v", guiPkgFiles, err)
	}
	var files []string
	for _, e := range entries {
		n := e.Name()
		if e.IsDir() || !strings.HasSuffix(n, ".go") || strings.HasSuffix(n, "_test.go") {
			continue
		}
		files = append(files, filepath.Join(guiPkgFiles, n))
	}
	sort.Strings(files)
	if len(files) == 0 {
		t.Fatalf("сторож Г5 ПЕРЕСТАЛ ЧТО-ЛИБО ПРОВЕРЯТЬ: в %s нет ни одного .go — "+
			"пакет переехал, и сверять стало не с чем", guiPkgFiles)
	}
	return files
}

// TestGuiNoDiscardedErrors — сторож: в cmd/gui нет отброшенных ошибок, кроме
// перечисленных поимённо.
func TestGuiNoDiscardedErrors(t *testing.T) {
	seen := map[string]bool{}
	for _, path := range guiGoFiles(t) {
		for _, d := range findDiscarded(t, path) {
			seen[d.key()] = true
			if _, allowed := discardExceptions[d.key()]; allowed {
				continue
			}
			t.Errorf("%s:%d: ошибка отброшена (форма %s, место %s) — "+
				"признак 2 правила П-НЕЗНАНИЕ: переменная остаётся нулевой, и ноль уходит к "+
				"человеку как измеренная величина. Либо ветвь на ошибку, либо строка в "+
				"discardExceptions с причиной (видимой строкой диффа).",
				d.file, d.line, d.form, d.key())
		}
	}
	// Исключение, которое перестало существовать, — не безобидно: перечень
	// исключений незаметно превращается в опись долга, за которой никто не
	// следит.
	for k := range discardExceptions {
		if !seen[k] {
			t.Errorf("исключение %q больше не встречается в cmd/gui — удалить его из discardExceptions", k)
		}
	}
}

// TestGuiDiscardGuardCatchesBothForms — ПРЕДЪЯВЛЕНИЕ ПРИЗНАКА НА ДВУХ
// СЛУЧАЯХ РАЗНОЙ ФОРМЫ. Зелёная проверка, не предъявившая покраснения,
// засчитывается как отсутствующая; и признак, предъявленный только на
// породившей форме, описывает форму, а не класс.
func TestGuiDiscardGuardCatchesBothForms(t *testing.T) {
	dir := t.TempDir()
	for _, tc := range []struct {
		name string
		form string
		src  string
	}{
		{
			name: "A/породившая форма: if … err == nil без else",
			form: "A",
			src: `package main
func f() (int, error) { return 0, nil }
func handler() int {
	n := 0
	if v, statErr := f(); statErr == nil {
		n = v
	}
	return n
}`,
		},
		{
			name: "B/другая форма: _ = err",
			form: "B",
			src: `package main
func g() error { return nil }
func handler() {
	err := g()
	_ = err
}`,
		},
		{
			name: "C/другая форма: блэнк на последнем значении вызова",
			form: "C",
			src: `package main
func h() (string, error) { return "", nil }
func handler() string {
	s, _ := h()
	return s
}`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(dir, fmt.Sprintf("case_%s.go", tc.form))
			if err := os.WriteFile(path, []byte(tc.src), 0600); err != nil {
				t.Fatal(err)
			}
			found := findDiscarded(t, path)
			if len(found) == 0 {
				t.Fatalf("сторож НЕ УВИДЕЛ отброшенную ошибку формы %s — признак описывает форму "+
					"последнего примера, а не свойство класса", tc.form)
			}
			if found[0].form != tc.form {
				t.Errorf("форма определена как %s, ожидалась %s", found[0].form, tc.form)
			}
		})
	}

	// И обратная сторона: на коде С ВЕТВЬЮ НА ОШИБКУ сторож молчит. Сторож,
	// краснеющий на законном коде, ослабляют первым же действием.
	path := filepath.Join(dir, "ok.go")
	if err := os.WriteFile(path, []byte(`package main
func f() (int, error) { return 0, nil }
func handler() (int, error) {
	v, err := f()
	if err != nil {
		return 0, err
	}
	return v, nil
}`), 0600); err != nil {
		t.Fatal(err)
	}
	if found := findDiscarded(t, path); len(found) != 0 {
		t.Errorf("сторож краснеет на коде с ветвью на ошибку: %+v", found)
	}
}

// TestGuiDiscardGuardStillSeesSomething — сторож, которому нечего разбирать,
// зелен по той же причине, по которой зелен сторож без дефектов. Здесь это
// различается: разбор обязан находить в cmd/gui хотя бы одно известное
// место (сегодня — единственное исключение).
func TestGuiDiscardGuardStillSeesSomething(t *testing.T) {
	total := 0
	for _, path := range guiGoFiles(t) {
		total += len(findDiscarded(t, path))
	}
	if total == 0 {
		t.Fatalf("сторож Г5 ПЕРЕСТАЛ ЧТО-ЛИБО ПРОВЕРЯТЬ: в %s не найдено НИ ОДНОГО места ни одной "+
			"из трёх форм — при живом перечне исключений это значит, что разбор перестал "+
			"видеть код, а не что долг погашен", guiPkgFiles)
	}
}
