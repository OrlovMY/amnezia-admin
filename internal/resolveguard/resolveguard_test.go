package resolveguard

// Структурный сторож A8 (ревью QA-01, подмена M12).
//
// ЗАЧЕМ. Тест cmd/cli на resolveInteractive/resolveByFlag проверяет саму
// обёртку, а НЕ то, что её зовут места меню и флаговых команд. Возврат
// одного из двенадцати мест к сырому core.ResolveClient(...).Index
// компилируется, меняет поведение и оставляет весь пакет зелёным: доезд
// доезжал до соседней функции, а не до боевого пути. Сторож делает
// «все места зовут обёртку» свойством, а не сегодняшним состоянием.
//
// ЦЕНА ВОПРОСА. Место, вернувшееся к сырому резолву, молча действует по
// первому совпадению имени и молчит о том, что число понято как имя.
// del/rename/toggle необратимы.
//
// ПРАВИЛО. В cmd/ вызовы core.ResolveClient и core.ResolveNonNumeric
// допускаются РОВНО в одном файле — cmd/cli/colors.go, где живут обёртки
// resolveInteractive и resolveByFlag. Везде ещё в cmd/ — находка.
//
// СТОРОЖ ПРЕДЪЯВЛЯЕТ КАНАРЕЙКИ, каждую ОТДЕЛЬНОЙ подменой, реагирующей
// именно на своё:
//   - TestGuardCatchesPlantedRawCall — сырой вызов в cmd/ вне обёрточного
//     файла обязан краснеть;
//   - TestGuardAllowsWrapperFile — тот же вызов В обёрточном файле краснеть
//     НЕ должен (иначе сторож краснеет не по заявленной причине);
//   - TestGuardCatchesEmptyRoot — пустой корень (сторож смотрит не туда)
//     обязан ронять прогон, а не зеленеть молча;
//   - TestGuardCatchesMissingWrapperCalls — если вызовов обёрток стало
//     меньше положенного (место удалили или переписали), это падение.
//
// ЧЕГО СТОРОЖ НЕ ЛОВИТ, поимённо:
//   - вызов, собранный через переменную-функцию или рефлексию: сторож ловит
//     форму, которой пишут на самом деле, — прямой селектор core.X(...);
//   - core/ и internal/ вне охвата: core — место, где эти функции и живут;
//   - правильность самих текстов Note()/Err() — это тесты в core/ и cmd/cli;
//   - _test.go: тестам звать core напрямую можно и нужно.

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// scannedRoot — дерево под охраной. Один корень, и он назван буквой.
var scannedRoot = filepath.Join("..", "..", "cmd")

// minFiles — сколько .go-файлов сторож обязан разобрать. Меньше — значит он
// смотрит не туда (переезд, опечатка в scannedRoot), и это падение.
const minFiles = 5

// wrapperFile — единственный файл cmd/, которому позволено звать core
// напрямую: в нём и живут обёртки.
const wrapperFile = "colors.go"

// rawFuncs — функции core, вызов которых мимо обёрток запрещён.
var rawFuncs = map[string]bool{"ResolveClient": true, "ResolveNonNumeric": true}

// wrapperCalls — сколько раз каждую обёртку обязаны звать в cmd/. Четыре
// пункта интерактивного меню; восемь флаговых мест (четыре в runDryRun,
// четыре в боевых ветках del/rename/toggle/rekey). Счёт, а не «больше
// нуля»: исчезновение одного места — ровно тот дефект, от которого сторож.
var wrapperCalls = map[string]int{"resolveInteractive": 4, "resolveByFlag": 8}

type finding struct {
	pos  string
	text string
}

// scanTree разбирает дерево и возвращает находки, счётчик вызовов обёрток и
// число разобранных файлов. Ошибку разбора отдаёт наружу: молча пропущенный
// файл выглядит так же, как файл без нарушений.
func scanTree(root string) ([]finding, map[string]int, int, error) {
	fset := token.NewFileSet()
	var out []finding
	calls := map[string]int{}
	files := 0
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			return perr
		}
		files++
		allowed := filepath.Base(path) == wrapperFile
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			switch fn := call.Fun.(type) {
			case *ast.SelectorExpr:
				pkg, ok := fn.X.(*ast.Ident)
				if !ok || pkg.Name != "core" || !rawFuncs[fn.Sel.Name] {
					return true
				}
				if allowed {
					return true
				}
				out = append(out, finding{fset.Position(call.Pos()).String(), "core." + fn.Sel.Name})
			case *ast.Ident:
				if _, want := wrapperCalls[fn.Name]; want {
					calls[fn.Name]++
				}
			}
			return true
		})
		return nil
	})
	return out, calls, files, err
}

func TestNoRawResolveOutsideWrapper(t *testing.T) {
	found, calls, files, err := scanTree(scannedRoot)
	if err != nil {
		t.Fatalf("обход %s: %v", scannedRoot, err)
	}
	if files < minFiles {
		t.Fatalf("разобрано %d .go-файлов в %s, ожидалось не меньше %d — сторож смотрит не туда", files, scannedRoot, minFiles)
	}
	for _, f := range found {
		t.Errorf("сырой вызов %s вне %s: %s — резолв обязан идти через resolveInteractive/resolveByFlag, иначе Note() не печатается и неоднозначность не останавливает действие", f.text, wrapperFile, f.pos)
	}
	for name, want := range wrapperCalls {
		if calls[name] != want {
			t.Errorf("вызовов %s в cmd/: %d, ожидалось %d — место резолва потеряно или заведено мимо обёртки", name, calls[name], want)
		}
	}
}

// ---------- канарейки ----------

// plantTree раскладывает минимальное дерево cmd/ во временном каталоге и
// добивает его наполнителями до minFiles, чтобы канарейка падала на СВОЁ, а
// не на порог числа файлов.
func plantTree(t *testing.T, pad bool, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	if pad {
		for i := 0; i < minFiles; i++ {
			name := filepath.Join("cli", fmt.Sprintf("pad%d.go", i))
			files[name] = fmt.Sprintf("package main\n\nfunc pad%d() {}\n", i)
		}
	}
	for name, body := range files {
		full := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	return root
}

const rawCallFile = "package main\n\nfunc f(clients []int, id string) { _ = core.ResolveClient(clients, id) }\n"

func TestGuardCatchesPlantedRawCall(t *testing.T) {
	root := plantTree(t, true, map[string]string{
		filepath.Join("cli", "main.go"): rawCallFile,
	})
	found, _, files, err := scanTree(root)
	if err != nil {
		t.Fatalf("scanTree: %v", err)
	}
	if files < minFiles {
		t.Fatalf("подготовка: разобрано %d файлов, нужно не меньше %d", files, minFiles)
	}
	if len(found) == 0 {
		t.Fatal("сторож НЕ заметил заведомый сырой вызов core.ResolveClient вне обёртки")
	}
}

func TestGuardAllowsWrapperFile(t *testing.T) {
	// Тот же самый заведомый вызов, но в законном файле: сторож обязан
	// МОЛЧАТЬ. Без этой проверки он мог бы краснеть на чём угодно.
	root := plantTree(t, true, map[string]string{
		filepath.Join("cli", wrapperFile): rawCallFile,
	})
	found, _, _, err := scanTree(root)
	if err != nil {
		t.Fatalf("scanTree: %v", err)
	}
	if len(found) != 0 {
		t.Fatalf("сторож покраснел на ЗАКОННОМ вызове внутри %s: %+v — он реагирует не на своё", wrapperFile, found)
	}
}

func TestGuardCatchesEmptyRoot(t *testing.T) {
	root := plantTree(t, false, map[string]string{})
	_, _, files, err := scanTree(root)
	if err != nil {
		t.Fatalf("scanTree: %v", err)
	}
	if files >= minFiles {
		t.Fatalf("пустой корень дал %d файлов — порог minFiles не работает", files)
	}
}

func TestGuardCatchesMissingWrapperCalls(t *testing.T) {
	// Дерево, где обёртки не зовут вовсе: счётчик обязан разойтись с
	// ожидаемым, иначе исчезновение места резолва пройдёт молча.
	root := plantTree(t, true, map[string]string{
		filepath.Join("cli", "main.go"): "package main\n\nfunc f() {}\n",
	})
	_, calls, _, err := scanTree(root)
	if err != nil {
		t.Fatalf("scanTree: %v", err)
	}
	for name, want := range wrapperCalls {
		if calls[name] == want {
			t.Fatalf("счётчик %s показал ожидаемые %d в дереве без единого вызова — счёт не работает", name, want)
		}
	}
}
