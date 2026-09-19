package permguard

// Структурный сторож прав создаваемых файлов (PR-A4, пункт 2).
//
// ЗАЧЕМ. Мест с 0644 было ровно два, оба в cmd/gui/main.go, и оба починены.
// Но «сегодня их нет» — это СОСТОЯНИЕ, а не свойство: третье место заведут
// через месяц одной строкой os.WriteFile(..., 0644), и никто не заметит.
// Сторож делает отсутствие свойством.
//
// ЦЕНА ВОПРОСА. Файлы, о которых речь, пишутся рядом с исполняемым файлом и
// в каталог «Настройки»: crash.log со стеком и путями, ui.json, а в core —
// хранилище .avlt, known_hosts и счётчики попыток. Права, открывающие их
// другим пользователям машины, отзыву не подлежат: файл уже прочитан.
//
// ГРАНИЦА СТОРОЖА — здесь, в коде, а не в отчёте: читатель, уверенный, что
// сторож ловит всё, перестанет искать обход. Сторож стоит на двух ногах.
//
//  1. РЕЖИМ В ВЫЗОВЕ ЗАПИСИ ФАЙЛА. Последний аргумент os.WriteFile и
//     os.OpenFile обязан быть либо целочисленным литералом БЕЗ битов группы
//     и остальных (0600, 0400, 0), либо именем из allowedPermIdents.
//     os.MkdirAll и os.Mkdir сюда НЕ входят намеренно: каталогу 0755 —
//     нормальные права, и запрет на них покраснел бы на честном коде, а
//     сторож, краснеющий на честном коде, ослабляют первым же действием.
//  2. ЛИТЕРАЛ 0644 ГДЕ УГОДНО в cmd/ и core/ — включая случаи, до которых
//     первая нога не дотягивается (режим в переменной, в константе, в поле
//     структуры, в вызове чужой обёртки).
//
// ЧЕГО СТОРОЖ НЕ ЛОВИТ, поимённо:
//   - режим, доехавший до os.WriteFile через переменную или параметр
//     (m := 0640; os.WriteFile(p, b, os.FileMode(m))) — поток данных он не
//     разбирает; вторая нога поймает только если литерал ровно 0644;
//   - собственную обёртку над записью файла в другом пакете;
//   - os.Chmod, os.Create (0666 по умолчанию), ioutil.*, f.Chmod;
//   - права, выставленные вне Go (установщик, архив, umask);
//   - Windows: там POSIX-биты не применяются вовсе (ACL). Сторож читает
//     ИСХОДНИКИ, поэтому одинаково работает на любой ОС, — но и означает он
//     ровно то, что означает: «в исходниках нет широких режимов», а не
//     «файлы на диске защищены».

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// scannedRoots — деревья, за которыми следит сторож (относительно этого
// пакета). Ровно те, что названы в программе A4: cmd/ и core/.
var scannedRoots = []string{
	filepath.Join("..", "..", "cmd"),
	filepath.Join("..", "..", "core"),
}

// allowedPermIdents — имена, которыми разрешено задавать режим файла.
// Перечисляем ДОПУСТИМОЕ поимённо, а не пытаемся описать недопустимое.
var allowedPermIdents = map[string]bool{
	"privateFilePerm": true, // cmd/gui: 0600, объявлена в cmd/gui/main.go
}

// fileWriteCalls — вызовы, последний аргумент которых является режимом
// создаваемого ФАЙЛА. Каталоги (Mkdir/MkdirAll) сюда не входят — см. шапку.
var fileWriteCalls = map[string]bool{
	"os.WriteFile": true,
	"os.OpenFile":  true,
}

// forbiddenLiteral — вторая нога сторожа: сам текст 0644 в любом виде.
var forbiddenLiteralValue int64 = 0o644

type finding struct {
	pos  string
	what string
}

// parsePermLiteral возвращает числовое значение целочисленного литерала и
// true, если узел — именно целочисленный литерал.
func parsePermLiteral(e ast.Expr) (int64, bool) {
	lit, ok := e.(*ast.BasicLit)
	if !ok || lit.Kind != token.INT {
		return 0, false
	}
	v, err := strconv.ParseInt(strings.ReplaceAll(lit.Value, "_", ""), 0, 64)
	if err != nil {
		return 0, false
	}
	return v, true
}

// isOctalSpelled — записан ли литерал восьмерично (0644 или 0o644/0O644).
func isOctalSpelled(s string) bool {
	s = strings.ReplaceAll(s, "_", "")
	if !strings.HasPrefix(s, "0") || len(s) < 2 {
		return false
	}
	return s[1] == 'o' || s[1] == 'O' || (s[1] >= '0' && s[1] <= '7')
}

// modeExprOK — разрешён ли такой способ задать режим файла.
func modeExprOK(e ast.Expr) bool {
	// os.FileMode(0600) и подобные приведения — разворачиваем.
	if call, ok := e.(*ast.CallExpr); ok && len(call.Args) == 1 {
		if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "FileMode" {
			return modeExprOK(call.Args[0])
		}
	}
	if id, ok := e.(*ast.Ident); ok {
		return allowedPermIdents[id.Name]
	}
	if v, ok := parsePermLiteral(e); ok {
		return v&0o077 == 0
	}
	// Всё прочее (переменная-селектор, арифметика, вызов) сторож не
	// разбирает и НЕ объявляет ни допустимым, ни запрещённым молча: он
	// требует явного решения — см. неразобранный вход ниже.
	return false
}

func callName(call *ast.CallExpr) string {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return ""
	}
	pkg, ok := sel.X.(*ast.Ident)
	if !ok {
		return ""
	}
	return pkg.Name + "." + sel.Sel.Name
}

// scanTree разбирает дерево и возвращает находки и число разобранных файлов.
func scanTree(t *testing.T, root string) ([]finding, int) {
	t.Helper()
	fset := token.NewFileSet()
	var out []finding
	files := 0
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") {
			return nil
		}
		// Сам сторож в cmd/ и core/ не лежит, исключений по именам файлов
		// нет: любое исключение — дыра, о которой забудут.
		f, perr := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if perr != nil {
			// Неразобранный вход — падение, а не пропуск: сторож, молча
			// пропустивший файл, выглядит как сторож, которому нечего
			// сказать (CLAUDE.md, «проверка обязана доказывать, что она
			// выполнялась»).
			t.Fatalf("сторож не смог разобрать %s: %v", path, perr)
		}
		files++
		ast.Inspect(f, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.CallExpr:
				name := callName(x)
				if fileWriteCalls[name] && len(x.Args) > 0 {
					mode := x.Args[len(x.Args)-1]
					if !modeExprOK(mode) {
						out = append(out, finding{fset.Position(mode.Pos()).String(),
							"режим файла в " + name + " не является ни литералом без прав группы/остальных, ни разрешённым именем"})
					}
				}
			case *ast.BasicLit:
				// Только ВОСЬМЕРИЧНОЕ написание: десятичное 420 — это не
				// права, а, например, ширина окна fyne.NewSize(420, 200),
				// которой в cmd/gui три штуки. Сторож, краснеющий на
				// размере окна, был бы отключён в тот же день.
				if v, ok := parsePermLiteral(x); ok && v == forbiddenLiteralValue && isOctalSpelled(x.Value) {
					out = append(out, finding{fset.Position(x.Pos()).String(),
						"литерал " + x.Value + " (0644) — права на чтение группе и остальным"})
				}
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatalf("обход %s: %v", root, err)
	}
	return out, files
}

func TestNoWorldReadableFileModes(t *testing.T) {
	total := 0
	for _, root := range scannedRoots {
		found, files := scanTree(t, root)
		total += files
		for _, f := range found {
			t.Errorf("%s: %s", f.pos, f.what)
		}
	}
	// Канарейка на молчаливый недозапуск: сторож, не нашедший ни одного
	// файла (переехал каталог, опечатка в пути), обязан покраснеть, а не
	// зазеленеть на пустом множестве.
	if total < 5 {
		t.Fatalf("сторож разобрал всего %d файлов — он смотрит не туда; проверьте scannedRoots", total)
	}
	t.Logf("разобрано файлов: %d", total)
}
