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
// САМ СТОРОЖ ПРЕДЪЯВЛЯЕТ КАНАРЕЙКУ. Сторож правила «проверка обязана
// доказывать, что она выполнялась» подчиняется правилу сам:
// TestGuardCatchesPlantedDefects скармливает ему синтетическое дерево с
// заведомыми дефектами и требует находок, а рядом — заведомо честный файл, на
// котором находок быть НЕ должно. Одной половины мало: канарейка, только
// ищущая находки, зазеленела бы и на стороже, который красит всё подряд.
//
// ГРАНИЦА СТОРОЖА — здесь, в коде, а не в отчёте: читатель, уверенный, что
// сторож ловит всё, перестанет искать обход. Сторож стоит на двух ногах.
//
//  1. РЕЖИМ В ВЫЗОВЕ ЗАПИСИ ФАЙЛА. Последний аргумент os.WriteFile и
//     os.OpenFile обязан быть либо целочисленным литералом БЕЗ битов группы
//     и остальных (0600, 0400, 0), либо разрешённым ИМЕНЕМ — а имя разрешено
//     не само по себе, а в паре с файлом, где оно объявлено, и только если
//     его объявление в этом же файле даёт режим без битов группы и остальных
//     (см. allowedPermIdents и checkModeExpr). Иначе второй
//     privateFilePerm, заведённый где угодно со значением 0640, прошёл бы по
//     одному имени.
//     os.MkdirAll и os.Mkdir сюда НЕ входят намеренно: каталогу 0755 —
//     нормальные права, и запрет на них покраснел бы на честном коде, а
//     сторож, краснеющий на честном коде, ослабляют первым же действием.
//  2. ЛИТЕРАЛ 0644 ГДЕ УГОДНО в cmd/ и core/ — включая случаи, до которых
//     первая нога не дотягивается (режим в константе, в поле структуры, в
//     вызове чужой обёртки).
//
// ЧЕГО СТОРОЖ НЕ ЛОВИТ, поимённо:
//   - ТОЛЬКО cmd/ и core/. internal/ и scripts/ он не смотрит ВООБЩЕ, хотя
//     продуктовый код там есть (internal/envcheck, internal/guiview,
//     internal/version). Охват задан в scannedRoots и равен тому, что
//     названо в программе A4, — не больше;
//   - ПОТОК ДАННЫХ. Режим, доехавший до os.WriteFile через параметр, поле
//     структуры или локальную переменную, сторож не вычисляет — но и не
//     пропускает молча: любое имя, кроме разрешённого для этого файла, и
//     любое выражение, которое он не разбирает, становятся НАХОДКОЙ
//     («незнание не выдаётся за да»). Чего он действительно не поймает —
//     это переприсваивание уже разрешённого имени в другом месте файла
//     (privateFilePerm = 0666 внутри какой-нибудь функции): сторож смотрит
//     только на объявление;
//   - собственную обёртку над записью файла в другом пакете: внутри неё
//     os.WriteFile увидят, но только если она лежит в cmd/ или core/;
//   - os.Chmod, os.Create (0666 по умолчанию), ioutil.*, f.Chmod;
//   - права, выставленные вне Go (установщик, архив, umask);
//   - Windows: там POSIX-биты не применяются вовсе (ACL). Сторож читает
//     ИСХОДНИКИ, поэтому одинаково работает на любой ОС, — но и означает он
//     ровно то, что означает: «в исходниках нет широких режимов», а не
//     «файлы на диске защищены».

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
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

// minFilesPerRoot — сколько .go-файлов сторож обязан найти В КАЖДОМ корне.
// Проверка именно покорневая, а не по сумме: если cmd/ однажды уцелеет
// пустым (переехал, переименован, опечатка в scannedRoots), одного core
// хватило бы на любой общий порог, и сторож зазеленел бы, обойдя половину
// множества.
const minFilesPerRoot = 5

// allowedPermIdents — разрешённые имена режима, привязанные к ФАЙЛУ
// объявления. Ключ — хвост пути файла (со слэшами), значение — имена,
// разрешённые только в нём. Перечисляем ДОПУСТИМОЕ поимённо, а не пытаемся
// описать недопустимое; привязка к файлу не даёт завести одноимённую
// константу с широким режимом в другом месте.
var allowedPermIdents = map[string]map[string]bool{
	"cmd/gui/main.go": {"privateFilePerm": true}, // 0600, объявлена там же
}

// fileWriteCalls — вызовы, последний аргумент которых является режимом
// создаваемого ФАЙЛА. Каталоги (Mkdir/MkdirAll) сюда не входят — см. шапку.
var fileWriteCalls = map[string]bool{
	"os.WriteFile": true,
	"os.OpenFile":  true,
}

// forbiddenLiteralValue — вторая нога сторожа: сам режим 0644.
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

// unwrapConversion разворачивает os.FileMode(x) и подобные приведения.
func unwrapConversion(e ast.Expr) ast.Expr {
	if call, ok := e.(*ast.CallExpr); ok && len(call.Args) == 1 {
		if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "FileMode" {
			return unwrapConversion(call.Args[0])
		}
	}
	return e
}

// narrowLiteral — литерал без битов группы и остальных.
func narrowLiteral(e ast.Expr) (ok bool, isLiteral bool) {
	v, lit := parsePermLiteral(unwrapConversion(e))
	if !lit {
		return false, false
	}
	return v&0o077 == 0, true
}

// allowedIdentIn — разрешено ли имя id в файле path (путь с любым
// разделителем; сравнивается хвост).
func allowedIdentIn(path, id string) bool {
	slashed := filepath.ToSlash(path)
	for file, names := range allowedPermIdents {
		if strings.HasSuffix(slashed, file) && names[id] {
			return true
		}
	}
	return false
}

// declaredNarrowModes собирает имена, объявленные в ЭТОМ файле как const/var
// с целочисленным литералом, и признак «литерал без битов группы и
// остальных». Нужно, чтобы разрешённое имя проверялось по своему объявлению,
// а не только по написанию.
func declaredNarrowModes(f *ast.File) map[string]bool {
	out := map[string]bool{}
	ast.Inspect(f, func(n ast.Node) bool {
		vs, ok := n.(*ast.ValueSpec)
		if !ok {
			return true
		}
		for i, name := range vs.Names {
			if i >= len(vs.Values) {
				continue
			}
			if narrow, isLit := narrowLiteral(vs.Values[i]); isLit {
				out[name.Name] = narrow
			}
		}
		return true
	})
	return out
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

// checkModeExpr возвращает пояснение к находке или "" если режим допустим.
func checkModeExpr(path string, decls map[string]bool, e ast.Expr) string {
	if narrow, isLit := narrowLiteral(e); isLit {
		if narrow {
			return ""
		}
		return "режим-литерал открыт группе и/или остальным"
	}
	if id, ok := unwrapConversion(e).(*ast.Ident); ok {
		if !allowedIdentIn(path, id.Name) {
			return "режим задан именем " + id.Name + ", не разрешённым для этого файла (см. allowedPermIdents)"
		}
		narrow, declared := decls[id.Name]
		if !declared {
			return "разрешённое имя " + id.Name + " не объявлено литералом в этом же файле — сторож не может проверить его значение"
		}
		if !narrow {
			return "разрешённое имя " + id.Name + " объявлено здесь же широким режимом"
		}
		return ""
	}
	// Всё прочее (селектор, арифметика, вызов) сторож не разбирает и НЕ
	// объявляет допустимым молча: незнание не выдаётся за «да».
	return "режим задан выражением, которое сторож не разбирает, — сделайте его литералом или разрешённым именем"
}

// scanTree разбирает дерево и возвращает находки и число разобранных файлов.
// Ошибку разбора возвращает наружу: сторож, молча пропустивший файл,
// выглядит как сторож, которому нечего сказать.
func scanTree(root string) ([]finding, int, error) {
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
		// Исключений по именам файлов нет: любое исключение — дыра, о
		// которой забудут. Сам сторож в cmd/ и core/ не лежит.
		f, perr := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if perr != nil {
			return fmt.Errorf("сторож не смог разобрать %s: %w", path, perr)
		}
		files++
		decls := declaredNarrowModes(f)
		ast.Inspect(f, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.CallExpr:
				name := callName(x)
				if fileWriteCalls[name] && len(x.Args) > 0 {
					mode := x.Args[len(x.Args)-1]
					if why := checkModeExpr(path, decls, mode); why != "" {
						out = append(out, finding{fset.Position(mode.Pos()).String(), name + ": " + why})
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
		return nil, files, err
	}
	return out, files, nil
}

func TestNoWorldReadableFileModes(t *testing.T) {
	for _, root := range scannedRoots {
		found, files, err := scanTree(root)
		if err != nil {
			t.Fatalf("обход %s: %v", root, err)
		}
		for _, f := range found {
			t.Errorf("%s: %s", f.pos, f.what)
		}
		// Канарейка на молчаливый недозапуск — ПОКОРНЕВАЯ (см.
		// minFilesPerRoot): пустой корень обязан ронять прогон, а не
		// растворяться в сумме по остальным.
		if files < minFilesPerRoot {
			t.Fatalf("в корне %s разобрано всего %d .go-файлов (минимум %d) — сторож смотрит не туда; проверьте scannedRoots", root, files, minFilesPerRoot)
		}
		t.Logf("корень %s: разобрано файлов %d", root, files)
	}
}

// --- канарейка на заведомый дефект -----------------------------------------

// plantedSources — синтетическое дерево, на котором сторож обязан споткнуться
// (bad*) и обязан промолчать (good.go). Обе половины нужны: канарейка, только
// ищущая находки, зазеленела бы и на стороже, который красит всё подряд.
var plantedSources = map[string]string{
	"bad_literal.go": `package p

import "os"

func f(p string) error { return os.WriteFile(p, nil, 0644) }
`,
	"bad_ident.go": `package p

import "os"

var wideMode os.FileMode = 0640

func g(p string) error { return os.WriteFile(p, nil, wideMode) }
`,
	"bad_octal_other.go": `package p

import "os"

func h(p string) error { return os.OpenFile(p, os.O_CREATE, 0666) }
`,
	"good.go": `package p

import "os"

type window struct{ w, h int }

func ok1(p string) error { return os.WriteFile(p, nil, 0600) }

func ok2(p string) error { return os.WriteFile(p, nil, os.FileMode(0o400)) }

// Каталогу 0755 — нормальные права: сторож про Mkdir* ничего не говорит.
func ok3(d string) error { return os.MkdirAll(d, 0755) }

// Десятичное 420 равно 0644 по значению, но это размер окна, а не права.
func ok4() window { return window{420, 200} }
`,
}

func writePlanted(t *testing.T, names ...string) string {
	t.Helper()
	dir := t.TempDir()
	for _, n := range names {
		src, ok := plantedSources[n]
		if !ok {
			t.Fatalf("нет образца %q", n)
		}
		if err := os.WriteFile(filepath.Join(dir, n), []byte(src), 0600); err != nil {
			t.Fatalf("подложить %s: %v", n, err)
		}
	}
	return dir
}

func TestGuardCatchesPlantedDefects(t *testing.T) {
	// Нога 1 и нога 2 по отдельности, каждая своим образцом: иначе одна
	// сломанная нога спряталась бы за находкой другой.
	cases := []struct {
		name string
		file string
		want string
	}{
		{"литерал 0644 прямо в вызове", "bad_literal.go", "0644"},
		{"широкий режим под именем", "bad_ident.go", "wideMode"},
		{"0666 в os.OpenFile", "bad_octal_other.go", "открыт группе"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := writePlanted(t, c.file)
			found, files, err := scanTree(dir)
			if err != nil {
				t.Fatalf("scanTree: %v", err)
			}
			if files != 1 {
				t.Fatalf("разобрано файлов %d, want 1", files)
			}
			if len(found) == 0 {
				t.Fatalf("сторож НЕ споткнулся на заведомом дефекте %s — он вечнозелёный", c.file)
			}
			joined := ""
			for _, f := range found {
				joined += f.what + "\n"
			}
			if !strings.Contains(joined, c.want) {
				t.Fatalf("находки не про то: хотел упоминание %q, получил:\n%s", c.want, joined)
			}
		})
	}

	// Вторая половина: на честном файле находок быть НЕ должно.
	t.Run("честный файл не краснеет", func(t *testing.T) {
		dir := writePlanted(t, "good.go")
		found, _, err := scanTree(dir)
		if err != nil {
			t.Fatalf("scanTree: %v", err)
		}
		if len(found) != 0 {
			var lines []string
			for _, f := range found {
				lines = append(lines, f.pos+": "+f.what)
			}
			sort.Strings(lines)
			t.Fatalf("сторож покраснел на честном коде (0600, os.FileMode(0400), MkdirAll 0755, размер окна 420):\n%s", strings.Join(lines, "\n"))
		}
	})

	// Третья половина — разрешённое имя разрешено НЕ ВЕЗДЕ: тот же
	// privateFilePerm, заведённый в чужом файле широким, обязан краснеть.
	t.Run("разрешённое имя в чужом файле", func(t *testing.T) {
		dir := t.TempDir()
		src := `package p

import "os"

var privateFilePerm os.FileMode = 0600

func f(p string) error { return os.WriteFile(p, nil, privateFilePerm) }
`
		if err := os.WriteFile(filepath.Join(dir, "other.go"), []byte(src), 0600); err != nil {
			t.Fatalf("подложить: %v", err)
		}
		found, _, err := scanTree(dir)
		if err != nil {
			t.Fatalf("scanTree: %v", err)
		}
		// Значение здесь ЗАВЕДОМО УЗКОЕ (0600) намеренно: иначе находку дала
		// бы проверка объявления, и канарейка зазеленела бы на стороже без
		// привязки имени к файлу — то есть проверяла бы не то.
		joined := ""
		for _, f := range found {
			joined += f.what + "\n"
		}
		if !strings.Contains(joined, "не разрешённым для этого файла") {
			t.Fatalf("сторож принял privateFilePerm в чужом файле: разрешённое имя действует само по себе, привязки к файлу нет. Находки:\n%s", joined)
		}
	})
}

// TestGuardFailsOnUnparsableInput — неразобранный вход обязан быть ошибкой, а
// не молчаливым пропуском.
func TestGuardFailsOnUnparsableInput(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "broken.go"), []byte("package p\nfunc ("), 0600); err != nil {
		t.Fatalf("подложить: %v", err)
	}
	if _, _, err := scanTree(dir); err == nil {
		t.Fatal("сторож молча проглотил неразбираемый файл")
	}
}
