package mouseguard

// Структурный сторож «перехватил мышь — обработай левый клик».
//
// ЦЕНА ВОПРОСА. Регресс 23.09 у владельца: «не выделяется строка, сколько
// ни кликай». Ячейка таблицы реализовала один лишь TappedSecondary ради
// контекстного меню. Боевой драйвер Fyne
// (fyne.io/fyne/v2@v2.7.4/internal/driver/glfw/window.go:460-468,
// window.processMouseClicked) выбирает цель клика по ПЯТИ интерфейсам
// сразу — fyne.Tappable, fyne.SecondaryTappable, fyne.DoubleTappable,
// fyne.Focusable, desktop.Mouseable — и только потом смотрит, что объект
// умеет. Ячейка стала целью и для левой кнопки, обработчика не имела, клик
// пропал. Ни одной ошибки не напечаталось: выбор строки просто перестал
// работать, а вместе с ним удаление, переименование и включение.
//
// ПРАВИЛО. Тип, объявленный в cmd/gui и объявляющий хотя бы один из
// «хватающих» методов — TappedSecondary, DoubleTapped, FocusGained,
// MouseDown, — обязан объявлять и Tapped. Метод, а не интерфейс: сторож
// ловит ту форму, которой пишут на самом деле.
//
// ПОЧЕМУ ИМЕННО ЭТИ ЧЕТЫРЕ. Это методы, по которым объект попадает в
// боевой предикат, не будучи fyne.Tappable. Tapped в список не входит —
// он и есть требуемое.
//
// СТОРОЖ ПРЕДЪЯВЛЯЕТ КАНАРЕЙКИ, каждую ОТДЕЛЬНОЙ компилируемой подменой,
// краснеющей именно на своей причине:
//   - TestGuardCatchesPlantedGrabWithoutTapped — подложенный тип с
//     TappedSecondary и без Tapped обязан краснеть;
//   - TestGuardAllowsGrabWithTapped — тот же тип, но с Tapped, краснеть НЕ
//     должен (иначе сторож краснеет не по заявленной причине);
//   - TestGuardAllowsTappedOnly — тип с одним лишь Tapped (наш
//     tappableLabel) не находка;
//   - TestGuardCatchesEmptyRoot — пустой корень (сторож смотрит не туда)
//     обязан ронять прогон, а не зеленеть молча;
//   - TestGuardSeesRealMouseTypes — сторож видит НАСТОЯЩИЕ типы мыши в
//     cmd/gui; исчезли — значит охват потерян.
//
// ЧЕГО СТОРОЖ НЕ ЛОВИТ, поимённо:
//   - интерфейс, полученный ВСТРАИВАНИЕМ (тип встроил widget.Entry и стал
//     Focusable, ничего не объявив): по AST этого не видно. Такой объект
//     уже умеет левый клик сам — как раз потому, что унаследовал целиком
//     чужой виджет;
//   - fyne.Draggable: в бою он участвует в выборе цели только при уже
//     начатом протаскивании, это другой разговор;
//   - cmd/cli и core: мыши там нет;
//   - _test.go: подменные виджеты в тестах под правило не подпадают;
//   - правильность того, ЧТО делает Tapped: это тесты cmd/gui
//     (TestPrimaryClickSelectsRowByBootRule).

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

// scannedRoot — дерево под охраной.
var scannedRoot = filepath.Join("..", "..", "cmd", "gui")

// minFiles — сколько .go-файлов сторож обязан разобрать. Меньше — значит он
// смотрит не туда (переезд, опечатка в scannedRoot), и это падение.
const minFiles = 1

// grabMethods — методы, по которым объект становится целью мыши, не умея
// левого клика.
var grabMethods = map[string]string{
	"TappedSecondary": "fyne.SecondaryTappable",
	"DoubleTapped":    "fyne.DoubleTappable",
	"FocusGained":     "fyne.Focusable",
	"MouseDown":       "desktop.Mouseable",
}

// requiredMethod — метод, который обязан быть у перехватчика.
const requiredMethod = "Tapped"

// knownMouseTypes — типы cmd/gui, которые СЕГОДНЯ работают с мышью. Список
// нужен не для запрета новых, а чтобы сторож не зеленел на пустоте: если ни
// одного из них не видно, охват потерян.
var knownMouseTypes = []string{"tableCell", "tappableLabel"}

type typeInfo struct {
	methods map[string]string // метод → позиция
}

// scanTree разбирает дерево и возвращает методы мыши по типам и число
// разобранных файлов. Ошибку разбора отдаёт наружу: молча пропущенный файл
// — это и есть способ сторожу ослепнуть.
func scanTree(root string) (map[string]*typeInfo, int, error) {
	types := map[string]*typeInfo{}
	files := 0
	fset := token.NewFileSet()

	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, 0, fmt.Errorf("корень %s не читается: %w", root, err)
	}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		path := filepath.Join(root, name)
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return nil, 0, fmt.Errorf("%s не разобран: %w", path, err)
		}
		files++
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv == nil || len(fn.Recv.List) == 0 {
				continue
			}
			recv := receiverTypeName(fn.Recv.List[0].Type)
			if recv == "" {
				continue
			}
			method := fn.Name.Name
			if method != requiredMethod {
				if _, isGrab := grabMethods[method]; !isGrab {
					continue
				}
			}
			ti := types[recv]
			if ti == nil {
				ti = &typeInfo{methods: map[string]string{}}
				types[recv] = ti
			}
			ti.methods[method] = fset.Position(fn.Pos()).String()
		}
	}
	return types, files, nil
}

func receiverTypeName(e ast.Expr) string {
	switch x := e.(type) {
	case *ast.StarExpr:
		return receiverTypeName(x.X)
	case *ast.Ident:
		return x.Name
	}
	return ""
}

// findings возвращает нарушения правила, отсортированные для устойчивого
// сообщения.
func findings(types map[string]*typeInfo) []string {
	var out []string
	for name, ti := range types {
		if _, ok := ti.methods[requiredMethod]; ok {
			continue
		}
		var grabbed []string
		for m, iface := range grabMethods {
			if pos, ok := ti.methods[m]; ok {
				grabbed = append(grabbed, fmt.Sprintf("%s (%s) в %s", m, iface, pos))
			}
		}
		if len(grabbed) == 0 {
			continue
		}
		sort.Strings(grabbed)
		out = append(out, fmt.Sprintf("тип %s объявляет %s, но не объявляет %s: "+
			"он становится целью ЛЕВОГО клика по боевому предикату Fyne "+
			"(glfw/window.go:460-468) и теряет этот клик — родительский виджет его не получит",
			name, strings.Join(grabbed, ", "), requiredMethod))
	}
	sort.Strings(out)
	return out
}

// TestNoMouseGrabWithoutTapped — само правило на боевом дереве.
func TestNoMouseGrabWithoutTapped(t *testing.T) {
	types, files, err := scanTree(scannedRoot)
	if err != nil {
		t.Fatalf("сторож не выполнялся: %v", err)
	}
	if files < minFiles {
		t.Fatalf("разобрано %d файлов в %s, ожидалось не меньше %d — сторож смотрит не туда",
			files, scannedRoot, minFiles)
	}
	for _, f := range findings(types) {
		t.Error(f)
	}
}

// TestGuardSeesRealMouseTypes — сторож видит настоящие типы мыши. Без этого
// он зеленел бы и на дереве, где мыши нет вовсе.
func TestGuardSeesRealMouseTypes(t *testing.T) {
	types, _, err := scanTree(scannedRoot)
	if err != nil {
		t.Fatalf("сторож не выполнялся: %v", err)
	}
	for _, want := range knownMouseTypes {
		ti, ok := types[want]
		if !ok {
			t.Errorf("сторож не видит тип %s в %s — охват потерян "+
				"(тип переименован, переехал или перестал работать с мышью)", want, scannedRoot)
			continue
		}
		if _, ok := ti.methods[requiredMethod]; !ok {
			t.Errorf("у типа %s нет %s", want, requiredMethod)
		}
	}
}

// plant кладёт подменный исходник в отдельный корень и возвращает путь.
func plant(t *testing.T, src string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "planted.go"), []byte(src), 0o600); err != nil {
		t.Fatalf("подмена не записана: %v", err)
	}
	return dir
}

const plantedGrabOnly = `package main

type planted struct{}

func (p *planted) TappedSecondary(e *int) {}
`

const plantedGrabWithTapped = `package main

type planted struct{}

func (p *planted) Tapped(e *int)          {}
func (p *planted) TappedSecondary(e *int) {}
`

const plantedTappedOnly = `package main

type planted struct{}

func (p *planted) Tapped(e *int) {}
`

// TestGuardCatchesPlantedGrabWithoutTapped — КАНАРЕЙКА: перехватчик без
// Tapped обязан краснеть.
func TestGuardCatchesPlantedGrabWithoutTapped(t *testing.T) {
	types, _, err := scanTree(plant(t, plantedGrabOnly))
	if err != nil {
		t.Fatalf("сторож не выполнялся: %v", err)
	}
	got := findings(types)
	if len(got) == 0 {
		t.Fatal("сторож НЕ заметил подложенный тип с TappedSecondary и без Tapped — " +
			"он не поймал бы регресс 23.09")
	}
	if !strings.Contains(got[0], "planted") || !strings.Contains(got[0], "TappedSecondary") {
		t.Errorf("сторож покраснел не по своей причине: %q", got[0])
	}
}

// TestGuardAllowsGrabWithTapped — КАНАРЕЙКА на соседнюю причину: тот же тип
// с Tapped краснеть НЕ должен.
func TestGuardAllowsGrabWithTapped(t *testing.T) {
	types, _, err := scanTree(plant(t, plantedGrabWithTapped))
	if err != nil {
		t.Fatalf("сторож не выполнялся: %v", err)
	}
	if got := findings(types); len(got) != 0 {
		t.Errorf("сторож краснеет на ПРАВИЛЬНОМ типе (Tapped + TappedSecondary): %v", got)
	}
}

// TestGuardAllowsTappedOnly — КАНАРЕЙКА на соседнюю причину: тип с одним
// Tapped (наш tappableLabel) не находка.
func TestGuardAllowsTappedOnly(t *testing.T) {
	types, _, err := scanTree(plant(t, plantedTappedOnly))
	if err != nil {
		t.Fatalf("сторож не выполнялся: %v", err)
	}
	if got := findings(types); len(got) != 0 {
		t.Errorf("сторож краснеет на типе с одним лишь Tapped: %v", got)
	}
}

// TestGuardCatchesEmptyRoot — КАНАРЕЙКА на слепоту: корень, где нечего
// разбирать, обязан ронять прогон, а не зеленеть.
func TestGuardCatchesEmptyRoot(t *testing.T) {
	_, files, err := scanTree(t.TempDir())
	if err != nil {
		return // не прочитался — тоже падение в боевом тесте
	}
	if files >= minFiles {
		t.Fatalf("в пустом корне разобрано %d файлов — счётчик врёт", files)
	}
	// Боевой тест на таком корне обязан упасть по проверке minFiles.
}

// TestGuardCatchesMissingRoot — КАНАРЕЙКА: несуществующий корень (переезд
// пакета) — ошибка, а не тишина.
func TestGuardCatchesMissingRoot(t *testing.T) {
	if _, _, err := scanTree(filepath.Join(t.TempDir(), "нет-такого")); err == nil {
		t.Fatal("сторож молча проглотил несуществующий корень — переезд cmd/gui остался бы незамеченным")
	}
}
