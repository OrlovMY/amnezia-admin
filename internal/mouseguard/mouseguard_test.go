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
// СИГНАТУРА, А НЕ ТОЛЬКО ИМЯ (найдено QA-01 после PR #17). Первая редакция
// сторожа сверяла методы ПО ИМЕНИ. Подложенный `func (p *planted) Tapped()`
// без аргумента интерфейс fyne.Tappable НЕ реализует — объект остаётся
// целью мыши и теряет левый клик ровно как раньше, — а сторожа проходил
// зелёным: «формально Tapped есть, фактически клик пропадает». Поэтому от
// Tapped требуется ровно один параметр, печатающийся как *fyne.PointEvent.
// Это ровно та форма, в которой Go признаёт реализацию fyne.Tappable.
//
// СТОРОЖ ПРЕДЪЯВЛЯЕТ КАНАРЕЙКИ, каждую ОТДЕЛЬНОЙ компилируемой подменой,
// краснеющей именно на своей причине:
//   - TestGuardCatchesPlantedGrabWithoutTapped — подложенный тип с
//     TappedSecondary и без Tapped обязан краснеть;
//   - TestGuardAllowsGrabWithTapped — тот же тип, но с Tapped, краснеть НЕ
//     должен (иначе сторож краснеет не по заявленной причине);
//   - TestGuardAllowsTappedOnly — тип с одним лишь Tapped (наш
//     tappableLabel) не находка;
//   - TestGuardCatchesTappedWithoutArgument и
//     TestGuardCatchesTappedWithWrongArgument — Tapped есть, но не той
//     формы: интерфейс не реализован, клик теряется, сторож обязан краснеть
//     ИМЕННО про сигнатуру;
//   - TestGuardCatchesEmptyRoot — пустой корень (сторож смотрит не туда)
//     обязан ронять прогон, а не зеленеть молча;
//   - TestGuardSeesRealMouseTypes — сторож видит НАСТОЯЩИЕ типы мыши в
//     cmd/gui; исчезли — значит охват потерян.
//
// ЧЕГО СТОРОЖ НЕ ЛОВИТ, поимённо:
//   - ТОЛЬКО КАТАЛОГ cmd/gui, без подкаталогов и без internal/ (граница
//     названа QA-01). Файлы читаются одним os.ReadDir, вложенные каталоги
//     пропускаются: новый мышиный виджет, вынесенный в internal/ или в
//     подпакет, сторожу невидим целиком. Держится это не молчанием, а
//     проверкой minFiles и списком knownMouseTypes: переедет сам cmd/gui —
//     сторож упадёт, а не позеленеет. Переезд ОТДЕЛЬНОГО виджета в
//     internal/ он не заметит, и это надо помнить при таком переносе;
//   - СИГНАТУРЫ «хватающих» методов. Проверяется сигнатура только у Tapped —
//     того метода, которого сторож ТРЕБУЕТ. У четырёх «хватающих» сверяется
//     лишь имя, и это осознанно: метод TappedSecondary(*int) интерфейса не
//     реализует и целью мыши не делает, но выглядит как попытка перехватить
//     мышь, и краснеть на нём честнее, чем молчать;
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
	"go/types"
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

// requiredParams — дословная сигнатура параметров Tapped, при которой Go
// признаёт тип реализующим fyne.Tappable. Сравнивается ТЕКСТОМ: сторож
// разбирает AST и типов не знает, а нам и нужна та форма, которой пишут.
const requiredParams = "*fyne.PointEvent"

// knownMouseTypes — типы cmd/gui, которые СЕГОДНЯ работают с мышью. Список
// нужен не для запрета новых, а чтобы сторож не зеленел на пустоте: если ни
// одного из них не видно, охват потерян.
var knownMouseTypes = []string{"tableCell", "tappableLabel"}

type typeInfo struct {
	methods map[string]string // метод → позиция
	params  map[string]string // метод → сигнатура параметров, например "*fyne.PointEvent"
}

// paramsOf печатает список параметров функции так, как он написан в
// исходнике: "*fyne.PointEvent", "" (нет параметров), "a, b int" и т.п.
func paramsOf(fn *ast.FuncDecl) string {
	if fn.Type == nil || fn.Type.Params == nil {
		return ""
	}
	var parts []string
	for _, f := range fn.Type.Params.List {
		typ := types.ExprString(f.Type)
		n := len(f.Names)
		if n == 0 {
			n = 1
		}
		for i := 0; i < n; i++ {
			parts = append(parts, typ)
		}
	}
	return strings.Join(parts, ", ")
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
				ti = &typeInfo{methods: map[string]string{}, params: map[string]string{}}
				types[recv] = ti
			}
			ti.methods[method] = fset.Position(fn.Pos()).String()
			ti.params[method] = paramsOf(fn)
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
		pos, declared := ti.methods[requiredMethod]
		// Сигнатура, а не только имя: Tapped() без аргумента интерфейса
		// fyne.Tappable не реализует, и объект теряет левый клик ровно так
		// же, как если бы Tapped не было вовсе.
		rightShape := declared && ti.params[requiredMethod] == requiredParams
		if rightShape {
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
		lack := fmt.Sprintf("не объявляет %s", requiredMethod)
		if declared {
			lack = fmt.Sprintf("объявляет %s(%s) в %s — а интерфейс fyne.Tappable требует %s(%s)",
				requiredMethod, ti.params[requiredMethod], pos, requiredMethod, requiredParams)
		}
		out = append(out, fmt.Sprintf("тип %s объявляет %s, но %s: "+
			"он становится целью ЛЕВОГО клика по боевому предикату Fyne "+
			"(glfw/window.go:460-468) и теряет этот клик — родительский виджет его не получит",
			name, strings.Join(grabbed, ", "), lack))
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
			continue
		}
		// И сигнатура настоящая: иначе сторож доказывал бы охват типом,
		// который сам интерфейса не реализует.
		if got := ti.params[requiredMethod]; got != requiredParams {
			t.Errorf("у типа %s метод %s(%s), а fyne.Tappable требует %s(%s)",
				want, requiredMethod, got, requiredMethod, requiredParams)
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

// Подмены пишутся В ТОЙ ЖЕ ФОРМЕ, в какой пишут настоящие виджеты: с
// *fyne.PointEvent. Иначе канарейка «правильный тип не краснеет» доказывала
// бы не то, что нужно.
const plantedGrabOnly = `package main

type planted struct{}

func (p *planted) TappedSecondary(e *fyne.PointEvent) {}
`

const plantedGrabWithTapped = `package main

type planted struct{}

func (p *planted) Tapped(e *fyne.PointEvent)          {}
func (p *planted) TappedSecondary(e *fyne.PointEvent) {}
`

const plantedTappedOnly = `package main

type planted struct{}

func (p *planted) Tapped(e *fyne.PointEvent) {}
`

// plantedTappedNoArg — ПОДМЕНА QA-01: Tapped есть, аргумента нет. Интерфейс
// fyne.Tappable не реализован, левый клик теряется — сторож обязан краснеть.
const plantedTappedNoArg = `package main

type planted struct{}

func (p *planted) Tapped()                            {}
func (p *planted) TappedSecondary(e *fyne.PointEvent) {}
`

// plantedTappedWrongArg — то же другой ценой: аргумент есть, но не тот.
const plantedTappedWrongArg = `package main

type planted struct{}

func (p *planted) Tapped(e *fyne.DragEvent)           {}
func (p *planted) TappedSecondary(e *fyne.PointEvent) {}
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

// TestGuardCatchesTappedWithoutArgument — КАНАРЕЙКА НА СИГНАТУРУ (QA-01):
// подложенный Tapped() без аргумента обязан краснеть, и краснеть ИМЕННО про
// сигнатуру, а не «метода нет».
func TestGuardCatchesTappedWithoutArgument(t *testing.T) {
	types, _, err := scanTree(plant(t, plantedTappedNoArg))
	if err != nil {
		t.Fatalf("сторож не выполнялся: %v", err)
	}
	got := findings(types)
	if len(got) == 0 {
		t.Fatal("сторож НЕ заметил подложенный Tapped() без аргумента: интерфейс " +
			"fyne.Tappable таким методом не реализуется, левый клик теряется — " +
			"«формально Tapped есть, фактически клик пропадает»")
	}
	if !strings.Contains(got[0], requiredParams) {
		t.Errorf("сторож покраснел не про сигнатуру: %q", got[0])
	}
}

// TestGuardCatchesTappedWithWrongArgument — та же причина, другая цена:
// аргумент есть, но чужого типа.
func TestGuardCatchesTappedWithWrongArgument(t *testing.T) {
	types, _, err := scanTree(plant(t, plantedTappedWrongArg))
	if err != nil {
		t.Fatalf("сторож не выполнялся: %v", err)
	}
	if got := findings(types); len(got) == 0 {
		t.Fatal("сторож НЕ заметил Tapped(*fyne.DragEvent): интерфейс fyne.Tappable " +
			"не реализован, левый клик теряется")
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
