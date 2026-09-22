package main

import (
	"strings"
	"testing"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/test"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"amnezia-admin/core"
	"amnezia-admin/internal/guiview"
)

// Проверки GUI-КОПИРОВАНИЯ. Дисплей НЕ требуется: test.NewApp даёт headless
// драйвер Fyne, окно создаётся в памяти. Эти тесты живут в cmd/gui, потому
// что проверяют настоящие виджеты; в релизной сборке (release.yml) пакет
// cmd/gui пока не прогоняется — это чинит A6, а логика, которую можно
// проверить без виджетов, вынесена в internal/guiview и проверена там.

const testKey = "aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789+/aBcD1="

func testUI(t *testing.T) *ui {
	t.Helper()
	a := test.NewApp()
	t.Cleanup(a.Quit)
	u := &ui{
		win: test.NewWindow(nil),
		clients: []core.ClientEntry{
			{ClientID: testKey, UserData: map[string]any{
				"clientName": "Ноутбук", "creationDate": "2026-09-22T12:34:56.789Z",
			}},
		},
		handshakes: map[string]string{testKey: "2 минуты назад"},
		peerStats:  map[string]core.PeerStat{testKey: {RxBytes: 1200000, TxBytes: 900000}},
		canManage:  true,
		status:     widget.NewLabel(""),
	}
	t.Cleanup(func() { u.win.Close() })
	u.buildTable()
	u.win.SetContent(u.table)
	return u
}

// TestCellMenuCopiesValueAndRow — ПОВЕДЕНЧЕСКИЙ тест обоих пунктов меню:
// после нажатия в буфере обмена лежит нужный текст, а в строке состояния —
// подтверждение человеку.
func TestCellMenuCopiesValueAndRow(t *testing.T) {
	u := testUI(t)
	m := u.cellMenu(widget.TableCellID{Row: 0, Col: keyColumn})
	if m == nil {
		t.Fatal("контекстное меню ячейки не построено")
	}
	if len(m.Items) != 2 {
		t.Fatalf("в меню %d пунктов, ожидалось 2 (%q и %q)", len(m.Items),
			guiview.MenuCopyValue, guiview.MenuCopyRow)
	}
	if m.Items[0].Label != guiview.MenuCopyValue || m.Items[1].Label != guiview.MenuCopyRow {
		t.Fatalf("подписи пунктов: %q, %q", m.Items[0].Label, m.Items[1].Label)
	}

	m.Items[0].Action()
	if got := fyne.CurrentApp().Clipboard().Content(); got != testKey {
		t.Errorf("«Копировать значение» положило в буфер %q, ожидался ключ ЦЕЛИКОМ %q", got, testKey)
	}
	if got := u.status.Text; got != guiview.StatusCopiedOne {
		t.Errorf("строка состояния после копирования значения: %q, ожидалось %q", got, guiview.StatusCopiedOne)
	}

	m.Items[1].Action()
	wantRow := "1 | Ноутбук | 2026-09-22T12:34:56.789Z | 2 минуты назад | 1.2 MB / 900.0 KB | " + testKey
	if got := fyne.CurrentApp().Clipboard().Content(); got != wantRow {
		t.Errorf("«Копировать строку» положило в буфер\n%q\nожидалось\n%q", got, wantRow)
	}
	if got := u.status.Text; got != guiview.StatusCopiedRow {
		t.Errorf("строка состояния после копирования строки: %q, ожидалось %q", got, guiview.StatusCopiedRow)
	}
}

// TestCellMenuCopiesColumnUnderCursor — пункт «Копировать значение» копирует
// ИМЕННО ту колонку, по которой нажали, а не первую попавшуюся.
func TestCellMenuCopiesColumnUnderCursor(t *testing.T) {
	u := testUI(t)
	for col, want := range map[int]string{
		1: "Ноутбук",
		2: "2026-09-22T12:34:56.789Z",
		4: "1.2 MB / 900.0 KB",
		5: testKey,
	} {
		u.cellMenu(widget.TableCellID{Row: 0, Col: col}).Items[0].Action()
		if got := fyne.CurrentApp().Clipboard().Content(); got != want {
			t.Errorf("колонка %d: в буфер попало %q, ожидалось %q", col, got, want)
		}
	}
}

// TestCellMenuOnEmptyRow — правая кнопка ниже последней строки не строит
// меню (и не роняет программу).
func TestCellMenuOnEmptyRow(t *testing.T) {
	u := testUI(t)
	if m := u.cellMenu(widget.TableCellID{Row: 5, Col: 0}); m != nil {
		t.Errorf("для несуществующей строки построено меню с %d пунктами", len(m.Items))
	}
}

// TestSecondaryTapShowsMenu — ПОВЕДЕНЧЕСКИ: правая кнопка по ячейке
// действительно открывает всплывающее меню поверх окна.
func TestSecondaryTapShowsMenu(t *testing.T) {
	u := testUI(t)
	cell := u.table.CreateCell()
	u.table.UpdateCell(widget.TableCellID{Row: 0, Col: keyColumn}, cell)

	st, ok := cell.(fyne.SecondaryTappable)
	if !ok {
		t.Fatalf("ячейка (%T) не реагирует на правую кнопку — контекстного меню не будет вовсе", cell)
	}
	if got := len(u.win.Canvas().Overlays().List()); got != 0 {
		t.Fatalf("до нажатия на экране уже %d наложений", got)
	}
	st.TappedSecondary(&fyne.PointEvent{})
	over := u.win.Canvas().Overlays().List()
	if len(over) == 0 {
		t.Fatal("правая кнопка по ячейке не открыла всплывающее меню")
	}
	var menu *widget.PopUpMenu
	walkObjects(over[len(over)-1], func(o fyne.CanvasObject) {
		if m, ok := o.(*widget.PopUpMenu); ok {
			menu = m
		}
	})
	if menu == nil {
		t.Fatalf("поверх окна оказалось %T без всплывающего меню внутри", over[len(over)-1])
	}
	// Подписи берутся с ОТРИСОВАННОГО меню, а не из того же места, где
	// заданы: собираем тексты объектов всплывающего меню.
	var shown []string
	walkObjects(menu, func(o fyne.CanvasObject) {
		if txt, ok := o.(*canvas.Text); ok && txt.Text != "" {
			shown = append(shown, txt.Text)
		}
	})
	all := strings.Join(shown, "|")
	for _, want := range []string{guiview.MenuCopyValue, guiview.MenuCopyRow} {
		if !strings.Contains(all, want) {
			t.Errorf("во всплывающем меню нет пункта %q; показаны: %q", want, all)
		}
	}
}

// TestCellIsNotPrimaryTappable — НЫНЕШНЕЕ ПОВЕДЕНИЕ НЕ СЛОМАНО: ячейка не
// перехватывает ЛЕВЫЙ клик. Драйвер Fyne отдаёт тап самому вложенному
// объекту, реализующему fyne.Tappable; реализуй ячейка этот интерфейс — тап
// не дошёл бы до widget.Table, и перестали бы работать выбор строки, а с ним
// удаление, переименование и включение.
func TestCellIsNotPrimaryTappable(t *testing.T) {
	u := testUI(t)
	cell := u.table.CreateCell()
	u.table.UpdateCell(widget.TableCellID{Row: 0, Col: 1}, cell)
	if _, bad := cell.(fyne.Tappable); bad {
		t.Errorf("ячейка (%T) сама обрабатывает левый клик — выбор строки в таблице сломан, "+
			"а с ним удаление, переименование и включение", cell)
	}
	if _, bad := cell.(fyne.Draggable); bad {
		t.Errorf("ячейка (%T) перехватывает протаскивание — прокрутка таблицы сломана", cell)
	}
	// И сам выбор строки по-прежнему доезжает до u.selectedRow.
	u.selectedRow = -1
	u.table.OnSelected(widget.TableCellID{Row: 0, Col: 1})
	if u.selectedRow != 0 {
		t.Errorf("после выбора строки u.selectedRow = %d, ожидалось 0", u.selectedRow)
	}
}

// TestHeaderStillSorts — НЫНЕШНЕЕ ПОВЕДЕНИЕ НЕ СЛОМАНО: клик по заголовку
// по-прежнему сортирует. Проверяется настоящим тапом по объекту заголовка.
func TestHeaderStillSorts(t *testing.T) {
	t.Setenv("HOME", t.TempDir()) // состояние сортировки пишется в файл
	u := testUI(t)
	u.sortPrimary = core.SortNone
	h := u.table.CreateHeader()
	u.table.UpdateHeader(widget.TableCellID{Row: -1, Col: 1}, h) // «Имя»
	tap, ok := h.(fyne.Tappable)
	if !ok {
		t.Fatalf("заголовок (%T) перестал быть кликабельным — сортировка недоступна", h)
	}
	tap.Tapped(&fyne.PointEvent{})
	if u.sortPrimary != core.SortByName {
		t.Errorf("после клика по заголовку «Имя» sortPrimary = %v, ожидалось %v",
			u.sortPrimary, core.SortByName)
	}
}

// TestKeyColumnFitsMeasuredKey — ширина колонки «Публичный ключ» ИЗМЕРЕНА.
//
// Ожидание берётся не из кода, который проверяется: ширина считается
// fyne.MeasureText по настоящему 44-знаковому ключу тем же размером шрифта,
// каким рисуется ячейка, плюс внутренние отступы widget.Label (их берём у
// самой метки: MinSize реального виджета, а не константой). Сверяется с
// tableColumnWidths — числом, которое стоит в программе.
func TestKeyColumnFitsMeasuredKey(t *testing.T) {
	a := test.NewApp()
	defer a.Quit()

	if len(testKey) != 44 {
		t.Fatalf("образец ключа — %d знаков, а публичный ключ WireGuard это 44", len(testKey))
	}
	size := a.Settings().Theme().Size(theme.SizeNameText)
	text := fyne.MeasureText(testKey, size, fyne.TextStyle{}).Width
	need := widget.NewLabel(testKey).MinSize().Width // текст + отступы метки
	if need < text {
		t.Fatalf("проверка ПЕРЕСТАЛА ЧТО-ЛИБО ЗНАЧИТЬ: метка (%v) уже текста (%v)", need, text)
	}
	if len(tableColumnWidths) <= keyColumn {
		t.Fatalf("проверка ПЕРЕСТАЛА ЧТО-ЛИБО ЗНАЧИТЬ: в tableColumnWidths нет колонки %d", keyColumn)
	}
	if got := tableColumnWidths[keyColumn]; got < need {
		t.Errorf("колонка «Публичный ключ» шириной %v точек не вмещает ключ: измерено %v точек "+
			"(текст %v + отступы метки). Владелец видит обрезок ключа", got, need, text)
	}
	// И ширина ДОЕЗЖАЕТ ДО ЭКРАНА: у настоящей отрисованной ячейки с ключом
	// ширина не меньше измеренной. Без этого tableColumnWidths могло бы
	// остаться правильным числом, которое никуда не передают.
	u := testUI(t)
	u.win.Resize(fyne.NewSize(1600, 400))
	u.table.Refresh()
	var cellW float32
	found := false
	walkObjects(u.win.Canvas().Content(), func(o fyne.CanvasObject) {
		if c, ok := o.(*tableCell); ok && c.Text == testKey {
			cellW, found = c.Size().Width, true
		}
	})
	if !found {
		t.Fatalf("проверка ПЕРЕСТАЛА ЧТО-ЛИБО ЗНАЧИТЬ: на экране нет ячейки с ключом")
	}
	if cellW < need {
		t.Errorf("отрисованная ячейка ключа шириной %v точек не вмещает измеренные %v — "+
			"ширина из tableColumnWidths до таблицы не доезжает", cellW, need)
	}
}

// walkObjects обходит дерево объектов окна (контейнеры и отрисовщики
// виджетов) — так проверка смотрит на то, что НА ЭКРАНЕ, а не на поля.
func walkObjects(o fyne.CanvasObject, fn func(fyne.CanvasObject)) {
	if o == nil {
		return
	}
	fn(o)
	switch x := o.(type) {
	case *fyne.Container:
		for _, c := range x.Objects {
			walkObjects(c, fn)
		}
	case fyne.Widget:
		for _, c := range test.WidgetRenderer(x).Objects() {
			walkObjects(c, fn)
		}
	}
}

// TestTableHeadersMatchGuiview — перечни колонок в cmd/gui и в guiview не
// разъезжаются: иначе «Копировать строку» отдаст не то число полей.
func TestTableHeadersMatchGuiview(t *testing.T) {
	if len(tableHeaders) != guiview.CopyColumnCount {
		t.Errorf("в таблице %d колонок, а guiview.CopyColumnCount = %d — строка в буфере "+
			"перестала соответствовать тому, что видно", len(tableHeaders), guiview.CopyColumnCount)
	}
	if len(tableColumnWidths) != len(tableHeaders) {
		t.Errorf("ширин %d, заголовков %d", len(tableColumnWidths), len(tableHeaders))
	}
	if !strings.Contains(tableHeaders[keyColumn], "ключ") {
		t.Errorf("колонка %d называется %q — индекс keyColumn указывает не на колонку ключа",
			keyColumn, tableHeaders[keyColumn])
	}
}
