package main

import (
	"fmt"
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

// Дословные ожидания подписей и подтверждений. НАБРАНЫ ЗДЕСЬ РУКАМИ, а не
// взяты из guiview (ревью QA-01): иначе переименование константы в продукте
// автоматически переименовало бы и ожидание, и пустая или испорченная
// подпись прошла бы зелёной.
const (
	wantMenuCopyValue   = "Копировать значение"
	wantMenuCopyRow     = "Копировать строку"
	wantStatusCopiedOne = "Значение скопировано в буфер обмена"
)

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
			wantMenuCopyValue, wantMenuCopyRow)
	}
	// Ожидания ЛИТЕРАЛЬНЫЕ (ревью QA-01). Сверка с guiview.MenuCopyValue
	// брала бы ожидание из того же места, откуда строится продукт: опечатка
	// или пустая подпись уехали бы к владельцу молча.
	if m.Items[0].Label != wantMenuCopyValue || m.Items[1].Label != wantMenuCopyRow {
		t.Fatalf("подписи пунктов: %q, %q; ожидались %q и %q",
			m.Items[0].Label, m.Items[1].Label, wantMenuCopyValue, wantMenuCopyRow)
	}

	m.Items[0].Action()
	if got := fyne.CurrentApp().Clipboard().Content(); got != testKey {
		t.Errorf("«Копировать значение» положило в буфер %q, ожидался ключ ЦЕЛИКОМ %q", got, testKey)
	}
	if got := u.status.Text; got != wantStatusCopiedOne {
		t.Errorf("строка состояния после копирования значения: %q, ожидалось %q", got, wantStatusCopiedOne)
	}

	m.Items[1].Action()
	wantRow := "Ноутбук | Создан: 2026-09-22T12:34:56.789Z | Активность: 2 минуты назад | " +
		"Трафик ↓/↑: 1.2 MB / 900.0 KB | Ключ: " + testKey
	if got := fyne.CurrentApp().Clipboard().Content(); got != wantRow {
		t.Errorf("«Копировать строку» положило в буфер\n%q\nожидалось\n%q", got, wantRow)
	}
	// В подтверждении назван КЛИЕНТ (ревью UX-01): правая кнопка не меняет
	// выделение строки, и промахнувшийся на строку выше человек иначе не
	// заметит, что скопировал чужие данные.
	if got, want := u.status.Text, "Строка «Ноутбук» скопирована в буфер обмена"; got != want {
		t.Errorf("строка состояния после копирования строки: %q, ожидалось %q", got, want)
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
	for _, want := range []string{wantMenuCopyValue, wantMenuCopyRow} {
		if !strings.Contains(all, want) {
			t.Errorf("во всплывающем меню нет пункта %q; показаны: %q", want, all)
		}
	}
}

// TestCellHandlesPrimaryTap — ячейка ОБЯЗАНА обрабатывать левый клик.
//
// ЧТО ЗДЕСЬ БЫЛО. До 23.09 этот тест требовал ОБРАТНОГО — чтобы ячейка не
// реализовывала fyne.Tappable, — в уверенности, что тогда левый клик
// достанется widget.Table. Уверенность неверна: боевой драйвер выбирает
// цель по пяти интерфейсам сразу (см. шапку hittest_test.go), и ячейка с
// одним лишь TappedSecondary перехватывала левый клик, не умея его
// обработать. Требование перевёрнуто по факту регресса у владельца.
func TestCellHandlesPrimaryTap(t *testing.T) {
	u := testUI(t)
	cell := u.table.CreateCell()
	u.table.UpdateCell(widget.TableCellID{Row: 0, Col: 1}, cell)
	tap, ok := cell.(fyne.Tappable)
	if !ok {
		t.Fatalf("ячейка (%T) не обрабатывает левый клик, хотя перехватывает его как цель "+
			"мыши — выбор строки сломан, а с ним удаление, переименование и включение", cell)
	}
	u.selectedRow = -1
	tap.Tapped(&fyne.PointEvent{})
	if u.selectedRow != 0 {
		t.Errorf("после левого клика по ячейке строки 0 u.selectedRow = %d, ожидалось 0",
			u.selectedRow)
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

// TestLeftClickReallySelectsRow — БОЕВОЙ ПУТЬ левого клика (ревью QA-01):
// настоящий тап по канве в центр ячейки, а не вызов u.table.OnSelected
// (обёртка, которая не доказывает, что событие вообще дойдёт до таблицы).
// Именно этим тапом пользуются удаление, переименование и включение.
func TestLeftClickReallySelectsRow(t *testing.T) {
	u := testUI(t)
	u.win.Resize(fyne.NewSize(1200, 400))
	u.table.Refresh()

	var cell fyne.CanvasObject
	walkObjects(u.win.Canvas().Content(), func(o fyne.CanvasObject) {
		if c, ok := o.(*tableCell); ok && c.Text == "Ноутбук" {
			cell = c
		}
	})
	if cell == nil {
		t.Fatal("проверка ПЕРЕСТАЛА ЧТО-ЛИБО ЗНАЧИТЬ: на экране нет ячейки с именем клиента")
	}
	pos := fyne.CurrentApp().Driver().AbsolutePositionForObject(cell)
	center := fyne.NewPos(pos.X+cell.Size().Width/2, pos.Y+cell.Size().Height/2)

	u.selectedRow = -1
	test.TapCanvas(u.win.Canvas(), center)
	if u.selectedRow != 0 {
		t.Errorf("после настоящего клика по ячейке u.selectedRow = %d, ожидалось 0 — "+
			"левый клик до таблицы не доходит, а от него зависят удаление, переименование "+
			"и включение", u.selectedRow)
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

// minReasonableKeyWidth — пол для ИЗМЕРИТЕЛЬНОГО ПРИБОРА (ревью QA-01).
// Без пола сломанный шрифт (например, размер 0) намерил бы ноль, проверки
// ширины остались бы зелёными, и колонка схлопнулась бы молча.
//
// Число взято по самому УЗКОМУ мыслимому ключу, а не по типичному: 44 знака
// «l» шрифтом 14 точек меряются в 163 точки, типичный base64-ключ — в 357,
// сплошные «m» — в 571. Пол 100 заведомо ниже самого узкого и заведомо выше
// отказа измерения.
const minReasonableKeyWidth = 100

// clientsWithKeys — список клиентов с заданными ключами.
func clientsWithKeys(keys ...string) []core.ClientEntry {
	out := make([]core.ClientEntry, 0, len(keys))
	for i, k := range keys {
		out = append(out, core.ClientEntry{ClientID: k, UserData: map[string]any{
			"clientName": fmt.Sprintf("Клиент %d", i+1),
		}})
	}
	return out
}

// repeatKey — 43 одинаковых знака плюс «=», как настоящий ключ WireGuard.
func repeatKey(r rune) string {
	return strings.Repeat(string(r), 43) + "="
}

// TestKeyColumnWidthFollowsActualKeys — ширина колонки идёт ЗА ФАКТИЧЕСКИМИ
// ключами: узкие знаки — колонка уже, широкие — шире, и в обоих случаях
// колонка не уже измеренного текста самого широкого ключа.
//
// Ожидание берётся не из проверяемого кода: ширина текста считается здесь
// отдельным вызовом fyne.MeasureText.
func TestKeyColumnWidthFollowsActualKeys(t *testing.T) {
	a := test.NewApp()
	defer a.Quit()
	size := a.Settings().Theme().Size(theme.SizeNameText)

	narrowKey, wideKey := repeatKey('l'), repeatKey('m')
	narrowText := fyne.MeasureText(narrowKey, size, fyne.TextStyle{}).Width
	wideText := fyne.MeasureText(wideKey, size, fyne.TextStyle{}).Width

	// Канарейка на сломанный прибор: нулевое или бессмысленно малое
	// измерение — это отказ измерения, а не «ключ узкий».
	if narrowText < minReasonableKeyWidth || wideText < minReasonableKeyWidth {
		t.Fatalf("ПРИБОР СЛОМАН: 44 знака измерены в %v и %v точек при шрифте %v — "+
			"это меньше разумного минимума %v; любые выводы о ширине колонки по такому "+
			"измерению выдуманы", narrowText, wideText, size, minReasonableKeyWidth)
	}
	if narrowText >= wideText {
		t.Fatalf("ПРОВЕРКА ПЕРЕСТАЛА ЧТО-ЛИБО ЗНАЧИТЬ: «l»-ключ (%v) не уже «m»-ключа (%v) — "+
			"шрифт стал моноширинным, и различать ширины больше не на чем", narrowText, wideText)
	}

	narrowCol := keyColumnWidth(clientsWithKeys(narrowKey))
	wideCol := keyColumnWidth(clientsWithKeys(wideKey))

	if narrowCol == wideCol {
		t.Errorf("колонка одинакова (%v) для узкого и широкого ключей — ширина зашита числом, "+
			"а не измеряется по фактическим ключам: кому-то подсветка снова обрежет ключ", narrowCol)
	}
	if narrowCol >= wideCol {
		t.Errorf("колонка для узких ключей (%v) не уже, чем для широких (%v)", narrowCol, wideCol)
	}
	if narrowCol < narrowText {
		t.Errorf("колонка %v уже измеренного текста %v — подсветка обрежет ключ", narrowCol, narrowText)
	}
	if wideCol < wideText && wideCol < keyColumnCap() {
		t.Errorf("колонка %v уже измеренного текста %v при непочатом потолке %v",
			wideCol, wideText, keyColumnCap())
	}
	t.Logf("измерено: шрифт %v; «l»-ключ текст %v → колонка %v; «m»-ключ текст %v → колонка %v; потолок %v",
		size, narrowText, narrowCol, wideText, wideCol, keyColumnCap())
}

// TestKeyColumnWidthTakesTheWidest — берётся максимум по ВСЕМ клиентам, а не
// первый или последний.
func TestKeyColumnWidthTakesTheWidest(t *testing.T) {
	a := test.NewApp()
	defer a.Quit()
	narrowKey, wideKey := repeatKey('l'), repeatKey('m')
	alone := keyColumnWidth(clientsWithKeys(wideKey))
	for _, order := range [][]string{{narrowKey, wideKey, narrowKey}, {wideKey, narrowKey}} {
		if got := keyColumnWidth(clientsWithKeys(order...)); got != alone {
			t.Errorf("при нескольких клиентах колонка %v вместо %v (максимум по всем ключам)", got, alone)
		}
	}
}

// TestKeyColumnWidthFitsHeaderWhenEmpty — пустой список или протокол без
// ключей: колонка не уже собственного заголовка, иначе обрежется подпись.
func TestKeyColumnWidthFitsHeaderWhenEmpty(t *testing.T) {
	a := test.NewApp()
	defer a.Quit()
	size := a.Settings().Theme().Size(theme.SizeNameText)
	header := fyne.MeasureText(tableHeaders[keyColumn], size, fyne.TextStyle{Bold: true}).Width
	for _, c := range [][]core.ClientEntry{nil, clientsWithKeys(""), clientsWithKeys("abc")} {
		if got := keyColumnWidth(c); got < header {
			t.Errorf("колонка %v уже заголовка %q (%v точек) — обрежется сама подпись",
				got, tableHeaders[keyColumn], header)
		}
	}
}

// TestKeyColumnWidthCapped — потолок: вымышленно широкий ключ не распирает
// окно, колонка упирается в keyColumnCap, и возвращается прокрутка.
func TestKeyColumnWidthCapped(t *testing.T) {
	a := test.NewApp()
	defer a.Quit()
	huge := strings.Repeat("W", 200)
	got := keyColumnWidth(clientsWithKeys(huge))
	if got != keyColumnCap() {
		t.Errorf("колонка для заведомо широкого ключа = %v, ожидался потолок %v", got, keyColumnCap())
	}
	var sum float32
	for _, w := range tableColumnWidths(clientsWithKeys(huge)) {
		sum += w
	}
	if sum+windowChrome() > maxStartWindowWidth {
		t.Errorf("при упоре в потолок сумма колонок %v + обрамление %v шире окна %v — "+
			"потолок не выполняет своей работы", sum, windowChrome(), float32(maxStartWindowWidth))
	}
}

// randomBase64Keys — n псевдослучайных 44-значных base64-ключей. Генератор
// детерминированный (тест не должен мигать), но выборка настоящая: именно по
// такой снято practicalWidestKeyText в продукте.
func randomBase64Keys(n int) []string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	seed := uint64(20260922)
	out := make([]string, 0, n)
	for i := 0; i < n; i++ {
		b := make([]byte, 44)
		for j := 0; j < 43; j++ {
			seed = seed*6364136223846793005 + 1442695040888963407
			b[j] = alphabet[(seed>>33)%64]
		}
		b[43] = '='
		out = append(out, string(b))
	}
	return out
}

// TestStartWindowFitsWidestLikelyKey — РЕШЕНИЕ ВЛАДЕЛЬЦА: окно открывается
// сразу с запасом, по самому широкому ПРАКТИЧЕСКИ возможному ключу, а не по
// типичному. Окно на лету не переразмеряется, поэтому расчёт по типичному
// ключу означал бы прокрутку сразу после подключения — то, на что владелец и
// жаловался.
//
// Ожидание НЕ берётся из проверяемого кода: тест сам набирает выборку из 5000
// случайных ключей и меряет их fyne.MeasureText, а обрамление складывает из
// размеров темы напрямую.
func TestStartWindowFitsWidestLikelyKey(t *testing.T) {
	a := test.NewApp()
	defer a.Quit()
	th := a.Settings().Theme()
	size := th.Size(theme.SizeNameText)

	var widest float32
	for _, k := range randomBase64Keys(5000) {
		if w := fyne.MeasureText(k, size, fyne.TextStyle{}).Width; w > widest {
			widest = w
		}
	}
	if widest < minReasonableKeyWidth {
		t.Fatalf("ПРИБОР СЛОМАН: самый широкий ключ выборки измерен в %v точек", widest)
	}
	typical := fyne.MeasureText(typicalKeyWidthSample, size, fyne.TextStyle{}).Width
	if widest <= typical {
		t.Fatalf("ПРОВЕРКА ПЕРЕСТАЛА ЧТО-ЛИБО ЗНАЧИТЬ: максимум выборки (%v) не шире типичного "+
			"ключа (%v) — различать «по типичному» и «по практическому максимуму» больше не на чем",
			widest, typical)
	}

	var fixed float32
	for _, w := range fixedColumnWidths {
		fixed += w
	}
	chrome := th.Size(theme.SizeNameScrollBar) + 4*th.Size(theme.SizeNamePadding)
	need := fixed + widest + 2*th.Size(theme.SizeNameInnerPadding) + chrome

	got := startWindowSize()
	switch {
	case need > maxStartWindowWidth:
		if got.Width != maxStartWindowWidth {
			t.Errorf("содержимое шире потолка (%v > %v), а окно %v", need, float32(maxStartWindowWidth), got.Width)
		}
	case got.Width < need:
		t.Errorf("стартовая ширина окна %v меньше, чем нужно самому широкому практически "+
			"возможному ключу: %v (колонки %v + ключ %v + отступы + обрамление %v). Окно на лету "+
			"не переразмеряется, значит у человека с широкими ключами прокрутка появится сразу "+
			"после подключения", got.Width, need, fixed, widest, chrome)
	}
	if got.Width < minStartWindowWidth {
		t.Errorf("стартовая ширина %v уже пола %v", got.Width, float32(minStartWindowWidth))
	}
	if got.Height != mainWindowHeight {
		t.Errorf("высота окна %v вместо прежней %v — её менять не просили", got.Height, float32(mainWindowHeight))
	}
	t.Logf("выборка 5000 ключей: максимум текста %v, типичный %v; окно %v × %v (нужно %v)",
		widest, typical, got.Width, got.Height, need)
}

// renderedKeyCellWidth — ширина отрисованной ячейки с данным ключом.
func renderedKeyCellWidth(t *testing.T, u *ui, key string) float32 {
	t.Helper()
	var w float32
	found := false
	walkObjects(u.win.Canvas().Content(), func(o fyne.CanvasObject) {
		if c, ok := o.(*tableCell); ok && c.Text == key {
			w, found = c.Size().Width, true
		}
	})
	if !found {
		t.Fatal("проверка ПЕРЕСТАЛА ЧТО-ЛИБО ЗНАЧИТЬ: на экране нет ячейки с ключом")
	}
	return w
}

// TestBuildTableSetsMeasuredWidths — ПЕРВИЧНЫЙ путь: ширины, с которыми
// таблица СОБИРАЕТСЯ, тоже измеренные. Прежняя редакция этого не проверяла:
// тест звал applyKeyColumnWidth и перекрывал то, что поставил buildTable, —
// подмена «второй список чисел прямо в buildTable» проходила зелёной
// (находка QA-01).
func TestBuildTableSetsMeasuredWidths(t *testing.T) {
	a := test.NewApp()
	t.Cleanup(a.Quit)
	key := repeatKey('m')
	u := &ui{win: test.NewWindow(nil), clients: clientsWithKeys(key), canManage: true}
	t.Cleanup(func() { u.win.Close() })
	u.buildTable() // и НИКАКОГО applyKeyColumnWidth
	u.win.SetContent(u.table)
	u.win.Resize(fyne.NewSize(1600, 400))
	u.table.Refresh()

	want := keyColumnWidth(u.clients)
	if got := renderedKeyCellWidth(t, u, key); got < want {
		t.Errorf("сразу после buildTable ячейка ключа %v уже измеренной ширины %v — "+
			"таблица строится по другому списку ширин", got, want)
	}
}

// TestKeyColumnWidthReachesTheTable — ДОЕЗД ПРИ СМЕНЕ СОСТАВА: после
// applyKeyColumnWidth новая ширина попадает в таблицу.
func TestKeyColumnWidthReachesTheTable(t *testing.T) {
	u := testUI(t)
	u.win.Resize(fyne.NewSize(1600, 400))
	key := repeatKey('m')
	u.clients = clientsWithKeys(key)
	u.applyKeyColumnWidth()
	u.table.Refresh()

	want := keyColumnWidth(u.clients)
	if got := renderedKeyCellWidth(t, u, key); got < want {
		t.Errorf("отрисованная ячейка ключа %v уже вычисленной ширины %v — пересчёт до таблицы "+
			"не доезжает", got, want)
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
	a := test.NewApp()
	defer a.Quit()
	if got := len(tableColumnWidths(nil)); got != len(tableHeaders) {
		t.Errorf("ширин %d, заголовков %d", got, len(tableHeaders))
	}
	if keyColumn != len(fixedColumnWidths) {
		t.Errorf("keyColumn = %d, а колонок с постоянной шириной %d — вычисляемой окажется "+
			"не та колонка", keyColumn, len(fixedColumnWidths))
	}
	if !strings.Contains(tableHeaders[keyColumn], "ключ") {
		t.Errorf("колонка %d называется %q — индекс keyColumn указывает не на колонку ключа",
			keyColumn, tableHeaders[keyColumn])
	}
}
