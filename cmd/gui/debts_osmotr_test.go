package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/test"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"amnezia-admin/core"
	"amnezia-admin/internal/fakesrv"
	"amnezia-admin/internal/guiview"
)

// Осмотр форм (verify-in-ui) для видимых добавок ДОЛГИ-ПРОДУКТ. Отдельным
// файлом: guiview.LoadedStatus и guiview.PinThrottleUnknown на c65420e нет,
// а debts_test.go обязан там компилироваться.

// ---------- У7: главное окно, длинная причина «?» в строке состояния ----------

var debtsLongStatsErr = errors.New(`команда "docker exec -i amnezia-awg sh -c 'wg show wg0 dump'": ` +
	strings.Repeat("ssh: handshake failed: read tcp 192.0.2.1:50123->203.0.113.10:22: ", 3) + "connection reset by peer")

// debtsLoadedStatus — худший по длине случай: отказ статистики с длинной
// ошибкой и клиент с длинным именем, у которого поле disabled испорчено.
func debtsLoadedStatus(clients []core.ClientEntry) string {
	clients = append(append([]core.ClientEntry(nil), clients...), core.ClientEntry{
		ClientID: repeatKey('W'), UserData: map[string]any{
			"clientName": "Планшет с очень длинным именем для проверки переноса", "disabled": "yes"}})
	return guiview.LoadedStatus("Пользователей: 4 · трафик и активность — с момента перезапуска сервера",
		clients, nil, debtsLongStatsErr)
}

func openMainLongStatus(t *testing.T, u *ui, sized func()) osmotrScene {
	osmotrMain(u)
	u.status.SetText(debtsLoadedStatus(u.clients))
	sized()
	c := u.win.Canvas()
	return osmotrScene{root: c.Content(), canvas: c, mins: osmotrFrame(c.Content(), nil)}
}

// openMainEnabledUnknown — главное окно, у «Телефона Анны» поле disabled
// испорчено: в «Активности» — guiview.EnabledUnknownCell (раунд 2, QA п.5).
func openMainEnabledUnknown(t *testing.T, u *ui, sized func()) osmotrScene {
	osmotrMain(u)
	// строка 1 («Ноутбук») — с измеренным временем: самая длинная ячейка
	// «<время> · вкл/откл: ?» (раунд 3, Я1)
	u.clients[0].UserData["disabled"] = "yes"
	u.status.SetText(guiview.LoadedStatus("Пользователей: 3 · трафик и активность — с момента перезапуска сервера",
		u.clients, u.peerStats, nil))
	u.applyKeyColumnWidth() // как refresh(): ширины по составу
	u.table.Refresh()
	sized()
	if got, want := cellText(u, 0, 3), testSeen.Format(guiview.HandshakeLayout)+" · "+guiview.EnabledUnknownCell; got != want {
		t.Fatalf("проверка ПЕРЕСТАЛА ЧТО-ЛИБО ЗНАЧИТЬ: «Активность» строки 1 — %q, ожидалось %q", got, want)
	}
	c := u.win.Canvas()
	return osmotrScene{root: c.Content(), canvas: c, mins: osmotrFrame(c.Content(), nil)}
}

func invMainWithStatus(status string) []string {
	inv := append([]string(nil), invMain...)
	inv[len(inv)-1] = "подпись:" + firstLine(status) // последняя — строка состояния
	return inv
}

// ---------- Н8: диалог пин-кода, счётчик попыток не читается ----------

// longVaultDir — каталог хранилищ с путём не короче 170 знаков без
// пробелов (постоянная сцена В1, раунд 2 долгов): глубокий профиль или
// «Загрузки» дают такие пути в бою, а каталог тестового бинарника короткий.
func longVaultDir(t *testing.T) string {
	t.Helper()
	base, err := os.MkdirTemp("", "osmotr")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(base) })
	dir := base
	for i := 0; len([]rune(dir)) < 170; i++ {
		dir = filepath.Join(dir, fmt.Sprintf("очень_глубокая_папка_%02d", i))
	}
	if strings.ContainsAny(dir, " \t") {
		t.Fatalf("проверка ПЕРЕСТАЛА ЧТО-ЛИБО ЗНАЧИТЬ: в пути есть пробел: %s", dir)
	}
	return dir
}

// openPinThrottleUnknown — диалог пин-кода, throttle.json повреждён; long —
// каталог хранилищ с длинным путём (через шов pinVaultDir).
func openPinThrottleUnknown(long bool) func(t *testing.T, u *ui, sized func()) osmotrScene {
	return func(t *testing.T, u *ui, sized func()) osmotrScene {
		localNetworkTime(t)
		var dir string
		if long {
			dir = longVaultDir(t)
			saved := pinVaultDir
			pinVaultDir = func() string { return dir }
			t.Cleanup(func() { pinVaultDir = saved })
		} else {
			dir = vaultDirForTest(t)
			t.Cleanup(func() { os.RemoveAll(dir) })
		}
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "throttle.json"), []byte("{"), 0o600); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { waitGUIGoroutines(t) })
		u.showConnectScreen("")
		sized()
		u.showVaultPinDialog(filepath.Join(dir, "нет.avlt"), "Сервер 1", widget.NewButton("", nil), widget.NewLabel(""))
		waitGUIGoroutines(t)
		c := u.win.Canvas()
		pop := topPopup(t, c)
		// Сцена значит что-то, только если путь действительно на экране.
		if texts := strings.Join(visibleTexts(pop), " "); !strings.Contains(texts, filepath.Join(dir, "throttle.json")) {
			t.Fatalf("проверка ПЕРЕСТАЛА ЧТО-ЛИБО ЗНАЧИТЬ: полного пути нет в диалоге: %s", texts)
		}
		mins := osmotrFrame(pop, nil)
		passwordEntry(t, pop, 0).SetText(typedCyrillicPin)
		return osmotrScene{root: pop, canvas: c, mins: mins}
	}
}

// TestDebtsActivityCellFits — раунд 3 (Я1): ячейка «<время> · вкл/откл: ?»
// помещается в колонку «Активность» (Fyne подпись не обрезает — лишнее
// налезло бы на «Трафик»; прибор осмотра меряет таблицу целиком и этого не
// видит). Текст — настоящий UpdateCell главного окна. Различение: без
// таких записей колонка прежняя, 140 т.
func TestDebtsActivityCellFits(t *testing.T) {
	u := focusTestUI(t)
	osmotrMain(u)
	if w := tableColumnWidths(u.clients)[activityColumn]; w != 140 {
		t.Fatalf("без неизвестных записей «Активность» %.1f т., ожидалось прежние 140", w)
	}
	u.clients[0].UserData["disabled"] = "yes"
	cell := cellText(u, 0, activityColumn)
	if !strings.Contains(cell, " · "+guiview.EnabledUnknownCell) {
		t.Fatalf("проверка ПЕРЕСТАЛА ЧТО-ЛИБО ЗНАЧИТЬ: ячейка %q", cell)
	}
	th := theme.Current()
	need := fyne.MeasureText(cell, th.Size(theme.SizeNameText), fyne.TextStyle{}).Width +
		2*th.Size(theme.SizeNameInnerPadding)
	if w := tableColumnWidths(u.clients)[activityColumn]; w < need {
		t.Fatalf("ячейка %q требует %.1f т., колонка %.1f т. — текст налезет на «Трафик»", cell, need, w)
	}
}

// TestDebtsTableHiddenWidth — раунд 4 (AU-UX Medium): колонки ЦЕЛИКОМ, а не
// атомом — сумма ширин против видимой ширины таблицы, штатно и с клиентом,
// у которого неизвестна включённость, на минимальном и стартовом окне.
// Держит решение раунда 4: расширение «Активности» — единственная добавка
// за краем (ровно на ширину расширения), колонка ключа НЕ урезается (иначе
// вернулась бы обрезанная подсветка ключа, решение владельца 22.09). Числа
// печатаются в лог для отчёта.
func TestDebtsTableHiddenWidth(t *testing.T) {
	type res struct{ sum, visible, hidden, key float32 }
	measure := func(unknown bool, size fyne.Size) res {
		u := focusTestUI(t)
		osmotrMain(u)
		if unknown {
			u.clients[0].UserData["disabled"] = "yes"
		}
		u.applyKeyColumnWidth()
		u.win.Resize(size)
		var sum float32
		ws := tableColumnWidths(u.clients)
		for _, w := range ws {
			sum += w
		}
		vis := u.table.Size().Width
		return res{sum, vis, sum - vis, ws[keyColumn]}
	}
	widen := func() float32 {
		u := focusTestUI(t)
		osmotrMain(u)
		base := tableColumnWidths(u.clients)[activityColumn]
		u.clients[0].UserData["disabled"] = "yes"
		return tableColumnWidths(u.clients)[activityColumn] - base
	}()
	if widen <= 0 {
		t.Fatalf("проверка ПЕРЕСТАЛА ЧТО-ЛИБО ЗНАЧИТЬ: «Активность» не расширяется")
	}
	for _, sz := range []struct {
		name string
		size fyne.Size
	}{{"минимальное", fyne.NewSize(1194.2, 517)}, {"стартовое", startWindowSize()}} {
		n, x := measure(false, sz.size), measure(true, sz.size)
		t.Logf("%s окно %.1f×%.0f: штатно сумма %.1f, видно %.1f, за краем %.1f; с «вкл/откл: ?» сумма %.1f, видно %.1f, за краем %.1f (расширение %.1f)",
			sz.name, sz.size.Width, sz.size.Height, n.sum, n.visible, n.hidden, x.sum, x.visible, x.hidden, widen)
		if x.key != n.key {
			t.Errorf("%s: колонка ключа урезана (%.1f → %.1f) — вернётся обрезанная подсветка ключа", sz.name, n.key, x.key)
		}
		if d := x.hidden - n.hidden - widen; d > 0.5 || d < -0.5 {
			t.Errorf("%s: за краем прибавилось %.1f, а расширение «Активности» %.1f — есть иная добавка", sz.name, x.hidden-n.hidden, widen)
		}
	}
}

// TestDebtsStatusStatsFailShort — раунд 4 (AU-UX Low): при отказе
// статистики строка состояния начинается с того, что делать, а сырая
// ошибка (здесь ~770 знаков, как в зонде аудитора) сжата до 120 знаков с
// сохранённым концом. Числа — высота строки состояния главного окна на
// 1194×517 и 1229×620 — печатаются в лог для отчёта.
func TestDebtsStatusStatsFailShort(t *testing.T) {
	raw := `команда "docker exec -i amnezia-awg sh -c 'wg show wg0 dump'": ` +
		strings.Repeat("ssh: handshake failed: read tcp 192.0.2.1:50123->203.0.113.10:22: ", 10) + "connection reset by peer"
	if n := len([]rune(raw)); n < 700 {
		t.Fatalf("проверка ПЕРЕСТАЛА ЧТО-ЛИБО ЗНАЧИТЬ: ошибка всего %d знаков", n)
	}
	st := guiview.LoadedStatus("Пользователей: 3", nil, nil, errors.New(raw))
	i := strings.Index(st, "Статистику с сервера получить не удалось — нажмите «Обновить» позже")
	if i < 0 {
		t.Fatalf("первым не сказано, что делать: %q", st)
	}
	reason := st[strings.Index(st, "Причина: ")+len("Причина: "):]
	if n := len([]rune(reason)); n > 121 {
		t.Errorf("причина %d знаков, ожидалось не больше 120: %q", n, reason)
	}
	// Второй, независимый сторож сжатия (выборка немоты, раунд 4): середина
	// сырой ошибки — десять повторов — в строку состояния не попадает.
	if n := strings.Count(st, "handshake failed"); n > 2 {
		t.Errorf("сырая ошибка не сжата: %d повторов из 10 в строке состояния", n)
	}
	if !strings.HasSuffix(reason, "connection reset by peer.") {
		t.Errorf("конец причины потерян: %q", reason)
	}
	for _, size := range []fyne.Size{{Width: 1194.2, Height: 517}, {Width: 1229, Height: 620}} {
		u := focusTestUI(t)
		osmotrMain(u)
		// состав зонда аудитора: два клиента с неизвестным состоянием и
		// длинными именами плюс отказ статистики с ~770-знаковой ошибкой
		u.clients[0].UserData["disabled"] = "yes"
		u.clients[0].UserData["clientName"] = "Ноутбук бухгалтерии второго этажа Иванова"
		u.clients[1].UserData["disabled"] = "yes"
		u.clients[1].UserData["clientName"] = "Телефон Анны Сергеевны служебный резервный"
		u.status.SetText(guiview.LoadedStatus("Пользователей: 3 · трафик и активность — с момента перезапуска сервера",
			u.clients, nil, errors.New(raw)))
		u.win.Resize(size)
		t.Logf("окно %.1f×%.0f: строка состояния %d знаков, высота %.1f т., таблица %.1f т.",
			size.Width, size.Height, len([]rune(u.status.Text)), u.status.Size().Height, u.table.Size().Height)
	}
}

// TestDebtsPinClosedHeadFirst — раунд 3 (UX-01, В1-б): полоса состояния
// диалога пина показывает две строки, около 100 знаков. При пути 170+ в них
// обязаны быть «Ввод пина закрыт» и «Повторить», а путь — в конце. Боевой
// путь: настоящий диалог, настоящий повреждённый throttle.json.
func TestDebtsPinClosedHeadFirst(t *testing.T) {
	u := focusTestUI(t)
	openPinThrottleUnknown(true)(t, u, func() { u.win.Resize(startWindowSize()) })
	var status string
	for _, s := range visibleTexts(topPopup(t, u.win.Canvas())) {
		if strings.Contains(s, "throttle.json") {
			status = s
		}
	}
	if status == "" {
		t.Fatal("проверка ПЕРЕСТАЛА ЧТО-ЛИБО ЗНАЧИТЬ: текста с путём в диалоге нет")
	}
	head := []rune(status)
	if len(head) > 100 {
		head = head[:100]
	}
	for _, w := range []string{"Ввод пина закрыт", "Повторить"} {
		if !strings.Contains(string(head), w) {
			t.Errorf("в первых 100 знаках нет %q: %q", w, string(head))
		}
	}
	if !strings.HasSuffix(status, "throttle.json.") {
		t.Errorf("путь не в конце текста: %q", status)
	}
	// Раунд 4 (AU-UX Low): подпись с путём выделяемая — путь копируется.
	var lbl *widget.Label
	walkObjects(topPopup(t, u.win.Canvas()), func(o fyne.CanvasObject) {
		if l, ok := o.(*widget.Label); ok && l.Text == status {
			lbl = l
		}
	})
	if lbl == nil {
		t.Fatal("проверка ПЕРЕСТАЛА ЧТО-ЛИБО ЗНАЧИТЬ: подписи с путём нет")
	}
	if !lbl.Selectable {
		t.Errorf("путь в диалоге пина нельзя выделить и скопировать")
	}
}

// openDiffDisableRecordOnly — раунд 6 (AU-UX Н5-1): окно «Показать
// изменения» из диалога «Отключить пользователя?» для клиента с
// неизвестным disabled ("true" строкой), у которого peer'а в wg0.conf нет.
// План настоящий (fakesrv), пояснение — plan.Note() в строке статуса окна.
func openDiffDisableRecordOnly(t *testing.T, u *ui, sized func()) osmotrScene {
	osmotrMain(u)
	sized()
	srv := fakesrv.New()
	const tbl, wg = "/opt/amnezia/awg/clientsTable", "/opt/amnezia/awg/wg0.conf"
	raw, _ := srv.File(tbl)
	var list []map[string]any
	if err := json.Unmarshal(raw, &list); err != nil || len(list) == 0 {
		t.Fatalf("fakesrv: %v", err)
	}
	list[0]["userData"].(map[string]any)["disabled"] = "true"
	id, name := list[0]["clientId"].(string), list[0]["userData"].(map[string]any)["clientName"].(string)
	out, _ := json.Marshal(list)
	srv.SetFile(tbl, out)
	conf, _ := srv.File(wg)
	var kept []string
	for _, b := range strings.Split(string(conf), "\n\n") {
		if !strings.Contains(b, id) {
			kept = append(kept, b)
		}
	}
	srv.SetFile(wg, []byte(strings.Join(kept, "\n\n")))
	sess := core.NewSessionWithRunner(srv, &core.ServerCreds{Host: "203.0.113.10", User: "root", Password: "x"})
	c := &core.Container{Name: "amnezia-awg", Dir: "/opt/amnezia/awg", Proto: "AmneziaWG", Managed: true}
	plan, err := sess.PlanSetEnabled(c, id, false)
	if err != nil {
		t.Fatalf("PlanSetEnabled: %v", err)
	}
	if plan.Note() != core.NoteDisableRecordOnly {
		t.Fatalf("проверка ПЕРЕСТАЛА ЧТО-ЛИБО ЗНАЧИТЬ: пояснения нет (%q)", plan.Note())
	}
	u.showDiffWindow("отключение \""+name+"\"", plan, nil)
	return scenePopup(t, u)
}

func init() {
	osmotrForms = append(osmotrForms,
		osmotrForm{name: "(д) изменения: отключение, неизвестно, peer убран", open: openDiffDisableRecordOnly, width: 692,
			inventory: []string{"подпись:" + firstLine(`Изменения перед применением: отключение "Alice"`),
				"подпись:/opt/amnezia/awg/wg0.conf", "прокрутка:", "подпись:/opt/amnezia/awg/clientsTable", "прокрутка:",
				"кнопка:Применить", "подпись:" + firstLine(core.NoteDisableRecordOnly), "кнопка:Закрыть"}},
		osmotrForm{name: "(г) главное окно, включён ли клиент — неизвестно", open: openMainEnabledUnknown,
			inventory: invMainWithStatus("Пользователей: 3 · трафик и активность — с момента перезапуска сервера")},
		osmotrForm{name: "(г) главное окно, причина «?» в строке состояния", open: openMainLongStatus,
			inventory: invMainWithStatus(debtsLoadedStatus(nil))},
		osmotrForm{name: "(б) пин-код, счётчик попыток не читается", open: openPinThrottleUnknown(false),
			inventory: invPinBase, width: 412},
		osmotrForm{name: "(б) пин-код, счётчик попыток не читается, путь 170+ знаков", open: openPinThrottleUnknown(true),
			inventory: invPinBase, width: 412},
	)
}

// TestDebtsPinThrottleBrokenBeforeAttempt — раунд 4 (AU-LOGIC М-1), раунд 5
// (М-4): счётчик испортился ПОСЛЕ открытия диалога, до нажатия «Открыть».
// Проверка перед попыткой (submit) обязана закрыть ввод, НЕ выполняя
// попытку расшифровки. Утверждается ПРЯМО: число вызовов шва vaultDecrypt
// равно 0. Различение: без порчи то же нажатие даёт ровно 1 вызов — шов
// действительно на пути попытки. Поле пина (ветка неудачи его очищает) —
// второй, косвенный сторож. Файл — новый API (шов), поэтому здесь, а не в
// debts_test.go.
func TestDebtsPinThrottleBrokenBeforeAttempt(t *testing.T) {
	for _, broken := range []bool{false, true} {
		u, open := pinDialogWith(t, func(string) {})
		calls := 0
		saved := vaultDecrypt
		vaultDecrypt = func(path, pin string) (core.VaultPayload, core.VaultInfo, error) {
			calls++
			return saved(path, pin)
		}
		if open.Disabled() {
			t.Fatalf("проверка ПЕРЕСТАЛА ЧТО-ЛИБО ЗНАЧИТЬ: до порчи ввод закрыт: %s", pinDialogTexts(t, u))
		}
		if broken {
			if err := os.WriteFile(filepath.Join(core.DefaultVaultDir(), "throttle.json"), []byte("{"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		pin := passwordEntry(t, topPopup(t, u.win.Canvas()), 0)
		pin.SetText("1111")
		test.Tap(open)
		waitGUIGoroutines(t)
		vaultDecrypt = saved
		texts := pinDialogTexts(t, u)
		if !broken {
			if calls != 1 {
				t.Fatalf("проверка ПЕРЕСТАЛА ЧТО-ЛИБО ЗНАЧИТЬ: штатная попытка дала %d вызовов расшифровки, ожидался 1", calls)
			}
			continue
		}
		if calls != 0 {
			t.Errorf("при неизвестном счётчике выполнено попыток расшифровки: %d, ожидалось 0: %s", calls, texts)
		}
		if !open.Disabled() || !strings.Contains(texts, "Ввод пина закрыт: не удалось прочитать") {
			t.Errorf("счётчик испорчен перед попыткой, а ввод не закрыт: %s", texts)
		}
		if pin.Text != "1111" {
			t.Errorf("поле пина очищено веткой неудачи — попытка была: %s", texts)
		}
	}
}
