package main

// ПОДСКАЗКА ПРО РАСКЛАДКУ ПРИ ВВОДЕ ПИНА И КЛЮЧА.
//
// ЗАЧЕМ. Просьба владельца 23.09.2026: переключать раскладку на английскую
// при вводе паролей и пин-кодов. Само переключение — системный вызов
// Windows, и проверить его действие можно только в живой сессии владельца
// (см. internal/kbdlayout). А вот СТРАХОВКА, которая работает на всех ОС и
// не зависит от успеха переключения, проверяется здесь боевым путём: текст
// кладётся в настоящее поле ввода диалога, и спрашивается, что после этого
// видно на экране.
//
// СЕКРЕТЫ. Ни один тест ниже не печатает введённого и требует того же от
// программы: подсказка говорит только о ФАКТЕ, сами символы на экран не
// попадают. Это отдельная проверка, а не оговорка в комментарии.
//
// Дословный текст подсказки НАБРАН ЗДЕСЬ РУКАМИ: возьми его из guiview —
// и переименование константы переименовало бы заодно и ожидание.

import (
	"errors"
	"fmt"
	"image/color"
	"strings"
	"testing"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/test"
	"fyne.io/fyne/v2/widget"

	"amnezia-admin/core"
	"amnezia-admin/internal/kbdlayout"
)

// wantLayoutSwitchFailed — дословный текст сообщения о неудавшемся
// переключении раскладки, набранный здесь руками.
const wantLayoutSwitchFailed = "Не удалось переключить раскладку на английскую — переключите её сами."

const (
	wantPinLayoutHint = "Похоже, включена не английская раскладка: пин-код принимает только латинские буквы, цифры и знаки с английской клавиатуры."
	wantKeyLayoutHint = "Похоже, включена не английская раскладка: админский ключ состоит только из латинских букв, цифр и знаков с английской клавиатуры."
)

// typedCyrillicPin — то, что получится, если набирать пин, не заметив
// русской раскладки. Набор намеренно бессмысленный: осмысленное слово
// совпало бы буквами с русскими подписями самого диалога, и проверка на
// утечку ловила бы не утечку. В сообщениях тестов он не печатается: это
// пароль.
const typedCyrillicPin = "йцукенгшщзХЪ1"

// typedLatinPin — верный ввод той же длины.
const typedLatinPin = "Abcdefgh1234!"

// visibleTexts собирает тексты ВИДИМЫХ подписей на экране (или в диалоге):
// widget.Label и canvas.Text.
//
// ПОЧЕМУ ИМЕННО ЭТИ ДВА И ПОЧЕМУ НЕ Entry (ревью SEC-01). canvas.Text — это
// mismatchLabel «Пины не совпадают» и подпись под галкой привязки: подписи,
// как и Label, и прежняя редакция их не видела, хотя называлась «видимые
// подписи». Поле ввода в перечень НЕ входит сознательно: в нём лежит то, что
// человек сам набрал, это не показ секрета программой (а поле пина к тому же
// парольное и рисует звёздочки). Проверка на утечку смотрит на то, что
// печатает ПРОГРАММА.
func visibleTexts(root fyne.CanvasObject) []string {
	var out []string
	walkVisibleStop(root, func(o fyne.CanvasObject) bool {
		switch x := o.(type) {
		case *widget.Label:
			out = append(out, x.Text)
			// ВНУТРЬ подписи не спускаемся: там тот же текст, разложенный
			// RichText на пословные куски. Куски засоряют выборку и мешают
			// искать в ней ЦЕЛЫЕ фразы — в том числе проверке на утечку
			// (ревью SEC-01).
			return true
		case *canvas.Text:
			out = append(out, x.Text)
		}
		return false
	})
	return out
}

// walkVisible обходит дерево, НЕ ЗАХОДЯ внутрь скрытых объектов.
//
// Обычного o.Visible() здесь мало, и это стоило бы ложного результата:
// widget.Label рисует себя вложенным RichText, и у СКРЫТОЙ подписи внутренний
// текст остаётся «видимым» сам по себе. Обход, проверяющий только сам объект,
// вытаскивал бы текст спрятанных подписей на свет. Боевой драйвер обходит
// дерево именно так — не спускаясь в скрытое.
func walkVisible(o fyne.CanvasObject, fn func(fyne.CanvasObject)) {
	walkVisibleStop(o, func(x fyne.CanvasObject) bool { fn(x); return false })
}

// walkVisibleStop — то же, но обработчик может сказать «внутрь этого не
// надо», вернув true.
func walkVisibleStop(o fyne.CanvasObject, fn func(fyne.CanvasObject) bool) {
	if o == nil || !o.Visible() {
		return
	}
	if fn(o) {
		return
	}
	switch x := o.(type) {
	case *fyne.Container:
		for _, c := range x.Objects {
			walkVisibleStop(c, fn)
		}
	case fyne.Widget:
		for _, c := range test.WidgetRenderer(x).Objects() {
			walkVisibleStop(c, fn)
		}
	}
}

func hasText(texts []string, want string) bool {
	for _, s := range texts {
		if s == want {
			return true
		}
	}
	return false
}

// passwordEntry — n-е по порядку обхода поле пароля.
func passwordEntry(t *testing.T, root fyne.CanvasObject, n int) *widget.Entry {
	t.Helper()
	var found []*widget.Entry
	walkObjects(root, func(o fyne.CanvasObject) {
		if e, ok := o.(*widget.Entry); ok && e.Password {
			found = append(found, e)
		}
	})
	if len(found) <= n {
		t.Fatalf("проверка ПЕРЕСТАЛА ЧТО-ЛИБО ЗНАЧИТЬ: полей пароля на экране %d, нужно хотя бы %d",
			len(found), n+1)
	}
	return found[n]
}

// noEnteredCharsOnScreen — введённое НЕ ПОКАЗАНО.
//
// Сверяется, что ни один КУСОК введённого длиной в 4 знака не виден на
// экране целиком.
//
// ПОЧЕМУ НЕ ПОСИМВОЛЬНО — И ЭТО ГРАНИЦА ПРОВЕРКИ, А НЕ НЕДОСМОТР. Весь
// интерфейс написан по-русски: подписи «Повтор пина», «Привязать к этой
// учётке Windows» содержат те же буквы, что и пин, набранный в русской
// раскладке. Требование «ни одной общей буквы» краснело бы всегда и было бы
// ослаблено первым же действием. Четыре знака подряд — это уже не совпадение
// букв, а показанный кусок секрета.
func noEnteredCharsOnScreen(t *testing.T, texts []string, entered string) {
	t.Helper()
	runes := []rune(entered)
	for _, s := range texts {
		if s == "" {
			continue
		}
		for i := 0; i+4 <= len(runes); i++ {
			if strings.Contains(s, string(runes[i:i+4])) {
				t.Errorf("на экране видна подпись, содержащая кусок введённого секрета " +
					"длиной 4 знака — секрет утёк в текст")
				return
			}
		}
	}
}

// TestSaveKeyDialogHintsAboutLayout — ПЕРВОЕ задание пина («как при первом
// вводе их»): человек набирает пин в русской раскладке, символы скрыты
// звёздочками, и без подсказки он узнает о беде только отказом «недопустимые
// символы» после нажатия «Сохранить».
func TestSaveKeyDialogHintsAboutLayout(t *testing.T) {
	u := focusTestUI(t)
	u.offerSaveKey("vpn://не-настоящий", "Сервер 1", "")
	over := u.win.Canvas().Overlays().List()
	if len(over) == 0 {
		t.Fatal("диалог сохранения ключа не открылся")
	}
	d := over[len(over)-1]

	pin := passwordEntry(t, d, 0)
	pin.SetText(typedCyrillicPin)

	texts := visibleTexts(d)
	if !hasText(texts, wantPinLayoutHint) {
		t.Errorf("в диалоге «Сохранить ключ?» набран пин не в английской раскладке, "+
			"а подсказки про раскладку на экране нет. Видно: %q", texts)
	}
	noEnteredCharsOnScreen(t, texts, typedCyrillicPin)
}

// TestSaveKeyDialogNoHintForLatinPin — СОСЕДНЯЯ ПРИЧИНА: на верном вводе
// подсказки быть не должно. Подсказка, срабатывающая на правильном пине,
// хуже её отсутствия.
func TestSaveKeyDialogNoHintForLatinPin(t *testing.T) {
	u := focusTestUI(t)
	u.offerSaveKey("vpn://не-настоящий", "Сервер 1", "")
	d := u.win.Canvas().Overlays().List()[0]

	pin := passwordEntry(t, d, 0)
	pin.SetText(typedLatinPin)

	if texts := visibleTexts(d); hasText(texts, wantPinLayoutHint) {
		t.Errorf("подсказка про раскладку показана на пине из одной латиницы с цифрами: %q", texts)
	}
}

// TestSaveKeyDialogHintFollowsRepeatField — второе поле («Повтор пина») тоже
// под присмотром: перепутать раскладку на нём так же легко.
func TestSaveKeyDialogHintFollowsRepeatField(t *testing.T) {
	u := focusTestUI(t)
	u.offerSaveKey("vpn://не-настоящий", "Сервер 1", "")
	d := u.win.Canvas().Overlays().List()[0]

	passwordEntry(t, d, 0).SetText(typedLatinPin)
	passwordEntry(t, d, 1).SetText(typedCyrillicPin)

	if texts := visibleTexts(d); !hasText(texts, wantPinLayoutHint) {
		t.Errorf("в поле «Повтор пина» набрано не в английской раскладке, подсказки нет: %q", texts)
	}
}

// TestPinDialogHintsAboutLayout — СЛУЧАЙ ВЛАДЕЛЬЦА ЦЕЛИКОМ («как при первом
// вводе их, так и потом для авторизации»): открытие сохранённого ключа.
// Здесь отказ особенно дорог — неверный пин тратит одну из десяти попыток до
// блокировки на пять минут.
func TestPinDialogHintsAboutLayout(t *testing.T) {
	// В сеть тест не ходит: пул хостов времени подменён на закрытый порт.
	savedHosts := core.NetworkTimeHosts
	core.NetworkTimeHosts = []string{"https://127.0.0.1:1"}
	t.Cleanup(func() { core.NetworkTimeHosts = savedHosts })

	u := focusTestUI(t)
	t.Cleanup(func() { waitGUIGoroutines(t) })
	u.showVaultPinDialog(t.TempDir()+"/нет.avlt", "Сервер 1", widget.NewButton("", nil), widget.NewLabel(""))
	over := u.win.Canvas().Overlays().List()
	if len(over) == 0 {
		t.Fatal("диалог пин-кода не открылся")
	}
	waitGUIGoroutines(t) // фоновый запрос онлайн-времени завершён
	d := over[len(over)-1]

	passwordEntry(t, d, 0).SetText(typedCyrillicPin)

	texts := visibleTexts(d)
	if !hasText(texts, wantPinLayoutHint) {
		t.Errorf("в диалоге «Введите пин-код» набрано не в английской раскладке, "+
			"подсказки нет. Видно: %q", texts)
	}
	noEnteredCharsOnScreen(t, texts, typedCyrillicPin)
}

// TestConnectScreenHintsAboutLayout — поле админского ключа: там тоже только
// латиница, цифры и знаки препинания.
func TestConnectScreenHintsAboutLayout(t *testing.T) {
	u := focusTestUI(t)
	u.showConnectScreen("")
	content := u.win.Canvas().Content()

	key := firstEntry(content)
	if key == nil {
		t.Fatal("проверка ПЕРЕСТАЛА ЧТО-ЛИБО ЗНАЧИТЬ: на экране подключения нет поля ввода")
	}
	key.SetText("vpn://кириллицаВКлюче")

	texts := visibleTexts(content)
	if !hasText(texts, wantKeyLayoutHint) {
		t.Errorf("в поле админского ключа символы не из английской раскладки, "+
			"подсказки нет. Видно: %q", texts)
	}
}

// TestConnectScreenNoHintForLatinKey — соседняя причина: настоящий ключ
// подсказки не вызывает.
func TestConnectScreenNoHintForLatinKey(t *testing.T) {
	u := focusTestUI(t)
	u.showConnectScreen("")
	content := u.win.Canvas().Content()

	key := firstEntry(content)
	key.SetText("vpn://" + testKey)

	if texts := visibleTexts(content); hasText(texts, wantKeyLayoutHint) {
		t.Errorf("подсказка про раскладку показана на обычном ключе vpn://…: %q", texts)
	}
}

// ---------- ревью UX-01 и SEC-01, круг 2 ----------

// buttonByText — кнопка с такой подписью на экране (или в диалоге).
func buttonByText(t *testing.T, root fyne.CanvasObject, text string) *widget.Button {
	t.Helper()
	var found *widget.Button
	walkObjects(root, func(o fyne.CanvasObject) {
		if b, ok := o.(*widget.Button); ok && b.Text == text {
			found = b
		}
	})
	if found == nil {
		t.Fatalf("проверка ПЕРЕСТАЛА ЧТО-ЛИБО ЗНАЧИТЬ: нет кнопки %q", text)
	}
	return found
}

// TestConnectScreenNoHintForMultilineKey — КЛЮЧ, РАЗБИТЫЙ НА СТРОКИ, НЕ
// ЛОЖНАЯ ТРЕВОГА (ревью UX-01).
//
// Поле ключа многострочное, и ключ регулярно копируют из мессенджера уже с
// переносами. Текст в этом поле ВИДЕН (оно не парольное): человек смотрел бы
// на латиницу и читал, что у него не та раскладка.
func TestConnectScreenNoHintForMultilineKey(t *testing.T) {
	u := focusTestUI(t)
	u.showConnectScreen("")
	content := u.win.Canvas().Content()

	key := firstEntry(content)
	key.SetText("vpn://" + testKey[:20] + "\n" + testKey[20:])

	if texts := visibleTexts(content); hasText(texts, wantKeyLayoutHint) {
		t.Errorf("ключ из одной латиницы, разбитый на строки, объявлен не той раскладкой: %q", texts)
	}
}

// TestConnectScreenHintForMultilineCyrillicKey — СОСЕДНЯЯ ПРИЧИНА: послабление
// касается только переносов, кириллица в разбитом на строки ключе подсказку
// по-прежнему вызывает.
func TestConnectScreenHintForMultilineCyrillicKey(t *testing.T) {
	u := focusTestUI(t)
	u.showConnectScreen("")
	content := u.win.Canvas().Content()

	key := firstEntry(content)
	key.SetText("vpn://" + testKey[:20] + "\nкириллица" + testKey[20:])

	if texts := visibleTexts(content); !hasText(texts, wantKeyLayoutHint) {
		t.Errorf("в разбитом на строки ключе есть кириллица, подсказки нет: %q", texts)
	}
}

// substituteForceEnglish подменяет системный вызов переключения раскладки на
// время теста. Это и есть доезд до третьего состояния БОЕВЫМ путём: диалог
// зовёт ту же функцию, что и в бою.
func substituteForceEnglish(t *testing.T, err error) {
	t.Helper()
	saved := forceEnglish
	forceEnglish = func() error { return err }
	t.Cleanup(func() { forceEnglish = saved })
}

// TestPinDialogTellsWhenLayoutSwitchFailed — ТРЕТЬЕ СОСТОЯНИЕ (ревью SEC-01).
// Переключение не удалось — человек об этом узнаёт. Иначе он уверен, что
// раскладка английская, хотя она не менялась.
func TestPinDialogTellsWhenLayoutSwitchFailed(t *testing.T) {
	substituteForceEnglish(t, errors.New("user32: отказ"))
	texts := openPinDialogTexts(t)
	if !hasText(texts, wantLayoutSwitchFailed) {
		t.Errorf("переключить раскладку не удалось, а диалог молчит: %q", texts)
	}
}

// TestPinDialogSilentWhenLayoutSwitched — переключили: говорить не о чем.
func TestPinDialogSilentWhenLayoutSwitched(t *testing.T) {
	substituteForceEnglish(t, nil)
	if texts := openPinDialogTexts(t); hasText(texts, wantLayoutSwitchFailed) {
		t.Errorf("раскладка переключена, а диалог сообщает об отказе: %q", texts)
	}
}

// TestPinDialogSilentWhenLayoutUnsupported — ОС так не умеет: обещания не
// было, пугать человека нечем. Это состояние обязано отличаться от отказа.
func TestPinDialogSilentWhenLayoutUnsupported(t *testing.T) {
	substituteForceEnglish(t, kbdlayout.ErrUnsupported)
	if texts := openPinDialogTexts(t); hasText(texts, wantLayoutSwitchFailed) {
		t.Errorf("на ОС без переключения раскладки показано сообщение об отказе: %q", texts)
	}
}

// openPinDialogTexts открывает диалог пин-кода и возвращает видимые подписи.
func openPinDialogTexts(t *testing.T) []string {
	t.Helper()
	savedHosts := core.NetworkTimeHosts
	core.NetworkTimeHosts = []string{"https://127.0.0.1:1"}
	t.Cleanup(func() { core.NetworkTimeHosts = savedHosts })

	u := focusTestUI(t)
	t.Cleanup(func() { waitGUIGoroutines(t) })
	u.showVaultPinDialog(t.TempDir()+"/нет.avlt", "Сервер 1", widget.NewButton("", nil), widget.NewLabel(""))
	over := u.win.Canvas().Overlays().List()
	if len(over) == 0 {
		t.Fatal("диалог пин-кода не открылся")
	}
	waitGUIGoroutines(t)
	return visibleTexts(over[len(over)-1])
}

// TestSaveKeyDialogRefusalGivesWholeRuleOnce — ОТКАЗ ГОВОРИТ ПРАВИЛО ЦЕЛИКОМ
// И ОДИН РАЗ (ревью UX-01).
//
// Раньше при отказе в строку состояния клалась ТА ЖЕ подсказка, что уже
// висит под полем: человек видел одну фразу дважды и терял остальную часть
// правила — исправив раскладку, получал второй отказ из-за длины.
func TestSaveKeyDialogRefusalGivesWholeRuleOnce(t *testing.T) {
	u := focusTestUI(t)
	u.offerSaveKey("vpn://не-настоящий", "Сервер 1", "")
	d := u.win.Canvas().Overlays().List()[0]

	// Пин не в той раскладке И короче двенадцати знаков: обе причины сразу.
	const short = "йцук1"
	passwordEntry(t, d, 0).SetText(short)
	passwordEntry(t, d, 1).SetText(short)
	buttonByText(t, d, "Сохранить").OnTapped()

	texts := visibleTexts(d)
	hints := 0
	rule := ""
	for _, s := range texts {
		if s == wantPinLayoutHint {
			hints++
		}
		if strings.HasPrefix(s, "Пин-код не принят: ") {
			rule = s
		}
	}
	// Ровно одна: общая всплывашка над парой полей пина — правило у них
	// одно. Вторая — это та же фраза, продублированная в строке состояния
	// вместо правила.
	if hints != 1 {
		t.Errorf("подсказка про раскладку показана %d раз(а), ожидалась 1 — общая всплывашка "+
			"над полями пина; лишняя означает, что отказ дублирует подсказку вместо правила: %q",
			hints, texts)
	}
	if rule == "" {
		t.Fatalf("после отказа человеку не сказано правило целиком. Видно: %q", texts)
	}
	if !strings.Contains(rule, "12 символов") {
		t.Errorf("в отказе нет требования длины: %q — исправив раскладку, человек получит "+
			"второй отказ", rule)
	}
	noEnteredCharsOnScreen(t, texts, short)
}

// TestLayoutHintDoesNotMoveButtons — ГЕОМЕТРИЯ НЕ ШЕВЕЛИТСЯ (ревью UX-01).
//
// Подсказка, скрытая через Hide(), выпадает из раскладки: она появляется — и
// всё, что ниже, едет вниз. Человек печатает пароль вслепую, а кнопка уезжает
// у него под пальцами. Место под подсказку резервируется заранее.
func TestLayoutHintDoesNotMoveButtons(t *testing.T) {
	u := focusTestUI(t)
	u.win.Resize(fyne.NewSize(900, 700))
	u.offerSaveKey("vpn://не-настоящий", "Сервер 1", "")
	d := u.win.Canvas().Overlays().List()[0]
	btn := buttonByText(t, d, "Сохранить")

	drv := fyne.CurrentApp().Driver()
	before := drv.AbsolutePositionForObject(btn)
	if before.Y == 0 {
		t.Fatal("проверка ПЕРЕСТАЛА ЧТО-ЛИБО ЗНАЧИТЬ: кнопка «Сохранить» не размещена на канве")
	}

	passwordEntry(t, d, 0).SetText(typedCyrillicPin)
	passwordEntry(t, d, 1).SetText(typedCyrillicPin)
	d.Refresh()

	if after := drv.AbsolutePositionForObject(btn); after != before {
		t.Errorf("после появления подсказок кнопка «Сохранить» переехала с %v на %v: "+
			"человек печатает пароль вслепую, а кнопка уходит у него под пальцами", before, after)
	}
}

// renderedTextBottom — нижняя граница НАРИСОВАННОГО текста подсказки,
// отсчитанная от верха самой всплывашки. Всплывашка для этого кладётся в
// настоящее окно и разворачивается на свой размер: только после раскладки
// Fyne расставляет строки переноса по своим местам.
func renderedTextBottom(t *testing.T, h *layoutHint) float32 {
	t.Helper()
	// У всплывашки меряется она сама, у резерва — его коробка: и там и там это
	// прямоугольник, в который текст обязан уложиться.
	var box fyne.CanvasObject = h.box
	if h.pop != nil {
		box = h.pop
	}
	w := test.NewWindow(box)
	t.Cleanup(w.Close)
	w.Resize(h.size)
	box.Resize(h.size)
	box.Refresh()

	drv := fyne.CurrentApp().Driver()
	top := drv.AbsolutePositionForObject(box).Y
	var bottom float32
	rows := 0
	walkVisible(box, func(o fyne.CanvasObject) {
		txt, ok := o.(*canvas.Text)
		if !ok || txt.Text == "" {
			return
		}
		rows++
		if b := drv.AbsolutePositionForObject(txt).Y + txt.Size().Height - top; b > bottom {
			bottom = b
		}
	})
	if rows == 0 {
		t.Fatal("проверка ПЕРЕСТАЛА ЧТО-ЛИБО ЗНАЧИТЬ: в подсказке не нарисовано ни одной строки")
	}
	return bottom
}

// TestLayoutHintSlotFitsText — ВСПЛЫВАШКА ДОСТАТОЧНА ДЛЯ СВОЕГО ТЕКСТА, а
// место в форме не занимает ни включённой, ни выключенной.
//
// Всплывашка не отодвигает содержимое, но обрезать текст она может ровно так
// же, как обрезал его маленький резерв: высота по-прежнему считается руками
// (wrappedLineCount), а подпись по-прежнему переносится по словам. Поэтому
// проверка «текст помещается» осталась дословно той же и меряется НАСТОЯЩЕЙ
// ВЁРСТКОЙ.
//
// ПОЧЕМУ НЕ MinSize (ревью QA-01). У подписи с переносом MinSize() равен
// одной строке ВНЕ ЗАВИСИМОСТИ от текста: сравнение с ним не могло покраснеть
// никогда, и подмена wrappedLineCount → return 1 (подсказка обрезается до
// трети фразы) оставляла прогон зелёным. Подпись кладётся в окно,
// разворачивается на размер всплывашки и спрашивается, докуда НА САМОМ ДЕЛЕ
// дотянулся нарисованный текст.
//
// Вторая половина — то, ради чего всплывашку и делали: MinSize коробки,
// которая стоит в форме, равен MinSize ОДНОГО ПОЛЯ ВВОДА и не зависит от
// того, показана подсказка или нет.
func TestLayoutHintSlotFitsText(t *testing.T) {
	a := test.NewApp()
	t.Cleanup(a.Quit)

	for _, c := range []struct {
		what  string
		text  string
		width float32
		float bool // true — всплывашка, false — зарезервированное место
	}{
		{"резерв под подсказку о пине в диалоге пин-кода", wantPinLayoutHint, pinDialogWidth, false},
		{"резерв под подсказку о пине в диалоге сохранения", wantPinLayoutHint, saveKeyDialWidth, false},
		{"всплывашка про ключ на экране подключения", wantKeyLayoutHint, connectFormWidth, true},
	} {
		t.Run(c.what, func(t *testing.T) {
			anchor := widget.NewEntry()
			var h *layoutHint
			var want fyne.Size
			if c.float {
				h = newLayoutHint(c.text, c.width, anchor)
				// Всплывашка обязана быть невидимкой для измерения: коробка,
				// стоящая в форме, меряется по ОДНОМУ полю ввода.
				want = anchor.MinSize()
			} else {
				h = newReservedHint(c.text, c.width)
				// Резерв обязан быть постоянным: место занято одинаково и с
				// подсказкой, и без неё.
				want = h.size
			}

			if off := h.box.MinSize(); off != want {
				t.Errorf("с выключенной подсказкой коробка занимает в форме %v, ожидалось %v", off, want)
			}
			h.setOn(true)
			if on := h.box.MinSize(); on != want {
				t.Errorf("с включённой подсказкой коробка занимает в форме %v вместо %v — "+
					"содержимое под ней поедет, кнопка уйдёт из-под пальца", on, want)
			}
			if bottom := renderedTextBottom(t, h); bottom > h.size.Height+0.5 {
				t.Errorf("нарисованный текст подсказки уходит на %v точек вниз, а отведено %v — "+
					"текст обрежется, человек прочтёт полфразы", bottom, h.size.Height)
			}
			h.setOn(false)
			if off := h.box.MinSize(); off != want {
				t.Errorf("после выключения коробка стала %v вместо %v", off, want)
			}
		})
	}
}

// TestForceEnglishLayoutThreeStates — ТРИ СОСТОЯНИЯ ПЕРЕКЛЮЧЕНИЯ, табличный
// разбор (ревью SEC-01 и QA-01).
//
// Подмена «default: return ""» компилируется и меняет поведение: человек
// уверен, что раскладка английская, хотя она не менялась. Раньше такая
// подмена оставляла весь прогон зелёным на всех трёх ОС — форма дефекта,
// которую мы ловим канарейками, а не «мелочь про сообщение».
//
// Проверка работает НА ЛЮБОЙ ОС, потому что подменяется сам системный вызов;
// живая Windows для неё не нужна.
func TestForceEnglishLayoutThreeStates(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want string
	}{
		{"переключили", nil, ""},
		{"ОС так не умеет", kbdlayout.ErrUnsupported, ""},
		{"не умеет, ошибка обёрнута", fmt.Errorf("слой GUI: %w", kbdlayout.ErrUnsupported), ""},
		{"пытались и не смогли", errors.New("user32: отказ"), wantLayoutSwitchFailed},
		{"неизвестная ошибка обёрнута", fmt.Errorf("внешний слой: %w", errors.New("отказ")), wantLayoutSwitchFailed},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			substituteForceEnglish(t, c.err)
			if got := forceEnglishLayout(); got != c.want {
				t.Errorf("forceEnglishLayout() = %q, ожидалось %q", got, c.want)
			}
		})
	}
}

// TestLayoutHintGoesOffWhenInputFixed — ПОДСКАЗКА ГАСНЕТ. Дыра, найденная
// QA-01: подмена, убирающая выключение подсказки, оставляла прогон зелёным, а
// человек видел бы вечную подсказку про раскладку на верном пине — то есть
// уверенное «не та раскладка» там, где раскладка верна.
func TestLayoutHintGoesOffWhenInputFixed(t *testing.T) {
	u := focusTestUI(t)
	u.offerSaveKey("vpn://не-настоящий", "Сервер 1", "")
	d := u.win.Canvas().Overlays().List()[0]

	pin := passwordEntry(t, d, 0)
	pin.SetText(typedCyrillicPin)
	if !hasText(visibleTexts(d), wantPinLayoutHint) {
		t.Fatal("проверка ПЕРЕСТАЛА ЧТО-ЛИБО ЗНАЧИТЬ: подсказка не появилась и гаснуть нечему")
	}

	pin.SetText(typedLatinPin) // человек переключил раскладку и набрал заново
	if texts := visibleTexts(d); hasText(texts, wantPinLayoutHint) {
		t.Errorf("пин исправлен на латиницу, а подсказка про раскладку осталась: %q", texts)
	}
}

// TestLayoutHintForPrefilledKeyField — ПОЛЕ, ЗАПОЛНЕННОЕ ДО ПОДКЛЮЧЕНИЯ
// ПОДСКАЗКИ. Вторая дыра QA-01: без завершающей сверки текущего текста
// подсказка молчала бы для ключа, попавшего в поле мимо нажатий на клавиши —
// из AMNEZIA_KEY или вставкой.
func TestLayoutHintForPrefilledKeyField(t *testing.T) {
	t.Setenv("AMNEZIA_KEY", "vpn://кириллицаВКлюче")

	u := focusTestUI(t)
	u.showConnectScreen("")
	content := u.win.Canvas().Content()

	if key := firstEntry(content); key == nil || key.Text == "" {
		t.Fatal("проверка ПЕРЕСТАЛА ЧТО-ЛИБО ЗНАЧИТЬ: поле ключа не заполнено из окружения")
	}
	if texts := visibleTexts(content); !hasText(texts, wantKeyLayoutHint) {
		t.Errorf("ключ попал в поле мимо нажатий клавиш и содержит кириллицу, "+
			"а подсказки нет: %q", texts)
	}
}

// TestVisibleTextsIgnoresHiddenText — КАНАРЕЙКА НА САМ ОБХОД (ревью SEC-01 и
// QA-01).
//
// Вся проверка «что человек видит на экране» стоит на walkVisible. Наивный
// обход — тот, что смотрит Visible() только у самого объекта и всё равно
// спускается внутрь скрытого, — вытаскивал бы текст спрятанных подписей на
// свет: widget.Label рисует себя вложенным RichText, и у СКРЫТОЙ подписи
// внутренний текст «видим» сам по себе. Такая подмена компилируется и
// оставляла бы зелёными все тесты подсказок сразу, потому что подсказку они
// нашли бы и в скрытом виде.
//
// Четыре случая в одном дереве, как просил SEC-01: скрытая подпись, скрытый
// canvas.Text, подпись внутри скрытого контейнера и один видимый canvas.Text.
// Вернуться должен ровно последний.
func TestVisibleTextsIgnoresHiddenText(t *testing.T) {
	a := test.NewApp()
	t.Cleanup(a.Quit)

	hiddenLabel := widget.NewLabel("скрытая-подпись")
	hiddenLabel.Hide()
	hiddenText := canvas.NewText("скрытый-canvas-текст", color.Black)
	hiddenText.Hide()
	inHiddenBox := widget.NewLabel("подпись-внутри-скрытого-контейнера")
	hiddenBox := container.NewVBox(inHiddenBox)
	hiddenBox.Hide()
	visible := canvas.NewText("видимый-canvas-текст", color.Black)

	root := container.NewVBox(hiddenLabel, hiddenText, hiddenBox, visible)
	w := test.NewWindow(root)
	t.Cleanup(w.Close)
	w.Resize(fyne.NewSize(400, 300))

	got := visibleTexts(root)
	if len(got) != 1 || got[0] != "видимый-canvas-текст" {
		t.Fatalf("видимыми признаны %q, а видима на экране ровно одна подпись — "+
			"обход заглядывает внутрь скрытого, и любая проверка «что видит человек» "+
			"на нём врёт", got)
	}
}
