package main

import (
	"testing"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/test"
	"fyne.io/fyne/v2/widget"

	"amnezia-admin/core"
)

// Фокус ввода в диалогах и на экранах с полями (жалоба владельца 22.09.2026:
// «ткнул на сервер и хочу начать вводить пароль, но мне надо еще ткнуть в это
// поле»). Проверяется headless: test.NewApp даёт канву в памяти, и
// Canvas().Focused() возвращает тот объект, в который реально уйдёт набор.
//
// ГДЕ ФОКУС НЕ СТАВИТСЯ И ПОЧЕМУ (решено осознанно, не забыто):
//   - диалог удаления (deleteSelected) — поля ввода в нём нет вовсе, и
//     первое, что человек обязан увидеть, — карточка активности клиента
//     перед необратимым действием, а не курсор;
//   - диалоги отключения/включения, перевыпуска, «Конфиг готов», окно
//     изменений, предупреждение о гонке, диалоги ключа сервера — полей ввода
//     нет, фокусировать нечего;
//   - сама таблица пользователей — фокус ввода отобрал бы клавиатуру у
//     прокрутки списка.

// waitGUIGoroutines ждёт завершения фоновых операций goSafe — с ТАЙМАУТОМ.
//
// Ожидание без таймаута было бы ловушкой: в программе есть goSafe, который
// живёт, пока идёт обратный отсчёт блокировки (тикер в showVaultPinDialog), и
// прогон повис бы молча на 10 минут до общего таймаута go test. Сейчас в этом
// тесте отсчёт не запускается (онлайн-время не получено — блокировке неоткуда
// взяться), но полагаться на это молча нельзя.
func waitGUIGoroutines(t *testing.T) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		guiGoroutines.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Errorf("фоновые операции goSafe не завершились за 30 с — ожидание прервано, " +
			"чтобы прогон не повис; проверьте, не остался ли работать тикер")
	}
}

// focusedIs — фокус канвы указывает ровно на этот виджет.
func focusedIs(t *testing.T, c fyne.Canvas, want fyne.Focusable, what string) {
	t.Helper()
	got := c.Focused()
	if got == nil {
		t.Errorf("%s: курсор никуда не поставлен — человеку придётся лишний раз щёлкать в поле", what)
		return
	}
	if got != want {
		t.Errorf("%s: курсор стоит в %T, а ожидался %T", what, got, want)
	}
}

// focusTestUI — ui с окном и пустым списком контейнеров; сети не касается.
func focusTestUI(t *testing.T) *ui {
	t.Helper()
	a := test.NewApp()
	t.Cleanup(a.Quit)
	w := test.NewWindow(nil)
	t.Cleanup(w.Close)
	return &ui{win: w, selectedRow: -1}
}

// firstEntry — первое поле ввода в дереве объектов (в порядке обхода).
func firstEntry(o fyne.CanvasObject) *widget.Entry {
	var found *widget.Entry
	walkObjects(o, func(x fyne.CanvasObject) {
		if e, ok := x.(*widget.Entry); ok && found == nil {
			found = e
		}
	})
	return found
}

// TestConnectScreenFocusesKeyEntry — экран подключения: курсор в поле ключа,
// вставлять ключ можно сразу.
func TestConnectScreenFocusesKeyEntry(t *testing.T) {
	u := focusTestUI(t)
	u.showConnectScreen("")
	want := firstEntry(u.win.Canvas().Content())
	if want == nil {
		t.Fatal("проверка ПЕРЕСТАЛА ЧТО-ЛИБО ЗНАЧИТЬ: на экране подключения нет поля ввода")
	}
	focusedIs(t, u.win.Canvas(), want, "экран подключения")
}

// TestPinDialogFocusesPinEntry — ЖАЛОБА ВЛАДЕЛЬЦА ДОСЛОВНО: ткнул в
// сохранённый сервер — пин вводится сразу, без второго щелчка.
func TestPinDialogFocusesPinEntry(t *testing.T) {
	// Диалог пин-кода при открытии запрашивает доверенное онлайн-время.
	// Тест НЕ ходит в сеть: пул хостов на время теста подменён на заведомо
	// закрытый порт локальной петли.
	savedHosts := core.NetworkTimeHosts
	core.NetworkTimeHosts = []string{"https://127.0.0.1:1"}
	t.Cleanup(func() { core.NetworkTimeHosts = savedHosts })

	u := focusTestUI(t)
	// Диалог при открытии уходит в фон за онлайн-временем. Ждём завершения
	// фоновой операции ДО проверок — иначе её запись в виджеты и чтение тех
	// же виджетов тестом идут без синхронизации, и -race справедливо
	// показывает гонку. Ждём по счётчику goSafe, а не временем.
	t.Cleanup(func() { waitGUIGoroutines(t) })
	u.showVaultPinDialog(t.TempDir()+"/нет.avlt", "Сервер 1", widget.NewButton("", nil), widget.NewLabel(""))

	over := u.win.Canvas().Overlays().List()
	if len(over) == 0 {
		t.Fatal("диалог пин-кода не открылся — проверять нечего")
	}
	waitGUIGoroutines(t) // фоновый запрос онлайн-времени завершён
	want := firstEntry(over[len(over)-1])
	if want == nil {
		t.Fatal("проверка ПЕРЕСТАЛА ЧТО-ЛИБО ЗНАЧИТЬ: в диалоге пин-кода нет поля ввода")
	}
	if !want.Password {
		t.Errorf("первое поле диалога пин-кода не парольное (%T) — похоже, фокус ставится не туда", want)
	}
	focusedIs(t, u.win.Canvas(), want, "диалог «Введите пин-код»")

}

// TestSaveKeyDialogFocusesLabelEntry — диалог сохранения ключа: курсор в
// первом поле формы (метка), дальше Enter ведёт метка → пин → повтор.
func TestSaveKeyDialogFocusesLabelEntry(t *testing.T) {
	u := focusTestUI(t)
	u.offerSaveKey("vpn://не-настоящий", "Сервер 1", "")
	over := u.win.Canvas().Overlays().List()
	if len(over) == 0 {
		t.Fatal("диалог сохранения ключа не открылся")
	}
	want := firstEntry(over[len(over)-1])
	if want == nil {
		t.Fatal("проверка ПЕРЕСТАЛА ЧТО-ЛИБО ЗНАЧИТЬ: в диалоге сохранения ключа нет поля ввода")
	}
	focusedIs(t, u.win.Canvas(), want, "диалог «Сохранить ключ?»")
}

// TestAddDialogFocusesNameEntry — «Новый пользователь»: имя вводится сразу.
func TestAddDialogFocusesNameEntry(t *testing.T) {
	u := focusTestUI(t)
	u.cur = &core.Container{Proto: "awg", Managed: true}
	u.status = widget.NewLabel("")
	u.addDialog()
	over := u.win.Canvas().Overlays().List()
	if len(over) == 0 {
		t.Fatal("диалог создания пользователя не открылся")
	}
	want := firstEntry(over[len(over)-1])
	if want == nil {
		t.Fatal("проверка ПЕРЕСТАЛА ЧТО-ЛИБО ЗНАЧИТЬ: в диалоге создания нет поля ввода")
	}
	focusedIs(t, u.win.Canvas(), want, "диалог «Новый пользователь»")
}

// TestRenameDialogFocusesNameEntry — «Переименовать»: новое имя вводится
// сразу, поле уже содержит прежнее.
func TestRenameDialogFocusesNameEntry(t *testing.T) {
	u := focusTestUI(t)
	u.cur = &core.Container{Proto: "awg", Managed: true}
	u.status = widget.NewLabel("")
	u.canManage = true
	u.clients = []core.ClientEntry{{ClientID: "id-1", UserData: map[string]any{"clientName": "Ноутбук"}}}
	u.selectedRow = 0
	u.renameSelected()
	over := u.win.Canvas().Overlays().List()
	if len(over) == 0 {
		t.Fatal("диалог переименования не открылся")
	}
	want := firstEntry(over[len(over)-1])
	if want == nil {
		t.Fatal("проверка ПЕРЕСТАЛА ЧТО-ЛИБО ЗНАЧИТЬ: в диалоге переименования нет поля ввода")
	}
	if want.Text != "Ноутбук" {
		t.Errorf("в поле переименования %q вместо прежнего имени — фокус ставится не в то поле", want.Text)
	}
	focusedIs(t, u.win.Canvas(), want, "диалог «Переименовать»")
	// Курсор в КОНЦЕ имени (ревью UX-01): иначе человек открывает диалог,
	// печатает и получает «НовоеИмяСтароеИмя».
	if got, end := want.CursorColumn, len([]rune("Ноутбук")); got != end {
		t.Errorf("курсор в поле переименования стоит на позиции %d, а имя длиной %d знаков: "+
			"набранное человеком имя припишется к старому спереди", got, end)
	}
}
