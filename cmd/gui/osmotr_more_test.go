package main

// ДИАЛОГИ, ДОБАВЛЕННЫЕ В ОСМОТР 29.09.2026 (правка координатора к заданию
// ДЕФЕКТЫ-ВИДА-И-12): минимум окна, выведенный не по всем диалогам, — не
// минимум. Здесь — все диалоги программы, которых в osmotrForms не было.

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/test"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"amnezia-admin/core"
	"amnezia-admin/internal/fakesrv"
	"amnezia-admin/internal/guiview"
)

// scenePopup — общий хвост: верхний диалог, кадр показа.
func scenePopup(t *testing.T, u *ui) osmotrScene {
	c := u.win.Canvas()
	pop := topPopup(t, c)
	return osmotrScene{root: pop, canvas: c, mins: osmotrFrame(pop, nil)}
}

// osmotrNewUser — конфиг нового клиента, как его вернул бы Apply.
func osmotrNewUser() *core.NewUser {
	return &core.NewUser{Name: "Телефон Анны", IP: "10.8.1.5",
		Config: "[Interface]\nPrivateKey = не-настоящий\nAddress = 10.8.1.5/32\n"}
}

// configDirEnv — каталог данных пользователя ОС для теста (не настоящий).
// Путь печатается в диалоге («Конфиг сохранён: …») и переносится; временный
// каталог на Windows, Linux и macOS разной длины, и без выравнивания число
// строк и замер зависели бы от ОС (урок PR #20). Поэтому временный каталог
// добивается ДО ОДНОЙ ШИРИНЫ ТЕКСТА: подпись занимает osmotrPathWidth т. —
// середина третьей строки при ширине строки ~440 т., так что разница в
// ширине отдельных знаков числа строк не меняет. Ширина проверяется.
const osmotrPathWidth = 1000

func configDirEnv(t *testing.T) {
	t.Helper()
	base, err := os.MkdirTemp("", "osm")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(base) })
	set := func(b string) float32 {
		t.Setenv("LOCALAPPDATA", b)
		t.Setenv("XDG_CONFIG_HOME", b)
		t.Setenv("HOME", b)
		d, err := core.UserConfigsDir()
		if err != nil {
			t.Fatalf("каталог данных: %v", err)
		}
		abs := filepath.Join(d, core.SanitizeName(osmotrNewUser().Name)+".conf")
		osmotrSavedLabel = firstLine("Конфиг сохранён: " + abs)
		return fyne.MeasureText("Конфиг сохранён: "+abs, theme.TextSize(), fyne.TextStyle{}).Width
	}
	pad := base
	for n := 1; set(pad) < osmotrPathWidth; n++ {
		if n > 200 {
			t.Fatal("путь не добивается до нужной ширины")
		}
		pad = filepath.Join(base, padName(n))
	}
	if w := set(pad); w < osmotrPathWidth || w > osmotrPathWidth+20 {
		t.Fatalf("ширина подписи с путём %.1f, ожидалось %d..%d", w, osmotrPathWidth, osmotrPathWidth+20)
	}
	if err := os.MkdirAll(pad, 0o700); err != nil {
		t.Fatal(err)
	}
}

func padName(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = 'x'
	}
	return string(b)
}

func openConfig(state string) func(t *testing.T, u *ui, sized func()) osmotrScene {
	return func(t *testing.T, u *ui, sized func()) osmotrScene {
		osmotrMain(u)
		sized()
		switch state {
		case "сохранён":
			configDirEnv(t)
		case "отказ":
			// Каталог данных не определяется ни на одной ОС: относительный
			// путь отвергают и core (Windows), и os.UserConfigDir.
			t.Setenv("LOCALAPPDATA", "rel")
			t.Setenv("XDG_CONFIG_HOME", "rel")
			t.Setenv("HOME", "")
		}
		u.showConfigDialog(osmotrNewUser(), "создан")
		c := u.win.Canvas()
		pop := topPopup(t, c)
		mins := osmotrFrame(pop, nil)
		if state != "" {
			test.Tap(buttonByText(t, pop, "Сохранить .conf"))
		}
		// Мерим диалог конфига, даже если поверх него окно ошибки.
		return osmotrScene{root: pop, canvas: c, mins: mins}
	}
}

// openDiff — окно изменений по настоящему плану удаления на fakesrv.
func openDiff(t *testing.T, u *ui, sized func()) osmotrScene {
	osmotrMain(u)
	sized()
	srv := fakesrv.New()
	sess := core.NewSessionWithRunner(srv, &core.ServerCreds{Host: "203.0.113.10", User: "root", Password: "x"})
	c := &core.Container{Name: "amnezia-awg", Dir: "/opt/amnezia/awg", Proto: "AmneziaWG", Managed: true}
	cl, err := sess.LoadClients(c)
	if err != nil || len(cl) == 0 {
		t.Fatalf("fakesrv: %v", err)
	}
	plan, err := sess.PlanDelete(c, cl[0].ClientID)
	if err != nil {
		t.Fatalf("PlanDelete: %v", err)
	}
	u.showDiffWindow("удаление \""+cl[0].Name()+"\"", plan, nil)
	return scenePopup(t, u)
}

func openRace(t *testing.T, u *ui, sized func()) osmotrScene {
	osmotrMain(u)
	sized()
	u.warnFreq = guiview.WarnEveryTime
	u.confirmRaceWarning(guiview.OpDeleteUser, func() {})
	return scenePopup(t, u)
}

const osmotrFP = "SHA256:nThbg6kXUpJWGl7E1IGOCspRomTxdCARLviKw6E5SY8"

func openHostKeyPrompt(t *testing.T, u *ui, sized func()) osmotrScene {
	u.showConnectScreen("")
	sized()
	u.showHostKeyPrompt("203.0.113.10:22", osmotrFP, make(chan bool, 1))
	return scenePopup(t, u)
}

func openHostKeyChanged(vault bool) func(t *testing.T, u *ui, sized func()) osmotrScene {
	return func(t *testing.T, u *ui, sized func()) osmotrScene {
		u.showConnectScreen("")
		sized()
		var vc *vaultCtx
		if vault {
			pin := "x"
			vc = &vaultCtx{pin: &pin}
		}
		u.hostKeyChangedDialog("203.0.113.10:22", osmotrFP, "SHA256:AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqK",
			"known_hosts", vc, widget.NewButton("", nil), widget.NewLabel(""))
		return scenePopup(t, u)
	}
}

func openForgetHostKey(t *testing.T, u *ui, sized func()) osmotrScene {
	u.showConnectScreen("")
	sized()
	pin := "x"
	u.confirmForgetHostKey("203.0.113.10:22", "known_hosts", &vaultCtx{pin: &pin},
		widget.NewButton("", nil), widget.NewLabel(""))
	return scenePopup(t, u)
}

func openInfo(t *testing.T, u *ui, sized func()) osmotrScene {
	osmotrMain(u)
	sized()
	u.selectedRow = -1
	u.deleteSelected() // боевой путь: «Не выбран пользователь»
	return scenePopup(t, u)
}

func openError(t *testing.T, u *ui, sized func()) osmotrScene {
	osmotrMain(u)
	sized()
	dialog.ShowError(errors.New("план устарел: сервер изменился, пока окно было открыто. Закройте окно и повторите операцию"), u.win)
	return scenePopup(t, u)
}

// osmotrSavedLabel — как прибор сокращает подпись «Конфиг сохранён: <путь>»
// в этом прогоне. Путь начинается с временного каталога ОС, поэтому в описи и
// в строках находок он заменяется на osmotrSavedToken (runOsmotr).
var osmotrSavedLabel string

const osmotrSavedToken = "Конфиг сохранён: <путь>"

// Описи новых форм (прогон 29.09.2026, сверены с main.go и снимками).
var (
	invConfigBase = []string{
		"подпись:Конфиг готов",
		"подпись:" + firstLine(`Пользователь "Телефон Анны" создан (IP 10.8.1.5).`),
		"изображение:", // QR
		"подпись:" + firstLine("Отсканируйте QR в приложении AmneziaWG на телефоне или импортируйте файл."),
		"кнопка:Сохранить .conf", "кнопка:Закрыть",
	}
	invActionTail = []string{"кнопка:Показать изменения", "подпись:", "кнопка:Отмена"}
	// fyneIconOverflow — значок стандартного диалога Fyne (dialog.ShowError,
	// ShowInformation) — большая бледная картинка ЗА текстом в правом верхнем
	// углу, по замыслу Fyne выходит за рамку на 4 т. Наша разметка тут ни
	// при чём; разрешено поимённо полной строкой, как любая находка.
	fyneIconOverflow = osmotrKnown{id: "ЗАМЫСЕЛ FYNE (значок стандартного диалога за текстом)",
		size: "", match: "изображение «»: сверху 4.0, справа 4.0"}
)

// knownD6 — Д6, найден осмотром 29.09.2026 (правка координатора): диалог
// «Конфиг готов» ПОСЛЕ сохранения (путь, «Скопировать путь», подсказка о
// новом месте) и ПОСЛЕ отказа сохранения (совет) выше стартового окна
// (620 т.): ему нужно 756 и 659 т. РАЗВИЛКА ВЛАДЕЛЬЦУ — уменьшить диалог или
// поднять минимум окна выше стартовой высоты; молча не решено.
func knownD6(size, match string) osmotrKnown {
	return osmotrKnown{id: "ИЗВЕСТНЫЙ ДЕФЕКТ Д6 (диалог «Конфиг готов» после сохранения/отказа выше окна; развилка владельцу)",
		size: size, match: match}
}

var moreForms = []osmotrForm{
	{name: "(в) вкл/выкл", open: openAction(func(u *ui) { u.toggleSelected() }), width: 412,
		inventory: cat([]string{"подпись:Отключить пользователя?", "подпись:Пользователь: Ноутбук…", "кнопка:Да"}, invActionTail)},
	{name: "(в) перевыпуск", open: openAction(func(u *ui) { u.regenerateSelected() }), width: 452,
		inventory: cat([]string{"подпись:Перевыпустить конфиг?", "подпись:Перевыпустить конфиг для Ноутбук? Старый…", "кнопка:Перевыпустить"}, invActionTail)},
	{name: "(д) конфиг готов", open: openConfig(""), width: 472,
		inventory: cat(invConfigBase, []string{"подпись:"})},
	{name: "(д) конфиг готов, сохранён", open: openConfig("сохранён"), width: 472,
		inventory: cat(invConfigBase, []string{"подпись:" + osmotrSavedToken, "кнопка:Скопировать путь",
			"подпись:" + firstLine(core.FirstSaveHint)}),
		known: []osmotrKnown{
			knownD6("стартовый", "подпись «Это новое место. Прежние версии сохранял…»: снизу 84.0"),
			knownD6("стартовый", "кнопка «Скопировать путь» × кнопка «Закрыть»: 79x21 = 1635 т²"),
			knownD6("стартовый", "подпись «Это новое место. Прежние версии сохранял…» × кнопка «Закрыть»: 79x11 = 902 т²"),
			knownD6("минимальный", "подпись «"+osmotrSavedToken+"»: снизу 5.6"),
			knownD6("минимальный", "кнопка «Скопировать путь»: снизу 45.6"),
			knownD6("минимальный", "подпись «Это новое место. Прежние версии сохранял…»: снизу 84.7"),
			knownD6("минимальный", "подпись «"+osmotrSavedToken+"» × кнопка «Закрыть»: 79x36 = 2855 т²"),
			knownD6("минимальный", "подпись «Это новое место. Прежние версии сохранял…»: мин 16x111, дано 440x35"),
		}},
	{name: "(д) конфиг готов, отказ сохранения", open: openConfig("отказ"), width: 472,
		inventory: cat(invConfigBase, []string{"подпись:", "подпись:" + firstLine(core.SaveFailedAdvice("Телефон Анны"))}),
		known: []osmotrKnown{
			knownD6("стартовый", "подпись «Пользователь \"Телефон Анны\" на сервере с…» × кнопка «Закрыть»: 79x36 = 2855 т²"),
			knownD6("минимальный", "подпись «Пользователь \"Телефон Анны\" на сервере с…» × кнопка «Закрыть»: 79x32 = 2507 т²"),
			knownD6("минимальный", "подпись «Пользователь \"Телефон Анны\" на сервере с…»: мин 16x111, дано 440x35"),
		}},
	{name: "(д) изменения перед применением", open: openDiff, width: 692,
		inventory: []string{"подпись:" + firstLine(`Изменения перед применением: удаление "Alice"`),
			"подпись:/opt/amnezia/awg/wg0.conf", "прокрутка:", "подпись:/opt/amnezia/awg/clientsTable", "прокрутка:",
			"кнопка:Применить", "подпись:", "кнопка:Закрыть"}},
	{name: "(д) предупреждение о гонке", open: openRace, width: 552,
		inventory: []string{"подпись:" + firstLine(guiview.WarningTitle()), "подпись:" + firstLine(guiview.WarningBody()),
			"кнопка:" + guiview.WarnContinueLabel(), "кнопка:" + guiview.WarnCancelLabel()}},
	{name: "(е) неизвестный сервер", open: openHostKeyPrompt, width: 472,
		inventory: []string{"подпись:Неизвестный сервер", "подпись:Сервер: 203.0.113.10:22…",
			"кнопка:Доверять и запомнить", "кнопка:Отмена"}},
	{name: "(е) ключ сервера изменился", open: openHostKeyChanged(false), width: 472,
		inventory: []string{"подпись:Ключ сервера изменился", "подпись:Сервер 203.0.113.10:22.…", "кнопка:Закрыть"}},
	{name: "(е) ключ сервера изменился, из хранилища", open: openHostKeyChanged(true), width: 472,
		inventory: []string{"подпись:Ключ сервера изменился", "подпись:Сервер 203.0.113.10:22.…",
			"кнопка:Забыть ключ сервера…", "кнопка:Закрыть"}},
	// Без d.Resize: Fyne даёт диалогу ширину по заголовку и кнопкам (229 т.),
	// ширину рамки не проверяем — заказанной нет.
	{name: "(е) забыть ключ сервера", open: openForgetHostKey,
		inventory: []string{"подпись:Забыть ключ сервера?", "подпись:Забыть ключ сервера 203.0.113.10:22? Ути…",
			"кнопка:Забыть", "кнопка:Отмена"}},
	{name: "(ж) не выбран пользователь", open: openInfo,
		inventory:  []string{"подпись:Не выбран пользователь", "подпись:Выберите строку в таблице.", "изображение:", "кнопка:ОК"},
		mayOverlap: []string{"|Не выбран пользователь", "|Выберите строку в таблице."},
		known:      []osmotrKnown{fyneIconOverflow}},
	{name: "(ж) ошибка", open: openError,
		inventory:  []string{"подпись:Ошибка", "подпись:План устарел: сервер изменился, пока окн…", "изображение:", "кнопка:ОК"},
		mayOverlap: []string{"|План устарел: сервер изменился, пока окн…"},
		known:      []osmotrKnown{fyneIconOverflow}},
}

func init() { osmotrForms = append(osmotrForms, moreForms...) }
