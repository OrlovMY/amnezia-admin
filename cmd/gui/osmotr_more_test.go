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

// configDirEnv — каталог данных пользователя ОС для теста (не настоящий),
// по МОДЕЛИ пути одной из трёх ОС CI.
//
// ПОЧЕМУ МОДЕЛИ, А НЕ ВЫРАВНИВАНИЕ (ревью QA-01, урок PR #20 в третий раз).
// Прежняя редакция добивала путь до 1000 т. и падала, если он шире 1020, —
// а на macOS базовый путь (/var/folders/…/T/osm…/Library/Application
// Support/…) уже 1133 т., да ещё с пробелом, который меняет перенос по
// словам. Выровнять путь на трёх ОС нельзя: хвост каталога данных у каждой
// ОС свой. И не нужно: после Д6 путь живёт ВНУТРИ прокрутки, прибор мерит её
// одним атомом, и ни одна находка ворот от числа строк пути не зависит.
// Поэтому вместо выравнивания — худший случай по умолчанию (модель macOS:
// самый широкий путь, с пробелом) и отдельный тест
// TestConfigSavedAcrossOSPathModels, который гоняет ворота и боевое правило
// мыши на всех трёх моделях на ЛЮБОЙ ОС.
type osmotrPathModel struct {
	name    string
	sub     string  // подкаталоги поверх временного, как у этой ОС
	atLeast float32 // ширина подписи «Конфиг сохранён: <путь>» не меньше (т.)
}

var (
	pathLinux = osmotrPathModel{"Linux (/tmp/osm…)", "", 0}
	// Windows runner: C:\Users\runneradmin\AppData\Local\Temp\osm… — 883 т.
	pathWindows = osmotrPathModel{"Windows runner", "", 883}
	// macOS runner: /var/folders/xx/…/T/osm…/Library/Application Support/… —
	// 1133 т., с пробелом в «Application Support».
	pathMacOS = osmotrPathModel{"macOS runner", filepath.Join("folders", "xx", "yy", "T", "Library", "Application Support"), 1133}
)

// osmotrPath — модель для форм прибора; по умолчанию худшая.
var osmotrPath = pathMacOS

func configDirEnv(t *testing.T) (width float32) {
	t.Helper()
	base, err := os.MkdirTemp("", "osm")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(base) })
	m := osmotrPath
	set := func(b string) float32 {
		t.Setenv("LOCALAPPDATA", b)
		t.Setenv("XDG_CONFIG_HOME", b)
		t.Setenv("HOME", b)
		d, err := core.UserConfigsDir()
		if err != nil {
			t.Fatalf("каталог данных: %v", err)
		}
		abs := filepath.Join(d, core.SanitizeName(osmotrNewUser().Name)+".conf")
		return fyne.MeasureText("Конфиг сохранён: "+abs, theme.TextSize(), fyne.TextStyle{}).Width
	}
	dir := filepath.Join(base, m.sub)
	for n := 1; set(dir) < m.atLeast; n++ {
		if n > 300 {
			t.Fatal("путь не добивается до ширины модели")
		}
		dir = filepath.Join(base, m.sub, padName(n))
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return set(dir)
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
		case "отказ, длинный путь":
			// каталог данных — длинный абсолютный путь (модель macOS), а на
			// месте каталога конфигураций — ФАЙЛ: MkdirAll отвечает ошибкой ОС
			// с полным путём (3–4 строки в окне)
			configDirEnv(t)
			d, err := core.UserConfigsDir()
			if err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(filepath.Dir(d), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(d, []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
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
		// Сохранение — само, при показе (задача 01.10.2026): нажимать нечего.
		// state "" — каталог по умолчанию тестов (TestMain).
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

// Описи новых форм (прогон 29.09.2026, сверены с main.go и снимками).
var (
	// «Конфиг готов» после Д6: текст и QR — в прокрутке (прибор мерит её как
	// один атом «прокрутка» и внутрь не идёт — названная граница, её
	// содержимое смотрит снимок), кнопки действия — вне её.
	invConfigBase = []string{
		"подпись:Конфиг готов", "изображение:", "прокрутка:", "кнопка:Сохранить ещё в…", "кнопка:Закрыть",
	}
	invActionTail = []string{"кнопка:Показать изменения", "подпись:", "кнопка:Отмена"}
	// fyneIconOverflow — значок стандартного диалога Fyne (dialog.ShowError,
	// ShowInformation) — большая бледная картинка ЗА текстом в правом верхнем
	// углу, по замыслу Fyne выходит за рамку на 4 т. Наша разметка тут ни
	// при чём; разрешено поимённо полной строкой, как любая находка.
	fyneIconOverflow = osmotrKnown{id: "ЗАМЫСЕЛ FYNE (значок стандартного диалога за текстом)",
		size: "", match: "изображение «»: сверху 4.0, справа 4.0"}
)

var moreForms = []osmotrForm{
	{name: "(в) вкл/выкл", open: openAction(func(u *ui) { u.toggleSelected() }), width: 412,
		inventory: cat([]string{"подпись:Отключить пользователя?", "подпись:Пользователь: Ноутбук…", "кнопка:Да"}, invActionTail)},
	// Д3–Д4 НА ДЕЛЕ (ревью UX-01): строка «Телефон Анны» с ключом из 43 «Q»
	// — широкие знаки, без пробелов. Снимки этих форм — доказательство, что
	// ключ переносится и его конец виден.
	{name: "(в) вкл/выкл, ключ из «Q»", open: openActionRow(1, func(u *ui) { u.toggleSelected() }), width: 412,
		inventory: cat([]string{"подпись:Отключить пользователя?", "подпись:Пользователь: Телефон Анны…", "кнопка:Да"}, invActionTail)},
	{name: "(в) удаление, ключ из «Q», статистики нет", open: openDeleteRow(1), width: 452,
		inventory: []string{"подпись:Удалить пользователя?", "подпись:Имя: Телефон Анны…",
			"подпись:Не удалось получить данные о подключения…",
			"кнопка:Удалить", "кнопка:Показать изменения", "подпись:", "кнопка:Отмена"}},
	{name: "(в) перевыпуск", open: openAction(func(u *ui) { u.regenerateSelected() }), width: 452,
		inventory: cat([]string{"подпись:Перевыпустить конфиг?",
			"подпись:" + firstLine("Перевыпустить конфиг пользователя «Ноутбук»? Старый конфиг перестанет работать."),
			"кнопка:Перевыпустить"}, invActionTail)},
	// Д6 закрыт прокруткой (решение владельца 29.09.2026): разрешения
	// knownD6 сняты, прибор показал их НЕИСПОЛЬЗОВАННЫМИ.
	{name: "(д) конфиг готов", open: openConfig(""), width: 472, inventory: cat(invConfigBase, []string{"кнопка:Скопировать путь"})},
	{name: "(д) конфиг готов, сохранён", open: openConfig("сохранён"), width: 472,
		inventory: cat(invConfigBase, []string{"кнопка:Скопировать путь"})},
	{name: "(д) конфиг готов, отказ сохранения", open: openConfig("отказ"), width: 472, inventory: invConfigBase},
	{name: "(д) конфиг готов, отказ с длинным путём", open: openConfig("отказ, длинный путь"), width: 472, inventory: invConfigBase},
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
	// Три абзаца, рамка 472 (ревью UX-01, 29.09.2026; было 229 т. столбиком).
	{name: "(е) забыть ключ сервера", open: openForgetHostKey, width: 472,
		inventory: []string{"подпись:Забыть ключ сервера?", "подпись:Забыть ключ сервера 203.0.113.10:22?",
			"подпись:" + firstLine("Будет стёрт сохранённый отпечаток — в хранилище и в known_hosts."),
			"подпись:" + firstLine("Делайте это, только если сами переустанавливали сервер."),
			"кнопка:Забыть", "кнопка:Отмена"}},
	{name: "(ж) не выбран пользователь", open: openInfo,
		inventory: []string{"подпись:Не выбран пользователь", "подпись:Выберите строку в таблице.", "изображение:", "кнопка:" + fyneRoleOK},
		// Значок Fyne лежит за текстом по замыслу; с кнопкой OK он
		// пересекается, если слово кнопки на языке системы длиннее
		// «ОК»/«OK» (доказательство — osmotr_lang_test.go, «Okidoki»).
		mayOverlap: []string{"|Не выбран пользователь", "|Выберите строку в таблице.", "|" + fyneRoleOK},
		known:      []osmotrKnown{fyneIconOverflow}, fyneStd: true},
	{name: "(ж) ошибка", open: openError,
		inventory:  []string{"подпись:" + fyneRoleError, "подпись:План устарел: сервер изменился, пока окн…", "изображение:", "кнопка:" + fyneRoleOK},
		mayOverlap: []string{"|План устарел: сервер изменился, пока окн…", "|" + fyneRoleOK},
		known:      []osmotrKnown{fyneIconOverflow}, fyneStd: true},
}

func init() { osmotrForms = append(osmotrForms, moreForms...) }
