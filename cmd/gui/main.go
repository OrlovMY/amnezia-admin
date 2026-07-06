// amnezia-admin-gui — графическая оболочка для администрирования сервера Amnezia VPN.
// Вся логика — в пакете core, здесь только Fyne UI.
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"image/color"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"amnezia-admin/core"
)

type ui struct {
	win        fyne.Window
	sess       *core.Session
	containers []core.Container
	cur        *core.Container

	clients    []core.ClientEntry
	handshakes map[string]string
	peerStats  map[string]core.PeerStat

	table       *widget.Table
	status      *widget.Label
	protoSelect *widget.Select
	selectedRow int

	// сортировка таблицы пользователей по клику на заголовок колонки;
	// primary — активная (со стрелкой в заголовке), secondary — tie-breaker
	// от предыдущего primary. Персистентно (ui.json рядом с exe), глобально
	// для приложения (не per-protocol).
	sortPrimary      core.SortColumn
	sortPrimaryDir   core.SortDir
	sortSecondary    core.SortColumn
	sortSecondaryDir core.SortDir
}

func main() {
	defer logPanic()
	a := app.New()
	w := a.NewWindow("Amnezia Admin")
	w.Resize(fyne.NewSize(980, 620))

	u := &ui{win: w, selectedRow: -1}
	u.sortPrimary, u.sortPrimaryDir, u.sortSecondary, u.sortSecondaryDir = loadSortState()
	w.SetContent(u.connectScreen())
	w.ShowAndRun()
}

// logPanic пишет панику в crash.log рядом с exe — окно без консоли, иначе падение невидимо
func logPanic() {
	if r := recover(); r != nil {
		dir := filepath.Dir(os.Args[0])
		msg := fmt.Sprintf("%s\npanic: %v\n\n%s\n", time.Now().Format(time.RFC3339), r, debug.Stack())
		os.WriteFile(filepath.Join(dir, "crash.log"), []byte(msg), 0644)
		panic(r)
	}
}

// goSafe запускает фоновую операцию с логированием паники
func goSafe(fn func()) {
	go func() {
		defer logPanic()
		fn()
	}()
}

// ---------- экран подключения ----------

func (u *ui) connectScreen() fyne.CanvasObject {
	keyEntry := widget.NewMultiLineEntry()
	keyEntry.SetPlaceHolder("Вставьте админский ключ vpn://...")
	keyEntry.Wrapping = fyne.TextWrapBreak
	if k := os.Getenv("AMNEZIA_KEY"); k != "" {
		keyEntry.SetText(k)
	}

	info := widget.NewLabel("")
	info.Wrapping = fyne.TextWrapWord

	var connectBtn *widget.Button
	connectBtn = widget.NewButtonWithIcon("Подключиться", theme.LoginIcon(), func() {
		key := strings.TrimSpace(keyEntry.Text)
		if key == "" {
			info.SetText("Ключ пустой.")
			return
		}
		u.attemptConnect(key, false, connectBtn, info)
	})

	title := widget.NewLabelWithStyle("Amnezia Admin", fyne.TextAlignCenter, fyne.TextStyle{Bold: true})
	hint := widget.NewLabel("Нужен админский ключ — внутри него SSH-доступ к серверу.\nПользовательский (share) ключ не подойдёт.")
	hint.Wrapping = fyne.TextWrapWord

	form := container.NewVBox(title, hint, keyEntry, connectBtn, info)

	if vaultBlock := u.savedVaultsBlock(connectBtn, info); vaultBlock != nil {
		form.Add(vaultBlock)
	}

	return container.NewCenter(container.NewGridWrap(fyne.NewSize(560, 400), form))
}

// savedVaultsBlock строит блок «Или загрузить из сохранённых» под кнопкой
// «Подключиться», если в каталоге "Настройки" есть сохранённые ключи (.avlt).
// Настоящие метки серверов зашифрованы и неизвестны до ввода пина, поэтому
// в списке показываются только порядковые "Сервер N" (порядок — по имени файла).
func (u *ui) savedVaultsBlock(connectBtn *widget.Button, info *widget.Label) fyne.CanvasObject {
	vaults := core.ListVaults(core.DefaultVaultDir())
	if len(vaults) == 0 {
		return nil
	}
	label := widget.NewLabel("Или загрузить из сохранённых:")
	names := make([]string, len(vaults))
	for i := range vaults {
		names[i] = fmt.Sprintf("Сервер %d", i+1)
	}
	if len(vaults) == 1 {
		btn := widget.NewButton(names[0], func() {
			u.showVaultPinDialog(vaults[0], names[0], connectBtn, info)
		})
		return container.NewVBox(label, btn)
	}
	sel := widget.NewSelect(names, nil)
	sel.OnChanged = func(_ string) {
		i := sel.SelectedIndex()
		if i < 0 || i >= len(vaults) {
			return
		}
		path, lbl := vaults[i], names[i]
		sel.ClearSelected()
		u.showVaultPinDialog(path, lbl, connectBtn, info)
	}
	return container.NewVBox(label, sel)
}

// showVaultPinDialog запрашивает пин-код для сохранённого ключа и, если он
// верен, сразу выполняет подключение. Argon2 на прод-параметрах занимает
// около секунды — расшифровка идёт в фоне (goSafe), кнопка на время
// заблокирована. Неверный пин не закрывает диалог — только очищает поле и
// показывает сообщение об ошибке (и остаток попыток), чтобы можно было
// повторить.
//
// Throttle (10 неверных попыток подряд → блокировка на 5 минут, персистентно
// в throttle.json per-vault) проверяется до расшифровки и обновляется сразу
// после неё: неудача пишется на диск НЕМЕДЛЕННО (fail-closed), до того, как
// решаем, показывать ли "осталось попыток" или переключаться в отсчёт блокировки.
func (u *ui) showVaultPinDialog(path, label string, connectBtn *widget.Button, info *widget.Label) {
	vaultDir := core.DefaultVaultDir()
	vaultName := filepath.Base(path)

	pinEntry := widget.NewEntry()
	pinEntry.Password = true
	pinEntry.SetPlaceHolder("Пин-код")
	statusLabel := widget.NewLabel("")
	statusLabel.Wrapping = fyne.TextWrapWord

	// throttleAttempts — сколько попыток даётся до блокировки (держим в
	// синхроне с core.throttleMaxFails; вынести в core.ExportedConst не стали,
	// т.к. это единственное место в GUI, где нужно число "осталось попыток").
	const throttleAttempts = 10

	var d dialog.Dialog
	var openBtn *widget.Button
	var ticker *time.Ticker
	// countdownGen — поколение текущего обратного отсчёта: goroutine тикера
	// сверяет его перед каждым обновлением UI и завершается сама, если
	// диалог запустил новый отсчёт или был закрыт (не полагаемся на
	// сравнение указателей *time.Ticker, которое легко перепутать).
	countdownGen := 0
	stopTicker := func() {
		countdownGen++
		if ticker != nil {
			ticker.Stop()
			ticker = nil
		}
	}

	// startCountdown переключает диалог в режим обратного отсчёта блокировки:
	// кнопка "Открыть" дизейблена, статус обновляется раз в секунду, по
	// истечении блокировка снимается автоматически.
	var startCountdown func(until time.Time)
	startCountdown = func(until time.Time) {
		stopTicker()
		myGen := countdownGen
		openBtn.Disable()
		update := func() bool {
			remaining := time.Until(until)
			if remaining <= 0 {
				statusLabel.SetText("")
				openBtn.Enable()
				return false
			}
			sec := int(remaining.Round(time.Second) / time.Second)
			statusLabel.SetText(fmt.Sprintf("Слишком много попыток. Повторите через %d:%02d", sec/60, sec%60))
			return true
		}
		if !update() {
			return
		}
		ticker = time.NewTicker(time.Second)
		tk := ticker
		goSafe(func() {
			for range tk.C {
				done := false
				fyne.Do(func() {
					if countdownGen != myGen {
						done = true // диалог закрыт или отсчёт перезапущен — эта goroutine больше не актуальна
						return
					}
					if !update() {
						done = true
					}
				})
				if done {
					tk.Stop()
					return
				}
			}
		})
	}

	// submit — общее действие и для кнопки "Открыть", и для Enter в поле
	// пина (единственное поле формы). Если кнопка дизейблена (throttle-блок
	// или уже идёт расшифровка) — Enter, как и клик, ничего не делает.
	submit := func() {
		if openBtn.Disabled() {
			return
		}
		pin := pinEntry.Text
		if blocked, remaining := core.CheckThrottle(core.LoadThrottle(vaultDir, vaultName), time.Now()); blocked {
			startCountdown(time.Now().Add(remaining))
			return
		}
		openBtn.Disable()
		statusLabel.SetText("Расшифровываю...")
		goSafe(func() {
			data, err := core.LoadVault(path)
			var payload core.VaultPayload
			if err == nil {
				payload, err = core.OpenVault(pin, data)
			}
			if err != nil {
				now := time.Now()
				st := core.RegisterFailure(core.LoadThrottle(vaultDir, vaultName), now)
				_ = core.SaveThrottle(vaultDir, vaultName, st) // fail-closed: пишем счётчик до любого дальнейшего ветвления
				fyne.Do(func() {
					pinEntry.SetText("")
					if blocked, remaining := core.CheckThrottle(st, now); blocked {
						startCountdown(now.Add(remaining))
						return
					}
					msg := "Неправильный пин-код или файл повреждён."
					if !errors.Is(err, core.ErrVaultBadPinOrCorrupt) {
						msg = err.Error() // прочая ошибка (например чтение файла) — показываем как есть
					}
					if left := throttleAttempts - st.Fails; left > 0 {
						msg += fmt.Sprintf(" Осталось попыток: %d.", left)
					}
					statusLabel.SetText(msg)
					openBtn.Enable()
				})
				return
			}
			_ = core.SaveThrottle(vaultDir, vaultName, core.RegisterSuccess())
			fyne.Do(func() {
				stopTicker()
				d.Hide()
				u.attemptConnect(payload.Key, true, connectBtn, info)
			})
		})
	}
	openBtn = widget.NewButtonWithIcon("Открыть", theme.LoginIcon(), submit)
	// единственное поле формы — Enter сразу выполняет submit (как нажатие "Открыть")
	pinEntry.OnSubmitted = func(string) { submit() }
	content := container.NewVBox(
		widget.NewLabel(label),
		pinEntry,
		statusLabel,
		openBtn,
	)
	d = dialog.NewCustom("Введите пин-код", "Отмена", content, u.win)
	d.SetOnClosed(stopTicker) // не течь тикером, если пользователь закрыл диалог во время отсчёта
	d.Resize(fyne.NewSize(380, 260))

	// сразу при открытии диалога проверяем throttle — если уже заблокировано
	// с прошлого раза, показываем отсчёт немедленно, не дожидаясь клика
	if blocked, remaining := core.CheckThrottle(core.LoadThrottle(vaultDir, vaultName), time.Now()); blocked {
		startCountdown(time.Now().Add(remaining))
	}
	d.Show()
}

// attemptConnect декодирует ключ, подключается по SSH и переключает экран.
// fromVault=false (ключ введён вручную) — после первого успешного подключения
// предлагает сохранить ключ в зашифрованное хранилище.
func (u *ui) attemptConnect(key string, fromVault bool, connectBtn *widget.Button, info *widget.Label) {
	connectBtn.Disable()
	info.SetText("Декодирую ключ и подключаюсь по SSH...")

	goSafe(func() {
		cfg, err := core.DecodeVpnKey(key)
		if err != nil {
			u.connectFail(connectBtn, info, "Ошибка декодирования ключа: "+err.Error())
			return
		}
		creds, err := core.CredsFromConfig(cfg)
		if err != nil {
			u.connectFail(connectBtn, info, err.Error())
			return
		}
		sess, err := core.Connect(creds)
		if err != nil {
			u.connectFail(connectBtn, info, "SSH не удался: "+err.Error())
			return
		}
		containers, err := sess.FindContainers()
		if err != nil {
			sess.Close()
			u.connectFail(connectBtn, info, err.Error())
			return
		}
		fyne.Do(func() {
			u.sess = sess
			u.containers = containers
			u.cur = &u.containers[0]
			for i := range u.containers {
				if u.containers[i].Managed {
					u.cur = &u.containers[i]
					break
				}
			}
			u.win.SetContent(u.mainScreen())
			u.refresh()
			if !fromVault {
				u.offerSaveKey(key, creds.Host)
			}
		})
	})
}

func (u *ui) connectFail(btn *widget.Button, info *widget.Label, msg string) {
	fyne.Do(func() {
		info.SetText(msg)
		btn.Enable()
	})
}

// offerSaveKey предлагает сохранить только что использованный (введённый
// вручную) ключ в зашифрованное хранилище .avlt. Отказ ("Не сохранять")
// просто закрывает диалог без побочных эффектов.
func (u *ui) offerSaveKey(key, defaultLabel string) {
	labelEntry := widget.NewEntry()
	labelEntry.SetText(defaultLabel)
	pinEntry := widget.NewEntry()
	pinEntry.Password = true
	pinRepeat := widget.NewEntry()
	pinRepeat.Password = true
	bindCheck := widget.NewCheck("Привязать к этой учётке Windows (файл нельзя перенести на другой ПК или учётную запись)", nil)
	bindHint := canvas.NewText("Рекомендуется: украденный файл будет бесполезен на другом компьютере.", color.NRGBA{R: 0x80, G: 0x80, B: 0x80, A: 0xff})
	bindHint.TextSize = theme.CaptionTextSize()
	statusLabel := widget.NewLabel("")
	statusLabel.Wrapping = fyne.TextWrapWord
	mismatchLabel := canvas.NewText("Пины не совпадают", color.NRGBA{R: 0xd9, G: 0x2d, B: 0x20, A: 0xff})
	mismatchLabel.TextStyle = fyne.TextStyle{Bold: true}
	mismatchLabel.Hide()

	var d dialog.Dialog
	var saveBtn *widget.Button
	busy := false

	// checkMismatch — живая индикация по мере ввода: как только оба поля
	// пина непусты и различаются, показываем предупреждение и не даём
	// сохранить; финальная проверка (ValidatePin + совпадение) в submit()
	// остаётся как подстраховка. Пины НЕ тримятся при сравнении — пробелы
	// значимы.
	checkMismatch := func() {
		p1, p2 := pinEntry.Text, pinRepeat.Text
		mismatch := p1 != "" && p2 != "" && p1 != p2
		if mismatch {
			mismatchLabel.Show()
		} else {
			mismatchLabel.Hide()
		}
		if busy {
			return
		}
		if mismatch {
			saveBtn.Disable()
		} else {
			saveBtn.Enable()
		}
	}
	pinEntry.OnChanged = func(string) { checkMismatch() }
	pinRepeat.OnChanged = func(string) { checkMismatch() }

	submit := func() {
		if saveBtn.Disabled() {
			return
		}
		pin := pinEntry.Text
		if err := core.ValidatePin(pin); err != nil {
			statusLabel.SetText(err.Error())
			return
		}
		if pin != pinRepeat.Text {
			statusLabel.SetText("Пин-коды не совпадают.")
			return
		}
		label := strings.TrimSpace(labelEntry.Text)
		if label == "" {
			label = defaultLabel
		}
		machineBind := bindCheck.Checked
		busy = true
		saveBtn.Disable()
		statusLabel.SetText("Шифрую...")
		goSafe(func() {
			payload := core.VaultPayload{
				Label:   label,
				Key:     key,
				Created: time.Now().Format(time.RFC3339),
			}
			data, err := core.SealVault(pin, payload, core.ProdArgonParams, machineBind)
			if err == nil {
				_, err = core.SaveVault(core.DefaultVaultDir(), data)
			}
			fyne.Do(func() {
				busy = false
				if err != nil {
					statusLabel.SetText(err.Error())
					saveBtn.Enable()
					return
				}
				d.Hide()
				n := len(core.ListVaults(core.DefaultVaultDir()))
				if u.status != nil {
					u.status.SetText(fmt.Sprintf("Ключ сохранён (Сервер %d).", n))
				}
			})
		})
	}
	saveBtn = widget.NewButtonWithIcon("Сохранить", theme.ConfirmIcon(), submit)

	// Enter-навигация: метка → пин → повтор пина → submit (как клик по кнопке)
	labelEntry.OnSubmitted = func(string) { u.win.Canvas().Focus(pinEntry) }
	pinEntry.OnSubmitted = func(string) { u.win.Canvas().Focus(pinRepeat) }
	pinRepeat.OnSubmitted = func(string) { submit() }

	content := container.NewVBox(
		widget.NewLabel("Сохранить этот ключ для быстрого подключения в следующий раз?"),
		widget.NewForm(
			widget.NewFormItem("Метка", labelEntry),
			widget.NewFormItem("Пин-код", pinEntry),
			widget.NewFormItem("Повтор пина", pinRepeat),
		),
		mismatchLabel,
		bindCheck,
		bindHint,
		statusLabel,
		saveBtn,
	)
	d = dialog.NewCustom("Сохранить ключ?", "Не сохранять", content, u.win)
	d.Resize(fyne.NewSize(460, 360))
	d.Show()
}

// ---------- главный экран ----------

func (u *ui) mainScreen() fyne.CanvasObject {
	// status и table должны существовать до protoSelect:
	// SetSelectedIndex вызывает callback, который делает refresh()
	u.status = widget.NewLabel("")
	u.status.Wrapping = fyne.TextWrapWord
	u.buildTable()

	names := make([]string, len(u.containers))
	for i, c := range u.containers {
		label := c.Proto
		if !c.Managed {
			label += " (просмотр)"
		}
		names[i] = label
	}
	u.protoSelect = widget.NewSelect(names, func(_ string) {
		i := u.protoSelect.SelectedIndex()
		if i >= 0 && i < len(u.containers) {
			u.cur = &u.containers[i]
			u.selectedRow = -1
			// выделение относилось к строке из СТАРОГО списка — в новом
			// списке той же строки может не быть (или там другой клиент)
			u.table.UnselectAll()
			u.refresh()
		}
	})
	for i := range u.containers {
		if &u.containers[i] == u.cur {
			u.protoSelect.SetSelectedIndex(i)
		}
	}

	server := widget.NewLabel(fmt.Sprintf("Сервер: %s@%s", u.sess.Creds.User, u.sess.Creds.Host))

	refreshBtn := widget.NewButtonWithIcon("Обновить", theme.ViewRefreshIcon(), func() { u.refresh() })
	addBtn := widget.NewButtonWithIcon("Создать", theme.ContentAddIcon(), func() { u.addDialog() })
	renameBtn := widget.NewButtonWithIcon("Переименовать", theme.DocumentCreateIcon(), func() { u.renameSelected() })
	toggleBtn := widget.NewButtonWithIcon("Вкл/Выкл", theme.MediaPauseIcon(), func() { u.toggleSelected() })
	regenBtn := widget.NewButtonWithIcon("Перевыпустить", theme.MediaReplayIcon(), func() { u.regenerateSelected() })
	delBtn := widget.NewButtonWithIcon("Удалить", theme.DeleteIcon(), func() { u.deleteSelected() })
	addBtn.Importance = widget.HighImportance

	top := container.NewBorder(nil, nil,
		container.NewHBox(server, widget.NewLabel("Протокол:"), u.protoSelect),
		container.NewHBox(refreshBtn, addBtn, renameBtn, toggleBtn, regenBtn, delBtn),
	)
	return container.NewBorder(top, u.status, nil, nil, u.table)
}

// tableHeaders — колонки таблицы пользователей. columnSort[i] — сортируемый
// ключ этой колонки, или core.SortNone, если колонка не сортируется (клик
// игнорируется): "#" (презентационный номер строки) и "Публичный ключ".
// ---------- персистентность сортировки таблицы (ui.json) ----------
//
// Состояние сортировки (какая колонка primary/secondary и в каком
// направлении) хранится в ui.json рядом с exe, в той же портативной папке
// "Настройки", что vault-файлы и throttle.json — НЕ в fyne app.Preferences
// (тот пишет в %APPDATA% и ломает портативность). Формат — плоский JSON,
// запись атомарна (tmp+rename). Битый/отсутствующий файл — тихий откат к
// дефолту (Активность, по убыванию), без паники.

type sortStateJSON struct {
	Primary      string `json:"primary"`
	PrimaryDir   string `json:"primaryDir"`
	Secondary    string `json:"secondary"`
	SecondaryDir string `json:"secondaryDir"`
}

var sortColumnNames = map[core.SortColumn]string{
	core.SortNone:          "none",
	core.SortByName:        "name",
	core.SortByCreated:     "created",
	core.SortByActivityCol: "activity",
	core.SortByTraffic:     "traffic",
}

func sortColumnFromName(s string) (core.SortColumn, bool) {
	for col, name := range sortColumnNames {
		if name == s {
			return col, true
		}
	}
	return core.SortNone, false
}

func sortDirName(d core.SortDir) string {
	if d == core.Desc {
		return "desc"
	}
	return "asc"
}

func sortDirFromName(s string) core.SortDir {
	if s == "desc" {
		return core.Desc
	}
	return core.Asc
}

func uiStatePath() string {
	return filepath.Join(core.DefaultVaultDir(), "ui.json")
}

// loadSortState читает ui.json; при отсутствии файла, битом JSON или
// нераспознанной primary-колонке возвращает дефолт: Активность по убыванию,
// без secondary (то же поведение, что было до появления сортировки по клику).
func loadSortState() (primary core.SortColumn, primaryDir core.SortDir, secondary core.SortColumn, secondaryDir core.SortDir) {
	defPrimary, defPrimaryDir, defSecondary, defSecondaryDir := core.SortByActivityCol, core.Desc, core.SortNone, core.Asc
	data, err := os.ReadFile(uiStatePath())
	if err != nil {
		return defPrimary, defPrimaryDir, defSecondary, defSecondaryDir
	}
	var st sortStateJSON
	if err := json.Unmarshal(data, &st); err != nil {
		return defPrimary, defPrimaryDir, defSecondary, defSecondaryDir
	}
	primary, ok := sortColumnFromName(st.Primary)
	if !ok || primary == core.SortNone {
		return defPrimary, defPrimaryDir, defSecondary, defSecondaryDir
	}
	secondary, ok = sortColumnFromName(st.Secondary)
	if !ok {
		secondary = core.SortNone
	}
	return primary, sortDirFromName(st.PrimaryDir), secondary, sortDirFromName(st.SecondaryDir)
}

// saveSortState записывает текущее состояние сортировки атомарно (tmp+rename).
// Ошибка молча логируется через crash.log не пишется — это некритичная UX-настройка,
// поэтому просто игнорируем ошибку записи (нет диалога, не мешаем работе).
func saveSortState(primary core.SortColumn, primaryDir core.SortDir, secondary core.SortColumn, secondaryDir core.SortDir) {
	dir := core.DefaultVaultDir()
	if err := os.MkdirAll(dir, 0755); err != nil {
		return
	}
	st := sortStateJSON{
		Primary:      sortColumnNames[primary],
		PrimaryDir:   sortDirName(primaryDir),
		Secondary:    sortColumnNames[secondary],
		SecondaryDir: sortDirName(secondaryDir),
	}
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return
	}
	path := uiStatePath()
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0644); err != nil {
		return
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
	}
}

var tableHeaders = []string{"#", "Имя", "Создан", "Активность", "Трафик ↓/↑", "Публичный ключ"}
var tableColumnSort = []core.SortColumn{
	core.SortNone, core.SortByName, core.SortByCreated, core.SortByActivityCol, core.SortByTraffic, core.SortNone,
}

// tappableLabel — widget.Label, которую можно кликнуть. В Fyne 2.7
// widget.Table не даёт штатного колбэка на клик по заголовку колонки:
// Table.Tapped() резолвит только ячейки данных (columnAt/rowAt), а тап по
// строке заголовка возвращает noCellMatch, если StickyRowCount не настроен
// (по умолчанию для NewTableWithHeaders — не настроен). Рабочий способ,
// подтверждённый исходниками fyne.io/fyne/v2/widget (Table.CreateHeader
// принимает произвольный fyne.CanvasObject) — сделать сам объект заголовка
// кликабельным виджетом: тогда драйвер Fyne при хит-тесте находит именно
// его (самый вложенный Tappable под курсором), а не Table.Tapped.
type tappableLabel struct {
	widget.Label
	onTap func()
}

func newTappableLabel() *tappableLabel {
	l := &tappableLabel{}
	l.TextStyle = fyne.TextStyle{Bold: true}
	l.ExtendBaseWidget(l)
	return l
}

func (l *tappableLabel) Tapped(*fyne.PointEvent) {
	if l.onTap != nil {
		l.onTap()
	}
}

func (l *tappableLabel) TappedSecondary(*fyne.PointEvent) {}

func (u *ui) buildTable() {
	headers := tableHeaders
	widths := []float32{40, 280, 165, 140, 150, 280}

	u.table = widget.NewTableWithHeaders(
		func() (int, int) { return len(u.clients), len(headers) },
		func() fyne.CanvasObject { return widget.NewLabel("") },
		func(id widget.TableCellID, o fyne.CanvasObject) {
			l := o.(*widget.Label)
			l.TextStyle = fyne.TextStyle{}
			if id.Row >= len(u.clients) {
				l.SetText("")
				return
			}
			cl := u.clients[id.Row]
			switch id.Col {
			case 0:
				l.SetText(fmt.Sprintf("%d", id.Row+1))
			case 1:
				l.TextStyle = fyne.TextStyle{Bold: true, Italic: cl.Disabled()}
				l.SetText(cl.Name())
			case 2:
				created := cl.Created()
				if r := []rune(created); len(r) > 19 {
					created = string(r[:19])
				}
				l.SetText(created)
			case 3:
				if cl.Disabled() {
					l.SetText("отключён")
				} else {
					hs := u.handshakes[cl.ClientID]
					if hs == "" {
						hs = "?"
					}
					l.SetText(hs)
				}
			case 4:
				st := u.peerStats[cl.ClientID]
				l.SetText(core.HumanBytes(st.RxBytes) + " / " + core.HumanBytes(st.TxBytes))
			case 5:
				l.SetText(cl.ClientID)
			}
		},
	)
	u.table.CreateHeader = func() fyne.CanvasObject {
		return newTappableLabel()
	}
	u.table.UpdateHeader = func(id widget.TableCellID, o fyne.CanvasObject) {
		hl := o.(*tappableLabel)
		if id.Row >= 0 || id.Col < 0 || id.Col >= len(headers) {
			hl.SetText("")
			hl.onTap = nil
			return
		}
		text := headers[id.Col]
		col := tableColumnSort[id.Col]
		if col != core.SortNone && col == u.sortPrimary {
			if u.sortPrimaryDir == core.Desc {
				text += " ▼"
			} else {
				text += " ▲"
			}
		}
		hl.SetText(text)
		if col == core.SortNone {
			hl.onTap = nil
		} else {
			colCopy := col
			hl.onTap = func() { u.onHeaderTapped(colCopy) }
		}
	}
	for i, w := range widths {
		u.table.SetColumnWidth(i, w)
	}
	u.table.OnSelected = func(id widget.TableCellID) {
		u.selectedRow = id.Row
	}
}

// onHeaderTapped обрабатывает клик по заголовку сортируемой колонки: тот же
// столбец — меняем направление; другой столбец — он становится новым primary
// (asc по умолчанию), а прежний primary сдвигается в secondary (tie-breaker,
// сохраняя своё последнее направление). Пересортировка — по уже загруженным
// u.clients/u.peerStats, без обращения к серверу.
func (u *ui) onHeaderTapped(col core.SortColumn) {
	if u.sortPrimary == col {
		if u.sortPrimaryDir == core.Asc {
			u.sortPrimaryDir = core.Desc
		} else {
			u.sortPrimaryDir = core.Asc
		}
	} else {
		u.sortSecondary = u.sortPrimary
		u.sortSecondaryDir = u.sortPrimaryDir
		u.sortPrimary = col
		u.sortPrimaryDir = core.Asc
	}
	saveSortState(u.sortPrimary, u.sortPrimaryDir, u.sortSecondary, u.sortSecondaryDir)
	u.applySort()
	if u.table != nil {
		u.table.Refresh()
	}
}

// applySort пересортировывает уже загруженный u.clients по текущему
// primary/secondary — общая точка применения сортировки и для refresh(),
// и для клика по заголовку (сеть не трогаем, сортируем то, что уже есть).
func (u *ui) applySort() {
	core.SortClientsMultiKey(u.clients, u.peerStats, u.sortPrimary, u.sortPrimaryDir, u.sortSecondary, u.sortSecondaryDir)
}

// refresh перечитывает пользователей с сервера (в фоне).
//
// Снимок cur делается дважды: один раз здесь (для запроса к нужному
// протоколу) и повторно сверяется с u.cur внутри fyne.Do — если пользователь
// успел переключить протокол, пока запрос летел по сети, устаревший ответ
// отбрасывается и не перерисовывает таблицу поверх уже актуальных данных.
func (u *ui) refresh() {
	if u.table == nil || u.status == nil {
		return // экран ещё строится
	}
	cur := u.cur
	u.status.SetText("Загружаю список пользователей...")
	goSafe(func() {
		clients, err := u.sess.LoadClients(cur)
		hs := u.sess.GetHandshakes(cur)
		stats, statErr := u.sess.GetPeerStats(cur)
		if statErr != nil {
			stats = map[string]core.PeerStat{}
		}
		fyne.Do(func() {
			if cur != u.cur {
				return // протокол сменился ещё раз, пока шёл запрос — ответ устарел
			}
			if err != nil {
				u.status.SetText("Ошибка: " + err.Error())
				return
			}
			u.clients = clients
			u.handshakes = hs
			u.peerStats = stats
			// применяем текущую (сохранённую/выбранную кликом по заголовку)
			// сортировку — переключение протокола не должно сбрасывать её на дефолт
			u.applySort()
			// widget.Table в Fyne после смены данных иногда не перерисовывает
			// видимые (уже отрисованные ранее) ячейки, если таблица осталась
			// проскроллена не в начало — без явного Refresh+ScrollToTop
			// таблица выглядит пустой, пока пользователь не проскроллит вручную.
			u.table.Refresh()
			u.table.ScrollToTop()
			note := ""
			if !cur.Managed {
				note = " — только просмотр, управление для этого протокола не поддерживается"
			}
			u.status.SetText(fmt.Sprintf("Пользователей: %d%s · трафик и активность — с момента перезапуска сервера", len(clients), note))
		})
	})
}

// ---------- создание ----------

func (u *ui) addDialog() {
	if !u.cur.Managed {
		dialog.ShowInformation("Недоступно",
			fmt.Sprintf("Создание пользователей для %s не поддерживается.", u.cur.Proto), u.win)
		return
	}
	entry := widget.NewEntry()
	entry.SetPlaceHolder("Иванов Иван")
	items := []*widget.FormItem{widget.NewFormItem("Имя", entry)}
	d := dialog.NewForm("Новый пользователь", "Создать", "Отмена", items, func(ok bool) {
		if !ok || strings.TrimSpace(entry.Text) == "" {
			return
		}
		name := strings.TrimSpace(entry.Text)
		u.status.SetText(fmt.Sprintf("Создаю пользователя %q...", name))
		goSafe(func() {
			nu, err := u.sess.AddUser(u.cur, name)
			fyne.Do(func() {
				if err != nil {
					u.status.SetText("")
					dialog.ShowError(err, u.win)
					return
				}
				u.status.SetText(fmt.Sprintf("Пользователь %q создан (IP %s).", nu.Name, nu.IP))
				u.showConfigDialog(nu, "создан")
				u.refresh()
			})
		})
	}, u.win)
	// единственное поле формы — Enter эквивалентен нажатию "Создать"
	entry.OnSubmitted = func(string) { d.Submit() }
	d.Resize(fyne.NewSize(420, 160))
	d.Show()
}

// writeConfigFile сохраняет клиентский конфиг в "Конфигурации\<Имя>.conf"
// (перезаписывая, если уже есть) и возвращает абсолютный путь.
func (u *ui) writeConfigFile(nu *core.NewUser) (string, error) {
	if err := os.MkdirAll("Конфигурации", 0755); err != nil {
		return "", err
	}
	fileName := filepath.Join("Конфигурации", core.SanitizeName(nu.Name)+".conf")
	if err := os.WriteFile(fileName, []byte(nu.Config), 0600); err != nil {
		return "", err
	}
	abs, _ := filepath.Abs(fileName)
	return abs, nil
}

// showConfigDialog показывает готовый клиентский конфиг в виде QR-кода
// (для сканирования приложением AmneziaWG на телефоне) и кнопку сохранения
// .conf на диск. Используется и после создания нового пользователя, и после
// перевыпуска (re-key) — verb это причастие в диалоге ("создан"/"перевыпущен").
func (u *ui) showConfigDialog(nu *core.NewUser, verb string) {
	var qrObj fyne.CanvasObject
	if png, err := core.QRPNG(nu.Config, 256); err == nil {
		res := fyne.NewStaticResource(core.SanitizeName(nu.Name)+"-qr.png", png)
		img := canvas.NewImageFromResource(res)
		img.FillMode = canvas.ImageFillOriginal
		img.SetMinSize(fyne.NewSize(256, 256))
		qrObj = img
	} else {
		l := widget.NewLabel("Не удалось построить QR-код: " + err.Error())
		l.Wrapping = fyne.TextWrapWord
		qrObj = l
	}

	savedLabel := widget.NewLabel("")
	savedLabel.Wrapping = fyne.TextWrapWord

	var saveBtn *widget.Button
	saveBtn = widget.NewButtonWithIcon("Сохранить .conf", theme.DocumentSaveIcon(), func() {
		abs, err := u.writeConfigFile(nu)
		if err != nil {
			dialog.ShowError(err, u.win)
			return
		}
		saveBtn.Disable()
		savedLabel.SetText("Сохранено: " + abs)
		if u.status != nil {
			u.status.SetText(fmt.Sprintf("Конфиг сохранён: %s", abs))
		}
	})

	hint := widget.NewLabel("Отсканируйте QR в приложении AmneziaWG на телефоне или импортируйте файл.")
	hint.Wrapping = fyne.TextWrapWord

	content := container.NewVBox(
		widget.NewLabelWithStyle(fmt.Sprintf("Пользователь %q %s (IP %s).", nu.Name, verb, nu.IP), fyne.TextAlignCenter, fyne.TextStyle{Bold: true}),
		container.NewCenter(qrObj),
		hint,
		saveBtn,
		savedLabel,
	)
	d := dialog.NewCustom("Конфиг готов", "Закрыть", content, u.win)
	d.Resize(fyne.NewSize(380, 480))
	d.Show()
}

// ---------- переименование ----------

func (u *ui) renameSelected() {
	if !u.cur.Managed {
		dialog.ShowInformation("Недоступно",
			fmt.Sprintf("Переименование пользователей для %s не поддерживается.", u.cur.Proto), u.win)
		return
	}
	idx := u.selectedRow
	if idx < 0 || idx >= len(u.clients) {
		dialog.ShowInformation("Не выбран пользователь", "Выберите строку в таблице.", u.win)
		return
	}
	victim := u.clients[idx]
	entry := widget.NewEntry()
	entry.SetText(victim.Name())
	items := []*widget.FormItem{widget.NewFormItem("Новое имя", entry)}
	d := dialog.NewForm(fmt.Sprintf("Переименовать %q", victim.Name()), "Сохранить", "Отмена", items, func(ok bool) {
		if !ok || strings.TrimSpace(entry.Text) == "" {
			return
		}
		newName := strings.TrimSpace(entry.Text)
		u.status.SetText(fmt.Sprintf("Переименовываю %q...", victim.Name()))
		goSafe(func() {
			err := u.sess.RenameUser(u.cur, victim.ClientID, newName)
			fyne.Do(func() {
				if err != nil {
					u.status.SetText("")
					dialog.ShowError(err, u.win)
					return
				}
				u.selectedRow = -1
				u.status.SetText(fmt.Sprintf("Пользователь %q переименован в %q.", victim.Name(), newName))
				u.refresh()
			})
		})
	}, u.win)
	// единственное поле формы — Enter эквивалентен нажатию "Сохранить"
	entry.OnSubmitted = func(string) { d.Submit() }
	d.Resize(fyne.NewSize(420, 160))
	d.Show()
}

// ---------- отключение/включение ----------

func (u *ui) toggleSelected() {
	if !u.cur.Managed {
		dialog.ShowInformation("Недоступно",
			fmt.Sprintf("Управление пользователями для %s не поддерживается.", u.cur.Proto), u.win)
		return
	}
	idx := u.selectedRow
	if idx < 0 || idx >= len(u.clients) {
		dialog.ShowInformation("Не выбран пользователь", "Выберите строку в таблице.", u.win)
		return
	}
	victim := u.clients[idx]
	enable := victim.Disabled()
	title := "Отключить пользователя?"
	verb := "Отключаю"
	if enable {
		title = "Включить пользователя?"
		verb = "Включаю"
	}
	dialog.ShowConfirm(title, fmt.Sprintf("Пользователь: %s\nКлюч: %s", victim.Name(), victim.ClientID), func(ok bool) {
		if !ok {
			return
		}
		u.status.SetText(fmt.Sprintf("%s %q...", verb, victim.Name()))
		goSafe(func() {
			err := u.sess.SetEnabled(u.cur, victim.ClientID, enable)
			fyne.Do(func() {
				if err != nil {
					u.status.SetText("")
					dialog.ShowError(err, u.win)
					return
				}
				u.selectedRow = -1
				if enable {
					u.status.SetText(fmt.Sprintf("Пользователь %q включён.", victim.Name()))
				} else {
					u.status.SetText(fmt.Sprintf("Пользователь %q отключён.", victim.Name()))
				}
				u.refresh()
			})
		})
	}, u.win)
}

// ---------- перевыпуск конфига (re-key) ----------

func (u *ui) regenerateSelected() {
	if !u.cur.Managed {
		dialog.ShowInformation("Недоступно",
			fmt.Sprintf("Перевыпуск конфигов для %s не поддерживается.", u.cur.Proto), u.win)
		return
	}
	idx := u.selectedRow
	if idx < 0 || idx >= len(u.clients) {
		dialog.ShowInformation("Не выбран пользователь", "Выберите строку в таблице.", u.win)
		return
	}
	victim := u.clients[idx]
	dialog.ShowConfirm("Перевыпустить конфиг?",
		fmt.Sprintf("Перевыпустить конфиг для %s? Старый конфиг перестанет работать, пользователю нужно установить новый.", victim.Name()),
		func(ok bool) {
			if !ok {
				return
			}
			u.status.SetText(fmt.Sprintf("Перевыпускаю конфиг для %q...", victim.Name()))
			goSafe(func() {
				nu, err := u.sess.RegenerateUser(u.cur, victim.ClientID)
				fyne.Do(func() {
					if err != nil {
						u.status.SetText("")
						dialog.ShowError(err, u.win)
						return
					}
					u.selectedRow = -1
					u.status.SetText(fmt.Sprintf("Конфиг для %q перевыпущен.", nu.Name))
					u.showConfigDialog(nu, "перевыпущен")
					u.refresh()
				})
			})
		}, u.win)
}

// ---------- удаление ----------

func (u *ui) deleteSelected() {
	if !u.cur.Managed {
		dialog.ShowInformation("Недоступно",
			fmt.Sprintf("Удаление пользователей для %s не поддерживается.", u.cur.Proto), u.win)
		return
	}
	idx := u.selectedRow
	if idx < 0 || idx >= len(u.clients) {
		dialog.ShowInformation("Не выбран пользователь", "Выберите строку в таблице.", u.win)
		return
	}
	victim := u.clients[idx]
	msg := fmt.Sprintf("Имя: %s\nСоздан: %s\nКлюч: %s\n", victim.Name(), victim.Created(), victim.ClientID)
	if hs := u.handshakes[victim.ClientID]; hs != "" && hs != "—" {
		msg += fmt.Sprintf("\n⚠ У этого клиента была активность!\nПоследнее подключение: %s\n", hs)
	} else {
		msg += "\nПодключений не было.\n"
	}
	dialog.ShowConfirm("Удалить пользователя?", msg, func(ok bool) {
		if !ok {
			return
		}
		u.status.SetText(fmt.Sprintf("Удаляю %q...", victim.Name()))
		goSafe(func() {
			err := u.sess.DeleteByID(u.cur, victim.ClientID)
			fyne.Do(func() {
				if err != nil {
					u.status.SetText("")
					dialog.ShowError(err, u.win)
					return
				}
				u.selectedRow = -1
				u.status.SetText(fmt.Sprintf("Пользователь %q удалён.", victim.Name()))
				u.refresh()
			})
		})
	}, u.win)
}
