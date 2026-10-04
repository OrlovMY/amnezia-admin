package main

// XRay в GUI (AL-01). Тексты — из internal/guiview и core (их сверяют
// тесты); здесь только окна.
//
// Ревью раунд 1: каждое действие XRay — план → ОДНО окно подтверждения
// (карточка, «что изменится», предупреждение о перезапуске по
// plan.RestartsXRay(), предупреждение о гонке) → Apply ТОГО ЖЕ плана
// (AU-LOGIC High-2, AU-UX M2). Кнопки окна — внизу рядом, фокус на «Отмена»,
// Esc — отмена (AU-UX M1).

import (
	"fmt"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"amnezia-admin/core"
	"amnezia-admin/internal/guiview"
)

// configDoneText — строка «Пользователь … создан» окна конфига: у XRay
// адреса нет.
func configDoneText(nu *core.NewUser, verb string) string {
	if nu.IP == "" {
		return fmt.Sprintf("Пользователь %q %s.", nu.Name, verb)
	}
	return fmt.Sprintf("Пользователь %q %s (IP %s).", nu.Name, verb, nu.IP)
}

// xrayServiceRow — выбрана служебная строка XRay: действий над ней нет
// (решение владельца 2) — сказать это и не открывать диалог действия.
func (u *ui) xrayServiceRow(cl core.ClientEntry) bool {
	if !u.xrayView.IsInstall(cl) {
		return false
	}
	// AU-UX Р3-2: заголовок — имя клиента из clientsTable; синтетическое —
	// только если имени нет
	title := cl.Name()
	if title == "" {
		title = core.XRayServiceName
	}
	dialog.ShowInformation(title, guiview.XRayServiceInfo, u.win)
	return true
}

// confirmWindow — окно подтверждения: разделы сверху (в прокрутке), внизу
// рядом «Отмена» и кнопка действия; фокус на «Отмена»; Esc — отмена.
// danger — кнопка действия опасного вида. Возвращает окно (тестам).
func (u *ui) confirmWindow(title string, sections []fyne.CanvasObject, okText string, danger bool, onOK func()) dialog.Dialog {
	return u.confirmWindowBtn(title, sections, okText, danger, onOK).d
}

// confirmWin — окно подтверждения и его кнопка «OK».
type confirmWin struct {
	d  dialog.Dialog
	ok *escButton
}

// confirmWindowBtn — то же, и кнопка подтверждения (окно восстановления
// включает её по галкам).
func (u *ui) confirmWindowBtn(title string, sections []fyne.CanvasObject, okText string, danger bool, onOK func()) confirmWin {
	var d dialog.Dialog
	cv := u.win.Canvas()
	prevKey := cv.OnTypedKey()
	closed := false
	restoreKeys := func() {
		if !closed {
			closed = true
			cv.SetOnTypedKey(prevKey)
		}
	}
	cancel := func() {
		restoreKeys()
		d.Hide()
	}
	cancelBtn := newEscButton(guiview.XRayRestartCancel(), theme.CancelIcon(), cancel, cancel)
	okIcon := theme.ConfirmIcon()
	if danger {
		okIcon = theme.WarningIcon()
	}
	okBtn := newEscButton(okText, okIcon, func() {
		restoreKeys()
		d.Hide()
		onOK()
	}, cancel)
	okBtn.Importance = widget.HighImportance
	if danger {
		okBtn.Importance = widget.DangerImportance
	}
	body := container.NewVScroll(container.NewVBox(sections...))
	content := container.NewBorder(nil, container.NewCenter(container.NewHBox(cancelBtn, okBtn)), nil, nil, body)
	d = dialog.NewCustomWithoutButtons(title, content, u.win)
	d.SetOnClosed(restoreKeys)
	d.Resize(fyne.NewSize(560, 380))
	cv.SetOnTypedKey(func(e *fyne.KeyEvent) {
		if e.Name == fyne.KeyEscape {
			restoreKeys()
			d.Hide()
			return
		}
		if prevKey != nil {
			prevKey(e)
		}
	})
	d.Show()
	cv.Focus(cancelBtn)
	u.xrayWarnShown = d
	return confirmWin{d, okBtn}
}

// escButton — кнопка окна подтверждения, которая по Esc отменяет окно. В
// Fyne v2.7.4 клавиша идёт ФОКУСУ, а обработчику окна — только без фокуса
// (internal/driver/glfw/window.go:716-721); фокус стоит на «Отмена», поэтому
// Esc обязана понимать сама кнопка (AU-UX р2, Р2-1).
type escButton struct {
	widget.Button
	onEsc func()
}

func newEscButton(text string, icon fyne.Resource, tapped, onEsc func()) *escButton {
	b := &escButton{onEsc: onEsc}
	b.Text, b.Icon, b.OnTapped = text, icon, tapped
	b.ExtendBaseWidget(b)
	return b
}

// TypedKey — Esc отменяет окно; прочее — как у кнопки.
func (b *escButton) TypedKey(e *fyne.KeyEvent) {
	if e.Name == fyne.KeyEscape && b.onEsc != nil {
		b.onEsc()
		return
	}
	b.Button.TypedKey(e)
}

// wrapLabel — подпись с переносом по словам.
func wrapLabel(text string, bold bool) *widget.Label {
	l := widget.NewLabelWithStyle(text, fyne.TextAlignLeading, fyne.TextStyle{Bold: bold})
	l.Wrapping = fyne.TextWrapWord
	return l
}

// restartSections — раздел предупреждения о перезапуске.
func restartSections() []fyne.CanvasObject {
	return []fyne.CanvasObject{wrapLabel(guiview.XRayRestartTitle(), true), wrapLabel(guiview.XRayRestartBody(), false)}
}

// confirmXRayRestart — перед «Применить» в окне изменений: предупреждение
// о перезапуске; restarts == false — do сразу (rename и т.п.).
func (u *ui) confirmXRayRestart(restarts bool, do func()) {
	if !restarts {
		do()
		return
	}
	u.confirmWindow(guiview.XRayRestartTitle(), restartSections(), guiview.XRayRestartConfirm(), true, do)
}

// xrayAct — общий путь действия XRay: план в фоне → одно окно → Apply того
// же плана → onDone. card — разделы карточки (имя, ключ и т.п.).
func (u *ui) xrayAct(title string, op guiview.Op, card []string, build func(*core.Container) (*core.Plan, error), onDone func(*core.Plan, *core.NewUser)) {
	cur := u.cur
	u.setBusy(true)
	u.status.SetText("Считаю изменения...")
	goSafe(func() {
		plan, err := build(cur)
		fyne.Do(func() {
			u.setBusy(false)
			u.status.SetText("")
			if err != nil {
				u.showError(err)
				return
			}
			var secs []fyne.CanvasObject
			restarts := plan.RestartsXRay()
			if restarts {
				// AU-UX р2: раздел о перезапуске — ПЕРВЫМ, виден без прокрутки
				secs = append(secs, restartSections()...)
			}
			for _, c := range card {
				secs = append(secs, wrapLabel(c, false))
			}
			if _, tbl := plan.Diff(); tbl != "" {
				secs = append(secs, wrapLabel("Что изменится:", true), wrapLabel(tbl, false))
			}
			if n := plan.Note(); n != "" {
				secs = append(secs, wrapLabel(n, false))
			}
			server := u.warnServerID()
			race := guiview.WarnDecision(op, u.warnFreq, u.warnSess, server)
			if race {
				secs = append(secs, wrapLabel(guiview.WarningTitle(), true), wrapLabel(guiview.WarningBody(), false))
			}
			okText := "Применить"
			if restarts {
				okText = guiview.XRayRestartConfirm()
			}
			u.confirmWindow(title, secs, okText, restarts, func() {
				if race {
					u.warnSess = guiview.AfterWarned(server)
				}
				u.setBusy(true)
				u.status.SetText("Применяю...")
				goSafe(func() {
					nu, err := u.sess.Apply(plan)
					fyne.Do(func() {
						if err != nil {
							u.setBusy(false)
							u.status.SetText("")
							u.showError(err)
							return
						}
						onDone(plan, nu)
					})
				})
			})
		})
	})
}

func xrayCard(cl core.ClientEntry) []string {
	return []string{fmt.Sprintf("Имя: %s\nСоздан: %s\nUUID (отпечаток): %s", cl.Name(), core.CreatedText(cl.Created()), core.UUIDPrint(cl.ClientID)),
		guiview.XRayDeleteActivity}
}

func (u *ui) xrayAdd(name string, onCreated func(*core.NewUser)) {
	u.xrayAct(fmt.Sprintf("Создать пользователя %q?", name), guiview.OpAddUser, nil,
		func(c *core.Container) (*core.Plan, error) { return u.sess.PlanAddUser(c, name) },
		func(_ *core.Plan, nu *core.NewUser) { onCreated(nu) })
}

func (u *ui) xrayDelete(cl core.ClientEntry) {
	u.xrayAct("Удалить пользователя?", guiview.OpDeleteUser, xrayCard(cl),
		func(c *core.Container) (*core.Plan, error) { return u.sess.PlanDelete(c, cl.ClientID) },
		func(*core.Plan, *core.NewUser) {
			u.selectedRow = -1
			u.status.SetText(fmt.Sprintf("Пользователь %q удалён.", cl.Name()))
			u.refresh()
		})
}

func (u *ui) xrayToggle(cl core.ClientEntry, enable bool) {
	title, done := "Отключить пользователя?", "отключён"
	if enable {
		title, done = "Включить пользователя?", "включён"
	}
	u.xrayAct(title, guiview.OpToggleUser, xrayCard(cl)[:1],
		func(c *core.Container) (*core.Plan, error) { return u.sess.PlanSetEnabled(c, cl.ClientID, enable) },
		func(p *core.Plan, _ *core.NewUser) {
			u.selectedRow = -1
			st := fmt.Sprintf("Пользователь %q %s.", cl.Name(), done)
			if n := p.Note(); n != "" {
				st += " " + n
			}
			u.status.SetText(st)
			u.refresh()
		})
}

func (u *ui) xrayRekey(cl core.ClientEntry) {
	u.xrayAct("Перевыпустить конфиг?", guiview.OpRekeyUser,
		append(xrayCard(cl)[:1], "Старый конфиг перестанет работать, пользователю нужно установить новый."),
		func(c *core.Container) (*core.Plan, error) { return u.sess.PlanRekey(c, cl.ClientID) },
		func(_ *core.Plan, nu *core.NewUser) {
			u.selectedRow = -1
			u.status.SetText(fmt.Sprintf("Конфиг для %q перевыпущен.", nu.Name))
			u.showConfigDialog(nu, "перевыпущен")
			u.refresh()
		})
}

// refreshXRay — загрузка списка XRay: записи clientsTable и служебная строка
// в конце. Сбой чтения — как у WG (AU-UX M3): прежний список ЭТОГО же XRay
// остаётся с пометкой «данные прошлого чтения», кнопки изменения
// выключены; если прежний список — не этого XRay (переключение протокола),
// таблица очищается.
func (u *ui) refreshXRay(cur *core.Container) {
	goSafe(func() {
		v, err := u.sess.LoadXRayView(cur)
		fyne.Do(func() {
			defer u.setBusy(false)
			if cur != u.cur {
				return
			}
			if err != nil {
				// clientsTable не прочитана — списка нет вовсе
				u.canManage = false
				if u.xrayLoadedFor != cur {
					u.clients = nil
				}
				u.table.Refresh()
				u.status.SetText(guiview.ErrorStatus(err, guiview.XRayStaleSuffix(u.xrayLoadedFor == cur)))
				return
			}
			// «только просмотр» (формат, ключ установки) — список есть,
			// управления нет; причина — в статусе (XRayNotes)
			u.canManage = v.ReadOnly == ""
			u.xrayView = v
			u.xrayLoadedFor = cur
			clients := append([]core.ClientEntry{}, v.Clients...)
			u.peerStats = map[string]core.PeerStat{}
			u.statsFailed = false
			u.clients = clients
			u.applySort()
			// клиент установки без записи в clientsTable — строкой последней
			if v.InstallID != "" && v.InstallListed && !v.InstallInTable {
				u.clients = append(u.clients, core.ClientEntry{ClientID: core.XRayServiceRowID,
					UserData: map[string]any{"clientName": core.XRayServiceName}})
			}
			u.applyKeyColumnWidth()
			u.table.Refresh()
			u.table.ScrollToTop()
			u.status.SetText(guiview.XRayStatus(v))
		})
	})
}

// showXRayConfig — QR и файл конфига существующего клиента XRay, собранные
// с сервера (меню строки «Показать QR» / «Сохранить конфигурацию…»).
func (u *ui) showXRayConfig(cl core.ClientEntry) {
	// AU-UX Р3-1 (решение ядра): клиенту установки разрешены действия
	// только чтения — показать QR и сохранить конфиг; отказ — только у
	// синтетической строки (записи в clientsTable нет — конфиг не собрать)
	if cl.ClientID == core.XRayServiceRowID && u.xrayServiceRow(cl) {
		return
	}
	cur := u.cur
	u.setBusy(true)
	u.status.SetText(fmt.Sprintf("Собираю конфиг %q с сервера...", cl.Name()))
	goSafe(func() {
		nu, err := u.sess.XRayClientConfig(cur, cl.ClientID)
		fyne.Do(func() {
			u.setBusy(false)
			u.status.SetText("")
			if err != nil {
				u.showError(err)
				return
			}
			u.showConfigDialog(nu, "— конфиг собран с сервера")
		})
	})
}

// headerText — подпись колонки: у XRay «Активность» — «Доступ» (AU-UX Low).
func (u *ui) headerText(col int) string {
	if col == 3 && u.cur != nil && core.IsXRay(u.cur) && u.xrayLoadedFor == u.cur {
		return guiview.XRayAccessHeader
	}
	return tableHeaders[col]
}
