package main

// XRay в GUI (AL-01). Тексты — из internal/guiview и core (их сверяют
// тесты); здесь только окна.

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
	if cl.ClientID != core.XRayServiceRowID {
		return false
	}
	dialog.ShowInformation(core.XRayServiceName, guiview.XRayServiceInfo, u.win)
	return true
}

// confirmXRayRestart — перед действием, перезапускающим XRay: предупреждение
// с кнопкой опасного вида; «Отмена» (кнопка диалога) — do не вызывается,
// ничего не пишется. restarts == false — do сразу (rename и т.п.).
func (u *ui) confirmXRayRestart(restarts bool, do func()) {
	if !restarts {
		do()
		return
	}
	body := widget.NewLabel(guiview.XRayRestartBody())
	body.Wrapping = fyne.TextWrapWord
	var d dialog.Dialog
	okBtn := widget.NewButtonWithIcon(guiview.XRayRestartConfirm(), theme.WarningIcon(), func() {
		d.Hide()
		do()
	})
	okBtn.Importance = widget.DangerImportance
	d = dialog.NewCustom(guiview.XRayRestartTitle(), guiview.XRayRestartCancel(), container.NewVBox(body, container.NewHBox(okBtn)), u.win)
	d.Resize(fyne.NewSize(520, 300))
	d.Show()
	u.xrayWarnShown = d
}

// refreshXRay — загрузка списка XRay: записи clientsTable и служебная строка
// в конце. Ошибка — как у управляемых протоколов: таблица прежняя, статус
// говорит, что данные от прошлого чтения.
func (u *ui) refreshXRay(cur *core.Container) {
	goSafe(func() {
		v, err := u.sess.LoadXRayView(cur)
		fyne.Do(func() {
			defer u.setBusy(false)
			if cur != u.cur {
				return
			}
			u.canManage = true
			if err != nil {
				u.status.SetText("Ошибка: " + core.MaskText(err.Error()) + " · показаны данные прошлого чтения.")
				return
			}
			u.xrayView = v
			clients := append([]core.ClientEntry{}, v.Clients...)
			u.peerStats = map[string]core.PeerStat{}
			u.statsFailed = false
			u.clients = clients
			u.applySort()
			// служебная строка — всегда последней, вне сортировки
			u.clients = append(u.clients, core.ClientEntry{ClientID: core.XRayServiceRowID,
				UserData: map[string]any{"clientName": core.XRayServiceName}})
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
	if cl.ClientID == core.XRayServiceRowID {
		u.xrayServiceRow(cl)
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
