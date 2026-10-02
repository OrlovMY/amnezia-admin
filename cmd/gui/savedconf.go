package main

// Окно «Конфигурация клиента» — пункты контекстного меню строки «Показать
// QR» и «Сохранить конфигурацию…» (задача владельца 01.10.2026).
//
// Приватный ключ клиента сервер не хранит; конфиг берётся из .conf, который
// программа сохранила на этом компьютере, — по ПУБЛИЧНОМУ ключу, не по имени
// (core.FindSavedConfig). Три состояния поиска — три разных окна. Конфиг
// содержит приватный ключ: он попадает только в QR и в файл, выбранный
// человеком, — не в строку состояния, не в тексты ошибок.

import (
	"errors"
	"fmt"
	"os"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/storage"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"amnezia-admin/core"
	"amnezia-admin/internal/guiview"
)

// savedConfigsDir — каталог конфигураций (тесты задают LOCALAPPDATA/
// XDG_CONFIG_HOME, TestMain — свой каталог по умолчанию).
var savedConfigsDir = core.UserConfigsDir

// legacyConfigDirs — каталоги прежних версий; TestMain уводит их во
// временный каталог, чтобы тест не прочитал настоящие «Конфигурации».
var legacyConfigDirs = core.LegacyConfigDirs

// savedSearchDirs — где искать: каталог этой версии, затем прежних.
func savedSearchDirs() []core.SavedDir {
	dir, err := savedConfigsDir()
	return append([]core.SavedDir{{Path: dir, Err: err}}, legacyConfigDirs()...)
}

// showSavedConfig — окно сохранённого конфига клиента строки row. save —
// сразу предложить сохранить в выбранное место (пункт «Сохранить
// конфигурацию…»).
func (u *ui) showSavedConfig(row int, save bool) {
	if row < 0 || row >= len(u.clients) {
		return
	}
	cl := u.clients[row]
	sc := core.FindSavedConfigIn(savedSearchDirs(), cl.ClientID)
	title := guiview.SavedConfigTitle(cl.Name())
	switch sc.State {
	case core.SavedFound:
		u.showFoundConfig(title, cl, sc, save)
	case core.SavedNotFound:
		text := widget.NewLabel(guiview.SavedNotFoundText(sc.Searched))
		text.Wrapping = fyne.TextWrapWord
		var d dialog.Dialog
		box := container.NewVBox(text)
		if u.canManage && u.cur != nil && u.cur.Managed {
			// UX-01 П1: кнопка не должна выглядеть безобидным «обновить».
			rekey := widget.NewButtonWithIcon(guiview.SavedRekeyButton, theme.WarningIcon(), func() {
				d.Hide()
				// СУЩЕСТВУЮЩИЙ поток перевыпуска — с его подтверждением и
				// предупреждением; ничего автоматически.
				u.selectedRow = row
				u.regenerateSelected()
			})
			rekey.Importance = widget.DangerImportance
			box.Add(rekey)
		}
		d = dialog.NewCustom(title, "Закрыть", box, u.win)
		d.Resize(fyne.NewSize(480, 220))
		d.Show()
	default:
		text := widget.NewLabel(guiview.SavedUnreadableText(sc.Why))
		text.Wrapping = fyne.TextWrapWord
		d := dialog.NewCustom(title, "Закрыть", text, u.win)
		d.Resize(fyne.NewSize(480, 220))
		d.Show()
	}
}

func (u *ui) showFoundConfig(title string, cl core.ClientEntry, sc core.SavedConfig, save bool) {
	from := widget.NewLabel(guiview.SavedFoundText(sc))
	from.Wrapping = fyne.TextWrapWord
	check := widget.NewLabel(guiview.SavedCheckPending)
	check.Wrapping = fyne.TextWrapWord
	// QR — только после сверки ключа сервера (SEC-01 R1): не совпал — скрыт,
	// показ — по явному «Всё равно показать QR».
	// QR в дерево окна не входит вовсе, пока не разрешён: Hide ненадёжен —
	// показ диалога показывает всё содержимое.
	qr := qrObject(cl.Name(), sc.Config)
	qrBox := container.NewCenter()
	showQR := func() {
		if len(qrBox.Objects) == 0 {
			qrBox.Add(qr)
		}
	}
	var anyway, unverified, stale *widget.Button
	stale = widget.NewButton(guiview.SavedShowQRStale, func() {
		showQR()
		stale.Hide()
	})
	anyway = widget.NewButton(guiview.SavedShowQRAnyway, func() {
		showQR()
		anyway.Hide()
	})
	unverified = widget.NewButton(guiview.SavedShowQRUnverified, func() {
		showQR()
		unverified.Hide()
	})

	path := sc.Path
	copyBtn := widget.NewButtonWithIcon("Скопировать путь", theme.ContentCopyIcon(), func() {
		fyne.CurrentApp().Clipboard().SetContent(path)
		if u.status != nil {
			u.status.SetText("Путь скопирован в буфер обмена")
		}
	})
	config := sc.Config
	name := cl.Name()
	saveBtn := widget.NewButtonWithIcon("Сохранить ещё в…", theme.DocumentSaveIcon(), func() {
		u.saveConfigAs(name, config)
	})
	// АУДИТ-МЕНЮ-QR-UX Н1: QR — вне прокрутки, сверху, целиком; пока он не
	// разрешён, место пустое, и кнопки показа — первыми под сверкой.
	info := container.NewVScroll(container.NewVBox(check, anyway, unverified, stale, from))
	content := container.NewBorder(qrBox, container.NewVBox(saveBtn, copyBtn), nil, nil, info)
	d := dialog.NewCustom(title, "Закрыть", content, u.win)
	d.Resize(fyne.NewSize(480, 560))
	d.Show()
	anyway.Hide() // после показа: d.Show() показывает всё содержимое
	unverified.Hide()
	stale.Hide()

	// Сверка с сервером — после показа: файл уже прочитан, сеть может быть
	// медленной. Не удалось — «не сверено», а не «совпадает».
	done := func(ch core.SavedCheck) {
		check.SetText(guiview.SavedCheckText(ch))
		switch qrDecision(ch) {
		case qrAuto:
			showQR()
			if save {
				u.saveConfigAs(name, config)
			}
		case qrForeign:
			anyway.Show() // окно сохранения само не открывается
		case qrStale:
			stale.Show()
		default:
			unverified.Show() // не сверено — ни QR, ни окна сохранения сами
		}
	}
	sess, ctr := u.sess, u.cur
	if sess == nil || ctr == nil {
		done(core.CheckSavedConfig(config, core.ServerPeer{}, errors.New("нет подключения к серверу")))
	} else {
		goSafe(func() {
			sp, err := sess.ClientPeerParams(ctr, cl)
			ch := core.CheckSavedConfig(config, sp, err)
			fyne.Do(func() { done(ch) })
		})
	}
}

// qrMode — что делать с QR и окном сохранения по итогу сверки ключа
// сервера. Три состояния (SEC-01 R1-a, признак 1): САМИ — только при
// «совпал»; «не совпал» и «не сверен» — по явной кнопке, у каждого своя.
type qrMode int

const (
	qrUnverified qrMode = iota // нулевое — «не сверен»: осторожная сторона
	qrAuto
	qrForeign
	qrStale // ключ сервера совпал, а PSK или адрес в файле — нет
)

// qrDecision — сам QR и само окно сохранения ТОЛЬКО если совпали ВСЕ три
// сверки (решение ядра, раунд 5): заведомо устаревший файл без явного шага
// не выдаётся.
func qrDecision(ch core.SavedCheck) qrMode {
	switch {
	case ch.ServerKey == core.CheckDiffer:
		return qrForeign
	case ch.ServerKey == core.CheckSame && ch.PSK == core.CheckSame && ch.Address == core.CheckSame:
		return qrAuto
	case ch.PSK == core.CheckDiffer || ch.Address == core.CheckDiffer:
		return qrStale
	}
	return qrUnverified
}

// qrObject — QR конфига или честная надпись, что QR построить не удалось
// (текст ошибки QR не содержит конфига).
func qrObject(name, config string) fyne.CanvasObject {
	png, err := core.QRPNG(config, 256)
	if err != nil {
		l := widget.NewLabel("Не удалось построить QR-код: " + err.Error())
		l.Wrapping = fyne.TextWrapWord
		return l
	}
	img := canvas.NewImageFromResource(fyne.NewStaticResource(core.SanitizeName(name)+"-qr.png", png))
	img.FillMode = canvas.ImageFillOriginal
	img.SetMinSize(fyne.NewSize(256, 256))
	return img
}

// errPermsNotLimited — файл записан, но права 0600 поставить не удалось.
var errPermsNotLimited = errors.New("права доступа не ограничены")

// chmodChosen — шов для теста отказа chmod.
var chmodChosen = os.Chmod

// writeChosenConfig — запись в файл, выбранный в окне сохранения, и права
// 0600 (SEC-01 M1): окно Fyne создаёт файл с правами по умолчанию (0644 на
// Unix) — приватный ключ клиента прочли бы все пользователи компьютера.
// Ошибка chmod — громко: файл записан, но открыт другим.
func writeChosenConfig(w fyne.URIWriteCloser, config string) (string, error) {
	where := w.URI().Path()
	_, werr := w.Write([]byte(config))
	cerr := w.Close()
	if werr == nil {
		werr = cerr
	}
	if werr != nil {
		return where, fmt.Errorf("конфиг НЕ сохранён в %s: %w", where, werr)
	}
	if w.URI().Scheme() == "file" {
		if err := chmodChosen(where, 0o600); err != nil {
			return where, fmt.Errorf("конфиг сохранён в %s, но %w (%v): файл с приватным ключом клиента могут прочитать другие пользователи этого компьютера", where, errPermsNotLimited, err)
		}
	}
	return where, nil
}

// saveConfigAs — «Сохранить ещё в…»: системное окно выбора файла, запись
// туда. Ошибка — диалогом (тексты файловой системы, без содержимого).
func (u *ui) saveConfigAs(name, config string) {
	fd := dialog.NewFileSave(func(w fyne.URIWriteCloser, err error) {
		if err != nil {
			u.showError(err)
			return
		}
		if w == nil {
			return // отмена
		}
		where, err := writeChosenConfig(w, config)
		if err != nil {
			u.showError(err)
			if errors.Is(err, errPermsNotLimited) && u.status != nil {
				u.status.SetText("Конфиг сохранён, но права НЕ ограничены: " + where)
			}
			return
		}
		if u.status != nil {
			u.status.SetText("Конфиг сохранён: " + where)
		}
	}, u.win)
	fd.SetFileName(core.SanitizeName(name) + ".conf")
	fd.SetFilter(storage.NewExtensionFileFilter([]string{".conf"}))
	fd.Show()
}
