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
			rekey := widget.NewButtonWithIcon("Перевыпустить…", theme.ViewRefreshIcon(), func() {
				d.Hide()
				// СУЩЕСТВУЮЩИЙ поток перевыпуска — с его подтверждением и
				// предупреждением; ничего автоматически.
				u.selectedRow = row
				u.regenerateSelected()
			})
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
	qr := qrObject(cl.Name(), sc.Config)

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
	info := container.NewVScroll(container.NewVBox(from, check, container.NewCenter(qr)))
	content := container.NewBorder(nil, container.NewVBox(saveBtn, copyBtn), nil, nil, info)
	d := dialog.NewCustom(title, "Закрыть", content, u.win)
	d.Resize(fyne.NewSize(480, 560))
	d.Show()

	// Сверка с сервером — после показа: файл уже прочитан, сеть может быть
	// медленной. Не удалось — «не сверено», а не «совпадает».
	sess, ctr := u.sess, u.cur
	if sess == nil || ctr == nil {
		check.SetText(guiview.SavedCheckText(core.CheckSavedConfig(config, "", "", errors.New("нет подключения к серверу"))))
	} else {
		goSafe(func() {
			psk, addr, err := sess.ClientPeerParams(ctr, cl)
			ch := core.CheckSavedConfig(config, psk, addr, err)
			fyne.Do(func() { check.SetText(guiview.SavedCheckText(ch)) })
		})
	}
	if save {
		u.saveConfigAs(name, config)
	}
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

// saveConfigAs — «Сохранить ещё в…»: системное окно выбора файла, запись
// туда. Ошибка — диалогом (тексты файловой системы, без содержимого).
func (u *ui) saveConfigAs(name, config string) {
	fd := dialog.NewFileSave(func(w fyne.URIWriteCloser, err error) {
		if err != nil {
			dialog.ShowError(err, u.win)
			return
		}
		if w == nil {
			return // отмена
		}
		where := w.URI().Path()
		_, werr := w.Write([]byte(config))
		cerr := w.Close()
		if werr == nil {
			werr = cerr
		}
		if werr != nil {
			dialog.ShowError(fmt.Errorf("конфиг НЕ сохранён в %s: %w", where, werr), u.win)
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
