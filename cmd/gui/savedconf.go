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
	if u.cur != nil && core.IsXRay(u.cur) {
		// XRay (AL-01): конфиг собирается с сервера — UUID хранится там.
		u.showXRayConfig(cl)
		return
	}
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
		if u.canManage && u.cur != nil && u.cur.Managed() {
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
	qr, qrNote := qrObjectNote(cl.Name(), sc.Config, u.savedQRContainer())
	if qrNote != "" {
		from.SetText(from.Text + "\n\n" + qrNote)
	}
	qrBox := container.NewVBox()
	showQR := func() {
		if len(qrBox.Objects) == 0 {
			qrBox.Add(qrSlot(qr))
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
	// Кнопки в ряд: под QR формата AmneziaVPN — строка листания, и на окне
	// 857×517 двум кнопкам столбиком места нет.
	content := container.NewBorder(qrBox, container.NewGridWithColumns(2, saveBtn, copyBtn), nil, nil, info)
	d := dialog.NewCustom(title, "Закрыть", content, u.win)
	d.Resize(configDialogSize(u.win.Canvas(), 480))
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
//
// Контейнер известен (WireGuard/AmneziaWG) — по умолчанию QR формата
// AmneziaVPN (core.AmneziaQRSeries): только в нём приложение получает
// заголовок сервера (description = адрес выдачи). Из текстового .conf оно
// берёт «Сервер N» (importController.cpp:643). Текстовый QR влезает —
// он доступен кнопкой «Текстовый QR» (AmneziaWG, WireGuard). Не влезает —
// только серия. Серию не построить — текстовый QR, а не влез и он —
// надпись с обеими причинами.
//
// note — что сказать человеку рядом: текстовый QR влез, а QR AmneziaVPN
// не построен или протокол неизвестен (приложение назовёт сервер «Сервер N»);
// "" — сказать нечего.
func qrObjectNote(name, config, containerName string) (obj fyne.CanvasObject, note string) {
	png, err := core.QRPNG(config, 256)
	if err == nil && containerName == "" {
		// Протокол неизвестен (u.cur == nil в «Показать QR»): серию не
		// строим — тип не угадывается, — но и молчать нельзя: из текстового
		// QR приложение возьмёт «Сервер N» (ревью: третье состояние).
		note = qrNoContainerNote
	}
	if err == nil && containerName != "" {
		pngs, serr := core.AmneziaQRSeries(config, containerName)
		switch {
		case serr == nil:
			s := newQRSeries(name, pngs)
			s.setAlt(png)
			return s, ""
		case !errors.Is(serr, core.ErrAmneziaQRContainer):
			// XRay (ErrAmneziaQRContainer) — не потеря: заголовок несёт
			// метка ссылки vless://. Остальное — сказать вслух.
			note = "QR формата AmneziaVPN не построен (" + serr.Error() +
				"); при сканировании текстового QR приложение AmneziaVPN назовёт сервер «Сервер N»."
		}
	}
	var big *core.QRTooLargeError
	if errors.As(err, &big) && containerName != "" {
		pngs, serr := core.AmneziaQRSeries(config, containerName)
		if serr == nil {
			return newQRSeries(name, pngs), ""
		}
		err = fmt.Errorf("%w; серия QR AmneziaVPN не построена: %v", err, serr)
	}
	if err != nil {
		l := widget.NewLabel("Не удалось построить QR-код: " + err.Error())
		l.Wrapping = fyne.TextWrapWord
		return l, ""
	}
	img := canvas.NewImageFromResource(fyne.NewStaticResource(core.SanitizeName(name)+"-qr.png", png))
	img.FillMode = canvas.ImageFillOriginal
	img.SetMinSize(fyne.NewSize(256, 256))
	return img, note
}

// qrNoContainerNote — пометка, когда протокол сервера неизвестен.
const qrNoContainerNote = "Протокол сервера не выбран — QR формата AmneziaVPN не построен; " +
	"при сканировании текстового QR приложение AmneziaVPN назовёт сервер «Сервер N»."

// qrSeries — серия QR формата AmneziaVPN: один код на виду, «QR i из N»,
// кнопки «Назад»/«Далее». Сканер приложения собирает куски по номеру в
// заголовке: порядок любой, повтор безвреден, таймера нет — автопереключение
// не нужно, человек листает сам.
type qrSeries struct {
	widget.BaseWidget
	name       string
	pngs       [][]byte
	idx        int
	img        *canvas.Image
	pos        *widget.Label
	caption    *widget.Label
	side       bool
	prev, next *widget.Button
	box        *fyne.Container
	// alt — текстовый QR (.conf) для AmneziaWG/WireGuard; nil — не влез.
	alt     []byte
	altMode bool
	altBtn  *widget.Button
}

// qrSeriesCaption — подпись серии: какое приложение её читает.
const qrSeriesCaption = "Сканируйте в приложении AmneziaVPN"

func newQRSeries(name string, pngs [][]byte) *qrSeries {
	s := &qrSeries{name: core.SanitizeName(name), pngs: pngs}
	s.img = canvas.NewImageFromResource(nil)
	s.img.FillMode = canvas.ImageFillContain
	s.img.ScaleMode = canvas.ImageScalePixels
	s.img.SetMinSize(fyne.NewSize(256, 256))
	s.pos = widget.NewLabelWithStyle("", fyne.TextAlignCenter, fyne.TextStyle{Bold: true})
	s.prev = widget.NewButtonWithIcon("Назад", theme.NavigateBackIcon(), func() { s.show(s.idx - 1) })
	s.next = widget.NewButtonWithIcon("Далее", theme.NavigateNextIcon(), func() { s.show(s.idx + 1) })
	s.next.IconPlacement = widget.ButtonIconTrailingText
	s.pos.Truncation = fyne.TextTruncateEllipsis
	s.caption = widget.NewLabel(qrSeriesCaption)
	s.altBtn = widget.NewButton(qrTextButton, func() {
		s.altMode = !s.altMode
		s.show(s.idx)
	})
	s.altBtn.Hide()
	s.box = container.NewVBox(
		container.NewCenter(s.img),
		s.navRow(),
	)
	s.ExtendBaseWidget(s)
	s.show(0)
	return s
}

// Подписи переключателя «серия AmneziaVPN ↔ текстовый QR».
const (
	qrTextButton   = "Текстовый QR"
	qrSeriesButton = "QR для AmneziaVPN"
	qrTextCaption  = "Текстовый QR: AmneziaWG, WireGuard"
)

func (s *qrSeries) navRow() fyne.CanvasObject {
	return container.NewBorder(nil, nil, s.prev, container.NewHBox(s.next, s.altBtn), s.pos)
}

// setAlt — текстовый QR как вторая форма (кнопка «Текстовый QR»).
func (s *qrSeries) setAlt(png []byte) {
	s.alt = png
	s.altBtn.Show()
	s.show(s.idx)
}

// show — показать код i (за краями — ничего не делает).
func (s *qrSeries) show(i int) {
	if i < 0 || i >= len(s.pngs) {
		return
	}
	s.idx = i
	if s.altMode && s.alt != nil {
		s.img.Resource = fyne.NewStaticResource(s.name+"-text-qr.png", s.alt)
		s.img.Refresh()
		s.caption.SetText(qrTextCaption)
		s.setPos(qrTextCaption)
		s.altBtn.SetText(qrSeriesButton)
		s.prev.Hide()
		s.next.Hide()
		return
	}
	s.altBtn.SetText(qrTextButton)
	s.caption.SetText(qrSeriesCaption)
	s.prev.Show()
	s.next.Show()
	s.img.Resource = fyne.NewStaticResource(fmt.Sprintf("%s-%d-qr.png", s.name, i+1), s.pngs[i])
	s.img.Refresh()
	switch {
	case len(s.pngs) == 1:
		// Один код — листать нечего: без «Назад/Далее» и «1 из 1».
		s.prev.Hide()
		s.next.Hide()
		s.setPos(qrSeriesCaption)
	case s.side:
		s.setPos(fmt.Sprintf("QR %d из %d", i+1, len(s.pngs)))
	default:
		s.setPos(fmt.Sprintf("QR %d из %d · %s", i+1, len(s.pngs), qrSeriesCaption))
	}
	if i == 0 {
		s.prev.Disable()
	} else {
		s.prev.Enable()
	}
	if i == len(s.pngs)-1 {
		s.next.Disable()
	} else {
		s.next.Enable()
	}
}

// setPos — строка над/рядом с кодом. В боковой раскладке подпись «что
// сканировать» несёт s.caption; если pos сказал бы то же самое (один код,
// текстовый QR), pos скрыт — подпись ровно один раз (ревью: дубль).
func (s *qrSeries) setPos(text string) {
	s.pos.SetText(text)
	if s.side && text == s.caption.Text {
		s.pos.Hide()
		return
	}
	s.pos.Show()
}

// setSide — раскладка «код слева, справа — листание, подпись и extra»
// (окно со строкой честности AmneziaWG 2). Вызывать до показа.
func (s *qrSeries) setSide(extra fyne.CanvasObject) {
	s.side = true
	s.box.Objects = []fyne.CanvasObject{container.NewBorder(nil, nil, container.NewCenter(s.img), nil,
		container.NewVBox(s.navRow(), s.caption, extra))}
	s.show(s.idx)
}

func (s *qrSeries) CreateRenderer() fyne.WidgetRenderer {
	return widget.NewSimpleRenderer(s.box)
}

// savedQRContainer — контейнер для серии QR в «Показать QR»: текущий
// протокол. Не выбран — "" (не знаем): серии нет, тип не угадывается.
func (u *ui) savedQRContainer() string {
	if u.cur == nil {
		return ""
	}
	return u.cur.Name
}

// isQRShown —на месте QR код (одиночный или серия), а не надпись об ошибке.
func isQRShown(o fyne.CanvasObject) bool {
	switch o.(type) {
	case *canvas.Image, *qrSeries:
		return true
	}
	return false
}

// qrSlot — место QR в окне. Картинка — по центру, своего размера. Надпись
// «QR не построен» — НА ВСЮ ширину: в Center перенос по словам получает
// минимальную ширину (одну букву) и идёт столбиком (находка владельца 12.10).
func qrSlot(o fyne.CanvasObject) fyne.CanvasObject {
	if _, ok := o.(*canvas.Image); ok {
		return container.NewCenter(o)
	}
	return o
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
	u.saveConfigAsExt(name, config, ".conf")
}

// saveConfigAsExt — saveConfigAs с расширением (XRay — .json, AL-01).
func (u *ui) saveConfigAsExt(name, config, ext string) {
	fd := dialog.NewFileSave(func(w fyne.URIWriteCloser, err error) {
		if err != nil {
			u.showError(err) // сторож PR-3: только через showError
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
	fd.SetFileName(core.SanitizeName(name) + ext)
	fd.SetFilter(storage.NewExtensionFileFilter([]string{ext}))
	fd.Show()
}
