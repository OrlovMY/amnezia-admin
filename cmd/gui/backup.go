package main

// Копия пользователей и переезд (5/5): «Копия…» на главном экране —
// сохранить копию сервера (громкое предупреждение «НЕ ЗАШИФРОВАН» в окне
// сохранения, SEC-01) и восстановить из копии на этом (новом) сервере:
// проверка совместимости, предпросмотр, отдельные галки «адрес» и
// «перезапустить XRay», кнопка опасного вида. Ввода пароля нет (Р-1 не
// решён). Тексты — из core (одни с CLI).

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/storage"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"amnezia-admin/core"
	"amnezia-admin/internal/version"
)

// Тексты кнопок (сторожа тестов берут их отсюда).
const (
	backupMenuTitle     = "Копия пользователей"
	backupSaveText      = "Сохранить копию сервера…"
	backupRestoreText   = "Восстановить из копии…"
	backupSaveOK        = "Сохранить"
	restoreApplyText    = "Заменить данные сервера"
	restoreAddrCheck    = "Понимаю: адрес другой или не проверен — выданные конфиги могут не работать"
	restoreXRayCheck    = "Перезапустить XRay (все подключения XRay оборвутся)"
	restoreSkipXRay     = "Перенести без XRay — XRay на новом сервере останется прежним"
	restoreXRayHint     = "Выберите, что делать с XRay:"
	restoreDetailsTitle = "Подробнее о копии (состав по протоколам и файлам)"
	backupCopyPathText  = "Скопировать путь"
	restoreForceText    = "Всё равно записать"
	restoreUsersTitle   = "На новом сервере уже есть пользователи"
	// targetFoldLines — длиннее этого список пользователей и конфликтов
	// сворачивается (число — в заголовке, видно всегда).
	targetFoldLines = 12
)

// requestedSize — заданный размер окон копии (сторож AU-UX р2 Р2-1 сверяет
// его с окном программы: Fyne молча обрезает диалог по окну).
var requestedSize = map[dialog.Dialog]fyne.Size{}

// lastSizedDialog — последнее окно, которому задан размер (для сторожа).
var lastSizedDialog dialog.Dialog

// sizeDialog — единственная точка задания размера окон копии.
func sizeDialog(d dialog.Dialog, s fyne.Size) {
	requestedSize[d] = s
	lastSizedDialog = d
	d.Resize(s)
}

// beforeBackupWork — шов теста: фоновая работа сохранения ждёт, пока тест
// осмотрит окно во время операции.
var beforeBackupWork func()

// fitDialog — размер окна по содержимому (отзыв владельца на 32d66c4:
// «почему окно со скролом, нельзя всё сразу отобразить?»): ширина width
// (не больше окна программы), высота — по содержимому inner, уложенному в
// эту ширину, плюс рамка окна; не больше окна программы — тогда и только
// тогда работает прокрутка. scroll — прокрутка вокруг inner (nil — её нет).
func (u *ui) fitDialog(d dialog.Dialog, inner, scroll fyne.CanvasObject, width float32) {
	win := u.win.Canvas().Size()
	margin := 4 * theme.Padding()
	if win.Width < 1 || win.Height < 1 {
		win = fyne.NewSize(width+2*margin, 600)
	}
	if width > win.Width-2*margin {
		width = win.Width - 2*margin
	}
	// рамка окна: заголовок, кнопки, поля — разница минимумов окна и
	// прокрутки (у прокрутки минимум мал и от содержимого не зависит)
	chromeH := d.MinSize().Height
	if scroll != nil {
		chromeH -= scroll.MinSize().Height
	} else {
		chromeH -= inner.MinSize().Height
	}
	innerW := width - 6*theme.Padding()
	inner.Resize(fyne.NewSize(innerW, inner.MinSize().Height)) // переносы по этой ширине
	need := inner.MinSize().Height + chromeH
	h := need
	if h > win.Height-2*margin {
		h = win.Height - 2*margin
	}
	sizeDialog(d, fyne.NewSize(width, h))
}

// backupResolve — разрешение имён (шов теста).
var backupResolve core.Resolver = net.LookupIP

func (u *ui) backupMenu() {
	if u.busy || u.sess == nil {
		return
	}
	var d dialog.Dialog
	save := widget.NewButtonWithIcon(backupSaveText, theme.DocumentSaveIcon(), func() { d.Hide(); u.backupDialog() })
	restore := widget.NewButtonWithIcon(backupRestoreText, theme.FolderOpenIcon(), func() { d.Hide(); u.restorePick() })
	body := container.NewVBox(
		wrapLabel("Копия нужна для переезда на новый сервер: ключ сервера, клиенты, параметры протоколов. "+core.IssuedConfigsNote, false),
		save, restore)
	d = dialog.NewCustom(backupMenuTitle, "Закрыть", body, u.win)
	u.fitDialog(d, body, nil, 560)
	d.Show()
}

// backupDialog — окно сохранения: предупреждение SEC-01 до записи.
// saveView — окно сохранения (поля — для тестов).
type saveView struct {
	d       dialog.Dialog
	ok      *escButton
	mode    *widget.RadioGroup // с паролем / без пароля — без выбора по умолчанию
	pw, pw2 *widget.Entry
	warn    *widget.Label
	hint    *widget.Label
}

const (
	backupWithPassword = "С паролем (файл зашифрован)"
	backupNoPassword   = "Без пароля (файл НЕ зашифрован)"
	backupModeHint     = "Выберите, защищать ли копию паролем:"
)

// backupDialog — окно сохранения: выбор «с паролем / без пароля» (решение
// владельца по Р-1), поля пароля и повтора, предупреждение выбранного
// режима — всё до записи. «Сохранить» включена только при выбранном режиме
// и (с паролем) совпавшем пароле не короче 12 символов.
func (u *ui) backupDialog() *saveView {
	dir, err := core.UserBackupsDir()
	where := "Файл будет записан в каталог: " + dir
	if err != nil {
		where = "Каталог копий не определён: " + err.Error()
	}
	v := &saveView{}
	v.pw, v.pw2 = widget.NewPasswordEntry(), widget.NewPasswordEntry()
	v.pw.SetPlaceHolder(fmt.Sprintf("Пароль (не короче %d символов)", core.BackupPasswordMin))
	v.pw2.SetPlaceHolder("Повторите пароль")
	v.warn = wrapLabel("", true)
	v.hint = wrapLabel("", false)
	var update func()
	v.mode = widget.NewRadioGroup([]string{backupWithPassword, backupNoPassword}, func(string) { update() })
	v.pw.OnChanged = func(string) { update() }
	v.pw2.OnChanged = func(string) { update() }
	cw := u.confirmWindowBtn("Сохранить копию сервера", []fyne.CanvasObject{
		wrapLabel(backupModeHint, true), v.mode, v.pw, v.pw2, v.hint, v.warn, wrapLabel(where, false),
	}, backupSaveOK, false, func() { u.doBackup(dir, err, v.layer()) }, 760)
	v.d, v.ok = cw.d, cw.ok
	update = func() {
		can := false
		switch v.mode.Selected {
		case backupNoPassword:
			v.pw.Hide()
			v.pw2.Hide()
			v.warn.SetText(core.BackupUnencryptedWarning)
			v.hint.SetText("")
			can = true
		case backupWithPassword:
			v.pw.Show()
			v.pw2.Show()
			v.warn.SetText(core.BackupPasswordWarning)
			verr := core.ValidateBackupPassword(core.NewSecret([]byte(v.pw.Text)))
			switch {
			case verr != nil:
				v.hint.SetText(fmt.Sprintf("Пароль — не короче %d символов.", core.BackupPasswordMin))
			case v.pw.Text != v.pw2.Text:
				v.hint.SetText("Пароли не совпадают.")
			default:
				v.hint.SetText("")
				can = true
			}
		default:
			v.pw.Hide()
			v.pw2.Hide()
			v.warn.SetText("")
			v.hint.SetText("")
		}
		if can {
			v.ok.Enable()
		} else {
			v.ok.Disable()
		}
		cw.refit() // содержимое поменялось — размер по нему
	}
	update()
	return v
}

// layer — слой выбранного режима (nil — не выбран).
func (v *saveView) layer() core.BackupLayer {
	switch v.mode.Selected {
	case backupWithPassword:
		return core.PasswordLayer{Password: core.NewSecret([]byte(v.pw.Text))}
	case backupNoPassword:
		return core.PlainLayer{}
	}
	return nil
}

// runBackupTo — снять копию и записать в dir слоем layer (синхронно; для
// теста и для фоновой задачи).
func (u *ui) runBackupTo(dir string, now time.Time, layer core.BackupLayer) (string, *core.Backup, error) {
	return u.runBackupCtx(context.Background(), dir, now, layer, nil)
}

// runBackupCtx — то же с отменой и прогрессом.
func (u *ui) runBackupCtx(ctx context.Context, dir string, now time.Time, layer core.BackupLayer, progress core.ProgressFunc) (string, *core.Backup, error) {
	if layer == nil {
		return "", nil, errors.New("не выбрано, защищать ли копию паролем — копия не снята")
	}
	b, err := u.sess.CollectBackupCtx(ctx, version.String(), now, backupResolve, progress)
	if err != nil {
		return "", nil, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", b, err
	}
	p, err := core.WriteBackupFileUniqueCtx(ctx, filepath.Join(dir, core.BackupFileName(b.Server.Host, now)), b, layer, progress)
	if err != nil {
		return "", b, err
	}
	return p, b, nil
}

func (u *ui) doBackup(dir string, dirErr error, layer core.BackupLayer) {
	if dirErr != nil {
		u.showError(dirErr)
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	u.setBusy(true)
	pv := u.progressWindow("Сохранение копии сервера", cancel)
	u.lastProgress = pv
	goSafe(func() {
		defer cancel()
		if beforeBackupWork != nil {
			beforeBackupWork()
		}
		p, b, err := u.runBackupCtx(ctx, dir, time.Now(), layer, pv.report)
		fyne.Do(func() {
			u.setBusy(false)
			if u.opFinished(err) {
				return // отменено закрытием программы
			}
			u.backupResult(p, b, err)
			u.closeNotDoneNote()
		})
	})
}

// backupResult — итог: состав копии, абсолютный путь, «Скопировать путь».
func (u *ui) backupResult(path string, b *core.Backup, err error) dialog.Dialog {
	var lines []string
	if b != nil {
		lines = core.BackupSummaryLines(b)
	}
	switch {
	case errors.Is(err, core.ErrCanceled):
		lines = append(lines, "", "Отменено — копия не сохранена.")
	case err != nil:
		lines = append(lines, "", "Копия НЕ записана: "+core.MaskText(err.Error()))
	default:
		lines = append(lines, "", "Копия записана: "+path)
	}
	objs := []fyne.CanvasObject{wrapLabel(strings.Join(lines, "\n"), false)}
	if err == nil {
		objs = append(objs, widget.NewButtonWithIcon(backupCopyPathText, theme.ContentCopyIcon(), func() {
			u.copyToClipboard(path, "Путь к копии скопирован в буфер обмена")
		}))
	}
	d := dialog.NewCustom("Копия сервера", "Закрыть", container.NewVScroll(container.NewVBox(objs...)), u.win)
	sizeDialog(d, fyne.NewSize(640, 420))
	d.Show()
	return d
}

func (u *ui) restorePick() {
	fd := dialog.NewFileOpen(func(r fyne.URIReadCloser, err error) {
		if err != nil {
			u.showError(err)
			return
		}
		if r == nil {
			return
		}
		p := r.URI().Path()
		r.Close()
		u.restoreFromFile(p)
	}, u.win)
	fd.SetFilter(storage.NewExtensionFileFilter([]string{".aabk"}))
	fd.Show()
}

// restorePrepare — чтение копии, проверка цели и план (синхронно, только
// чтение). Ошибка плана возвращается отдельно: окно всё равно показывается
// с её причиной, кнопка замены — выключена.
func (u *ui) restorePrepare(path string, layers ...core.BackupLayer) (*core.Backup, *core.CompatReport, *core.RestorePlan, error, error) {
	if len(layers) == 0 {
		layers = []core.BackupLayer{core.PlainLayer{}}
	}
	b, err := core.ReadBackupFile(path, layers...)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	compat, err := u.sess.CheckTarget(b, backupResolve)
	if err != nil {
		return b, nil, nil, nil, err
	}
	rp, planErr := u.sess.PlanRestore(b, compat, true)
	return b, compat, rp, planErr, nil
}

// restoreFromFile — пароль спрашивается только у зашифрованной копии.
func (u *ui) restoreFromFile(path string) {
	name, err := core.BackupLayerOf(path)
	if err != nil {
		u.showError(err)
		return
	}
	if name == core.PasswordLayerName {
		u.passwordPrompt(func(pw core.Secret) {
			u.restoreWith(path, core.PlainLayer{}, core.PasswordLayer{Password: pw})
		})
		return
	}
	u.restoreWith(path, core.PlainLayer{})
}

// passwordPrompt — пароль зашифрованной копии (окно подтверждения).
func (u *ui) passwordPrompt(onOK func(core.Secret)) (*widget.Entry, *escButton) {
	e := widget.NewPasswordEntry()
	cw := u.confirmWindowBtn("Копия зашифрована", []fyne.CanvasObject{wrapLabel("Введите пароль копии:", true), e},
		"Открыть", false, func() { onOK(core.NewSecret([]byte(e.Text))) })
	cw.ok.Disable()
	e.OnChanged = func(s string) {
		if s == "" {
			cw.ok.Disable()
		} else {
			cw.ok.Enable()
		}
	}
	return e, cw.ok
}

func (u *ui) restoreWith(path string, layers ...core.BackupLayer) {
	// автокопия наследует режим копии-источника
	u.restoreLayer = layers[len(layers)-1]
	u.setBusy(true)
	goSafe(func() {
		b, compat, rp, planErr, err := u.restorePrepare(path, layers...)
		fyne.Do(func() {
			u.setBusy(false)
			if err != nil {
				u.showError(err)
				return
			}
			u.restoreWindow(b, compat, rp, planErr)
		})
	})
}

// restoreView — окно восстановления (поля — для тестов).
type restoreView struct {
	d         dialog.Dialog
	apply     *escButton
	addrCheck *widget.Check
	xrayRadio *widget.RadioGroup // «одно из двух», без выбора по умолчанию
	details   *widget.Accordion  // «Подробнее о копии» (свёрнуто)
	text      string
	// users — отдельное окно «Всё равно записать» (пользователи на новом
	// сервере или конфликты), nil — не открывалось.
	users *targetView
}

// targetView — окно подтверждения записи поверх пользователей нового
// сервера (поля — для тестов).
type targetView struct {
	d     dialog.Dialog
	force *escButton
	list  *widget.Accordion // свёрнутый длинный список; nil — список короткий
	text  string
}

// targetSections — заголовок с числом (всегда виден) и список: короткий —
// как есть, длинный — свёрнут.
func targetSections(rp *core.RestorePlan) ([]fyne.CanvasObject, *widget.Accordion, string) {
	head := core.TargetWarnHead(rp)
	lines := core.TargetWarnLines(rp, 0)
	text := head + "\n" + strings.Join(lines, "\n")
	secs := []fyne.CanvasObject{wrapLabel(head, true)}
	body := wrapLabel(strings.Join(lines, "\n"), false)
	if len(lines) <= targetFoldLines && rp.TargetUserCount() <= targetFoldLines {
		return append(secs, body), nil, text
	}
	acc := widget.NewAccordion(widget.NewAccordionItem(
		fmt.Sprintf("Список: пользователей %d, конфликтов %d", rp.TargetUserCount(), rp.TargetConflictCount()), body))
	return append(secs, acc), acc, text
}

// targetConfirm — отдельное явное подтверждение: запись только кнопкой
// «Всё равно записать» (опасный стиль), фокус на «Отмена».
func (u *ui) targetConfirm(rp *core.RestorePlan, onOK func()) *targetView {
	secs, acc, text := targetSections(rp)
	secs = append(secs, wrapLabel("Перед записью будет снята автокопия этого сервера. Записать, только если эти пользователи вам не нужны или перенесены иначе.", false))
	cw := u.confirmWindowBtn(restoreUsersTitle, secs, restoreForceText, true, onOK, 640)
	return &targetView{d: cw.d, force: cw.ok, list: acc, text: text}
}

// restoreWindow — устройство окна подтверждения XRay (AU-UX H1): «Отмена» и
// «Заменить данные сервера» внизу рядом, фокус на «Отмена», Esc — отмена.
// Разделы: удаляемые клиенты (M2, первым), расхождения при СТОП (списком),
// сводка копии, проверка нового сервера, план; галки. Кнопка замены включена,
// только если нет СТОП, план построен, адрес подтверждён (если нужно) и про
// XRay сделан явный выбор — перезапустить или перенести без него (M1).
func (u *ui) restoreWindow(b *core.Backup, compat *core.CompatReport, rp *core.RestorePlan, planErr error) *restoreView {
	v := &restoreView{}
	var sections []fyne.CanvasObject
	var all []string
	addSection := func(lines []string, bold bool) {
		if len(lines) == 0 {
			return
		}
		sections = append(sections, wrapLabel(strings.Join(lines, "\n"), bold))
		all = append(all, lines...)
	}
	// пользователи нового сервера: здесь — число (заголовок), список и
	// конфликты — в отдельном окне «Всё равно записать» (окно до начала —
	// без прокрутки, отзыв владельца на 32d66c4)
	// Один раздел с удаляемыми (круг 3: пометки «будет заменён…» длиннее —
	// окно до начала остаётся без прокрутки).
	if rp != nil {
		var head []string
		if rp.NeedsTargetConfirm() {
			head = []string{core.TargetWarnHead(rp) + " Список и конфликты — в следующем окне, перед записью."}
		}
		addSection(append(head, core.RemovedLines(rp)...), true)
	}
	addSection(core.CompatStopLines(compat), true)
	if planErr != nil && !compat.Stop {
		addSection([]string{"План не построен: " + core.MaskText(planErr.Error())}, true)
	}
	// Сводка копии (по файлам) — под «Подробнее о копии» (отзыв владельца
	// на 32d66c4: окно до начала — без прокрутки); сверху — одна строка.
	sum := core.BackupSummaryLines(b)
	state := "полная"
	if !b.Complete {
		state = "НЕПОЛНАЯ (подробности — ниже)"
	}
	addSection([]string{fmt.Sprintf("Копия сервера %s от %s — %s.", b.Server.Host, b.CreatedAt, state)}, false)
	all = append(all, sum...)
	v.details = widget.NewAccordion(widget.NewAccordionItem(restoreDetailsTitle, wrapLabel(strings.Join(sum, "\n"), false)))
	sections = append(sections, v.details)
	addSection(core.CompatLines(compat), false)
	if rp != nil {
		addSection(core.RestorePlanLines(rp), false)
	}
	v.text = strings.Join(all, "\n")
	xray := false
	if rp != nil {
		for _, it := range rp.Items {
			xray = xray || it.RestartsXRay
		}
	}
	var update func()
	if compat.NeedAddressConfirm {
		v.addrCheck = widget.NewCheck(restoreAddrCheck, func(bool) { update() })
		sections = append(sections, v.addrCheck)
	}
	if xray {
		sections = append(sections, restartSections()...)
		v.xrayRadio = widget.NewRadioGroup([]string{restoreXRayCheck, restoreSkipXRay}, func(string) { update() })
		sections = append(sections, wrapLabel(restoreXRayHint, true), v.xrayRadio)
	}
	cw := u.confirmWindowBtn("Восстановить из копии на этом сервере", sections, restoreApplyText, true, func() {
		if rp.NeedsTargetConfirm() {
			v.users = u.targetConfirm(rp, func() { u.doRestore(rp, v, true) })
			return
		}
		u.doRestore(rp, v, false)
	}, 900)
	v.d, v.apply = cw.d, cw.ok
	update = func() {
		can := !compat.Stop && planErr == nil && rp != nil && (v.addrCheck == nil || v.addrCheck.Checked)
		if xray {
			// явный выбор про XRay (AU-UX р2 Р2-2)
			can = can && v.xrayRadio.Selected != ""
		}
		if can {
			v.apply.Enable()
		} else {
			v.apply.Disable()
		}
	}
	update()
	return v
}

// runRestore — замена (синхронно; для теста и для фоновой задачи).
// targetOK — отдельное подтверждение записи поверх пользователей нового
// сервера («Всё равно записать»).
func (u *ui) runRestore(rp *core.RestorePlan, xrayOK, targetOK bool, now time.Time) (string, []core.RestoreOutcome, error) {
	return u.runRestoreCtx(context.Background(), rp, xrayOK, targetOK, now, nil)
}

// runRestoreCtx — то же с отменой (до первой записи) и прогрессом.
func (u *ui) runRestoreCtx(ctx context.Context, rp *core.RestorePlan, xrayOK, targetOK bool, now time.Time, progress core.ProgressFunc) (string, []core.RestoreOutcome, error) {
	dir, err := core.UserBackupsDir()
	if err == nil {
		err = os.MkdirAll(dir, 0o700)
	}
	if err != nil {
		return "", nil, errors.New("каталог автокопии не определён — замена запрещена: " + err.Error())
	}
	layer := u.restoreLayer
	if layer == nil {
		layer = core.PlainLayer{}
	}
	return u.sess.Restore(rp, core.RestoreOptions{AutoCopyDir: dir, ToolVersion: version.String(), Now: now,
		Resolve: backupResolve, Layer: layer, ConfirmXRay: func() bool { return xrayOK }, TargetConfirmed: targetOK, Ctx: ctx, Progress: progress})
}

func (u *ui) doRestore(rp *core.RestorePlan, v *restoreView, targetOK bool) {
	xrayOK := v.xrayRadio != nil && v.xrayRadio.Selected == restoreXRayCheck
	v.d.Hide()
	ctx, cancel := context.WithCancel(context.Background())
	u.setBusy(true)
	pv := u.progressWindow("Восстановление из копии", cancel)
	u.lastProgress = pv
	goSafe(func() {
		defer cancel()
		auto, outs, err := u.runRestoreCtx(ctx, rp, xrayOK, targetOK, time.Now(), pv.report)
		fyne.Do(func() {
			u.setBusy(false)
			u.restoreFinished(auto, outs, err)
		})
	})
}

// restoreFinished — конец восстановления (в потоке интерфейса).
func (u *ui) restoreFinished(auto string, outs []core.RestoreOutcome, err error) {
	if u.opFinished(err) {
		return // отменено закрытием программы, на сервер ничего не записано
	}
	u.restoreResult(auto, outs, err)
	u.closeNotDoneNote()
	u.refresh()
}

func (u *ui) restoreResult(auto string, outs []core.RestoreOutcome, err error) dialog.Dialog {
	text := ""
	switch {
	case errors.Is(err, core.ErrCanceled):
		text = "Отменено — на сервер ничего не записано."
		if auto != "" {
			text += "\nАвтокопия нового сервера уже сохранена: " + auto
		}
	case err != nil:
		text = "Ничего не записано: " + core.MaskText(err.Error())
	default:
		enc := u.restoreLayer != nil && u.restoreLayer.Name() == core.PasswordLayerName
		text = strings.Join(core.RestoreOutcomeLines(auto, enc, outs), "\n")
	}
	d := dialog.NewCustom("Итог восстановления", "Закрыть", container.NewVScroll(wrapLabel(text, false)), u.win)
	sizeDialog(d, fyne.NewSize(640, 420))
	d.Show()
	return d
}
