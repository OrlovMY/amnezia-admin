package main

// «Перенести на сервер…» (Б3): прямой переезд «на лету» из окна «Копия…».
// Источник — текущий подключённый сервер (только чтение), цель — ключ vpn://
// нового сервера. Копия источника на диск НЕ пишется; на диск пишется только
// автокопия цели перед заменой. Ядро — core/migrate_direct.go, образец — CLI
// (cmd/cli/migrate.go). Тексты проверки, плана и итога — из core.
//
// Три состояния есть в двух местах, и оба нарочно не сводятся к «да/нет»:
//   - «один ли это сервер»: да / нет / узнать не удалось (клон VPS с тем же
//     ключом хоста при другом адресе — «не знаем», а не «один сервер»);
//   - итог: перенесено / не перенесено / неизвестно (связь потеряна).
//     Нулевое значение migState — «неизвестно».

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/widget"

	"amnezia-admin/core"
	"amnezia-admin/internal/version"
)

// Тексты (сторожа тестов берут их отсюда).
const (
	migrateMenuText        = "Перенести на сервер…"
	migrateAskTitle        = "Перенос на новый сервер"
	migrateAskNext         = "Продолжить"
	migrateApplyText       = "Перенести на новый сервер"
	migrateWinTitle        = "Перенос на новый сервер"
	migrateNoDiskText      = "Копия старого сервера на диск не записывалась: её данные только в памяти программы."
	migrateSrcSafeText     = "Старый сервер продолжает работать: он только читался и не изменён."
	migrateXRayRestart     = "Перезапустить XRay (подключения XRay оборвутся)"
	migrateXRaySkip        = "Без XRay (на новом сервере останется прежний)"
	migrateAddrConsequence = "Если адрес выдачи другой или не проверен, старые конфиги клиентов к новому серверу НЕ придут, пока адрес не перенесён на него у хостера."
	migrateAutoCopyAsk     = "Автокопия НОВОГО сервера (его состояние до замены) будет сохранена на диск. Защитить её паролем?"
	migrateAutoCopyNote    = "Перед заменой программа сохранит на диск АВТОКОПИЮ НОВОГО сервера (его нынешнее состояние; источник на диск не пишется)."
	migrateReasonStop      = "«Перенести» недоступна: проверка нового сервера нашла расхождения или план не построен (см. выше)."
	migrateReasonAddr      = "«Перенести» недоступна: подтвердите адрес (галка выше)."
	migrateReasonXRay      = "«Перенести» недоступна: выберите, что делать с XRay."
	migrateReasonMode      = "«Перенести» недоступна: выберите, защищать ли автокопию паролем."
	migrateReasonPwShort   = "«Перенести» недоступна: пароль автокопии — не короче %d символов."
	migrateReasonPwDiff    = "«Перенести» недоступна: пароли не совпадают."
	migrateReasonReady     = "Всё подтверждено — можно переносить."
	migrateAddrHint        = "Адрес выдачи у источника неизвестен (в ключе IP, адрес для клиентов не выбран). Чтобы подтверждать его не пришлось, подключитесь к старому серверу с заданным адресом для клиентов."
)

// migState — итог переноса. Нулевое значение — НЕИЗВЕСТНО: если ничего не
// решило иначе, программа не знает, а не «перенесено» и не «не перенесено».
type migState int

const (
	migUnknown migState = iota
	migDone
	migNotDone
)

// migrateVerdict — заголовок итога. Порядок ветвей важен: «неизвестно»
// проверяется РАНЬШЕ «частично/не перенесено» и «перенесено» (иначе
// неизвестный контейнер потерялся бы среди остальных).
func migrateVerdict(err error, outs []core.RestoreOutcome) (migState, string) {
	if err != nil {
		if errors.Is(err, core.ErrCanceled) {
			return migNotDone, "НЕ ПЕРЕНЕСЕНО — отменено. На новый сервер ничего не записано."
		}
		return migNotDone, "НЕ ПЕРЕНЕСЕНО — на новый сервер ничего не записано."
	}
	if len(outs) == 0 {
		return migUnknown, "НЕИЗВЕСТНО — итог не получен. Программа не знает, что записано на новом сервере; это не «перенесено» и не «не перенесено»."
	}
	done := 0
	for _, o := range outs {
		if o.State == core.RestoreUnknown {
			return migUnknown, "НЕИЗВЕСТНО — связь потеряна или запись оборвалась. Программа не знает, что записано на новом сервере; это не «перенесено» и не «не перенесено». Проверьте новый сервер вручную."
		}
		if o.State == core.RestoreDone {
			done++
		}
	}
	switch {
	case done == len(outs):
		return migDone, "ПЕРЕНЕСЕНО — все контейнеры заменены и проверены на новом сервере."
	case done > 0:
		return migNotDone, "ПЕРЕНЕСЕНО ЧАСТИЧНО — часть контейнеров заменена и не откатывается, остальные НЕ перенесены (подробности ниже)."
	}
	return migNotDone, "НЕ ПЕРЕНЕСЕНО — на новый сервер ничего не перенесено (подробности ниже)."
}

// migrateSameText — текст остановки, когда не доказано, что серверы разные.
// Состояний три: «один и тот же» и «узнать не удалось» говорятся по-разному.
func migrateSameText(v core.SameServerVerdict, why string) string {
	if v == core.SameYes {
		return "ПЕРЕЕЗД ОСТАНОВЛЕН: это один и тот же сервер (" + why + "). Переезд сервера на самого себя не выполняется."
	}
	return "ПЕРЕЕЗД ОСТАНОВЛЕН: узнать не удалось, один ли это сервер — " + why + ". " +
		"Пока не доказано, что серверы разные, программа ничего не читает и не пишет. На серверах ничего не изменено."
}

// migrateSide — строка про сторону переезда: адрес и отпечаток ключа хоста.
func migrateSide(role string, s *core.Session) string {
	host, port := "?", "?"
	if s != nil && s.Creds != nil {
		host = s.Creds.Host
		if s.Creds.Port != "" { // пустой порт — «не знаем», не «22»
			port = s.Creds.Port
		}
	}
	fp := "не определён"
	if s != nil && s.HostKeyFingerprint != "" {
		fp = s.HostKeyFingerprint
	}
	return fmt.Sprintf("%s: %s:%s, ключ хоста %s", role, host, port, fp)
}

// migClose — закрытие сессии цели (шов теста: видно, что закрыто).
var migClose = func(s *core.Session) { s.Close() }

// closeMigDst — закрыть сессию цели, если она ещё открыта (SSH root на новый
// сервер не должен висеть без видимого признака): «Отмена» окон переноса,
// смена источника, выход из программы, конец переноса.
func (u *ui) closeMigDst() {
	if u.toHostLogin != nil { // пароль входа нового сервера (режим по IP)
		u.toHostLogin.Wipe()
		u.toHostLogin = nil
	}
	if u.migDst != nil {
		migClose(u.migDst)
		u.migDst = nil
	}
}

// migrateConnect — подключение к цели (шов теста). Ключ хоста — тем же
// TOFU/known_hosts, что и при обычном подключении.
var migrateConnect = func(creds *core.ServerCreds, pol core.HostKeyPolicy) (*core.Session, error) {
	return core.ConnectWithHostKey(creds, pol)
}

// migrateAsk — первый шаг: какой новый сервер. Режимы: «Сервер с Amnezia
// (ключ vpn://)» — как было (выбран по умолчанию), и «Новый чистый сервер
// (по IP/имени)» — migrate_tohost.go.
func (u *ui) migrateAsk() *escButton {
	if u.busy || u.sess == nil {
		return nil
	}
	e := widget.NewPasswordEntry() // ключ содержит пароль/SSH-ключ: не показывать
	e.SetPlaceHolder("vpn://…")
	keyHint := wrapLabel("Ключ нового сервера:", true)
	var ok *escButton
	mode := widget.NewRadioGroup([]string{migrateModeKey, migrateModeHost}, nil)
	mode.Required = true
	cw := u.confirmWindowBtn(migrateAskTitle, []fyne.CanvasObject{
		wrapLabel("Источник — сервер, к которому вы сейчас подключены (только чтение). Цель — НОВЫЙ сервер. "+
			"Данные старого сервера пойдут на новый напрямую, из памяти, без записи копии на диск. Перед заменой программа сохранит на диск автокопию нового сервера.", false),
		wrapLabel("Новый сервер:", true), mode,
		keyHint, e,
	}, migrateAskNext, false, func() {
		if mode.Selected == migrateModeHost {
			e.SetText("")
			u.toHostConnect("", "22", "root", "")
			return
		}
		key := e.Text
		e.SetText("")
		u.migrateStart(key)
	}, 640)
	ok = cw.ok
	update := func() {
		host := mode.Selected == migrateModeHost
		if host {
			keyHint.Hide()
			e.Hide()
		} else {
			keyHint.Show()
			e.Show()
		}
		if host || mode.Selected == migrateModeKey && strings.TrimSpace(e.Text) != "" {
			ok.Enable()
		} else {
			ok.Disable()
		}
		cw.refit()
	}
	e.OnChanged = func(string) { update() }
	mode.OnChanged = func(string) { update() }
	mode.SetSelected(migrateModeKey) // как было: режим ключа
	u.focusField(e)
	return ok
}

// migrateStart — подключение к цели, сверка «один ли сервер», чтение
// источника и проверка цели: всё вне потока интерфейса, с прогрессом и
// отменой. Ключ в окна и ошибки не попадает.
func (u *ui) migrateStart(key string) {
	u.closeMigDst() // прежняя цель, если окно закрыли без переноса
	ctx, cancel := context.WithCancel(context.Background())
	u.setBusy(true)
	pv := u.progressWindow("Подготовка переноса", cancel)
	u.lastProgress = pv
	knownHosts := filepath.Join(core.DefaultVaultDir(), "known_hosts")
	src := u.sess
	goSafe(func() {
		defer cancel()
		dst, m, text, err := u.migratePrepare(ctx, src, key, knownHosts, pv)
		uiDo(func() {
			u.setBusy(false)
			closeDst := func() {
				if dst != nil {
					migClose(dst)
				}
			}
			if u.opFinished(err) {
				closeDst()
				return
			}
			switch {
			case errors.Is(err, core.ErrCanceled):
				closeDst()
				u.migrateInfo("Перенос отменён", "Отменено — на серверах ничего не изменено.")
			case text != "":
				closeDst()
				u.migrateInfo("Перенос остановлен", text)
			case err != nil:
				closeDst()
				u.migrateInfo("Перенос невозможен", migrateErrText(err))
			default:
				u.migDst = dst
				u.migrateWindow(m, dst)
			}
		})
	})
}

func migrateErrText(err error) string {
	t := core.MaskText(err.Error())
	if errors.Is(err, core.ErrSameServer) {
		return "ПЕРЕЕЗД ОСТАНОВЛЕН: " + t
	}
	return "Перенос невозможен, на серверах ничего не изменено: " + t
}

// migratePrepare — фоновая часть. text != "" — остановка с готовым текстом.
func (u *ui) migratePrepare(ctx context.Context, src *core.Session, key, knownHosts string, pv *progressView) (*core.Session, *core.Migration, string, error) {
	cfg, err := core.DecodeVpnKey(key)
	if err != nil {
		return nil, nil, "", errors.New("ключ нового сервера не разобран: " + core.MaskText(err.Error()))
	}
	creds, err := core.CredsFromConfig(cfg)
	if err != nil {
		return nil, nil, "", errors.New("ключ нового сервера: " + core.MaskText(err.Error()))
	}
	pv.report(core.Progress{Text: "подключение к новому серверу…"})
	dst, err := migrateConnect(creds, core.HostKeyPolicy{
		KnownHostsPath: knownHosts,
		Prompt:         u.hostKeyPrompt,
		OnChanged: func(host, knownFp, presentedFp string) {
			uiDo(func() {
				u.migrateInfo("Ключ нового сервера изменился", fmt.Sprintf("Сервер %s.\nСохранённый отпечаток: %s\nПолученный: %s\n"+
					"Так бывает после переустановки сервера. Если вы его не переустанавливали — возможна подмена: не подключайтесь.", host, knownFp, presentedFp))
			})
		},
	})
	if err != nil {
		return nil, nil, "", errors.New("подключение к новому серверу не удалось: " + core.MaskText(err.Error()))
	}
	if ctx.Err() != nil {
		return dst, nil, "", core.ErrCanceled
	}
	if v, why := core.SameServer(src, dst, backupResolve); v != core.SameNo {
		return dst, nil, migrateSameText(v, why), nil
	}
	m, err := core.PrepareMigration(ctx, src, dst, core.MigrationOptions{ToolVersion: version.String(), Now: time.Now(), Resolve: backupResolve, Progress: pv.report})
	if err != nil {
		return dst, nil, "", err
	}
	return dst, m, "", nil
}

// migrateInfo — информационное окно с текстом (прокрутка, перенос строк).
func (u *ui) migrateInfo(title, text string) dialog.Dialog {
	d := dialog.NewCustom(title, "Закрыть", container.NewVScroll(wrapLabel(text, false)), u.win)
	sizeDialog(d, fyne.NewSize(640, 300))
	d.Show()
	return d
}

// migrateView — окно подтверждения переноса (поля — для тестов).
type migrateView struct {
	d         dialog.Dialog
	apply     *escButton
	addrCheck *widget.Check
	xrayRadio *widget.RadioGroup
	mode      *widget.RadioGroup // автокопия цели: с паролем / без
	pw, pw2   *widget.Entry
	text      string
	users     *targetView
	// pinned — обязательные элементы в закреплённой панели (вне прокрутки);
	// reason — почему «Перенести» погашена (или что всё подтверждено).
	pinned []fyne.CanvasObject
	reason *widget.Label
}

func (v *migrateView) layer() core.BackupLayer {
	switch v.mode.Selected {
	case backupWithPassword:
		return core.PasswordLayer{Password: core.NewSecret([]byte(v.pw.Text))}
	case backupNoPassword:
		return core.PlainLayer{}
	}
	return nil
}

// migrateWindow — до записи: адрес и отпечаток ключа хоста обеих сторон,
// результат сверки цели (СТОП списком), что будет записано; подтверждение —
// явной кнопкой, включённой только при полном наборе условий.
func (u *ui) migrateWindow(m *core.Migration, dst *core.Session) *migrateView {
	v := &migrateView{}
	u.migShown = v
	compat, rp, b := m.Compat, m.Plan, m.Source()
	var sections []fyne.CanvasObject
	var all []string
	add := func(lines []string, bold bool) {
		if len(lines) == 0 {
			return
		}
		sections = append(sections, wrapLabel(strings.Join(lines, "\n"), bold))
		all = append(all, lines...)
	}
	add([]string{migrateSide("Источник (только чтение)", u.sess), migrateSide("Цель (сюда будет записано)", dst), migrateNoDiskText}, false)
	if rp != nil {
		var head []string
		if rp.NeedsTargetConfirm() {
			head = []string{core.TargetWarnHead(rp) + " Список и конфликты — в следующем окне, перед записью."}
		}
		add(append(head, core.RemovedLines(rp)...), true)
	}
	add(core.CompatStopLines(compat), true)
	sum := core.BackupSummaryLines(b)
	if len(sum) > 1 {
		sum = sum[1:] // первая строка — про файл копии, здесь файла нет
	}
	all = append(all, sum...)
	sections = append(sections, widget.NewAccordion(widget.NewAccordionItem("Что прочитано с источника (по протоколам)", wrapLabel(strings.Join(sum, "\n"), false))))
	add(core.CompatLines(compat), false)
	if rp != nil {
		add(core.RestorePlanLines(rp), false)
	}
	v.text = strings.Join(all, "\n")
	xray := false
	if rp != nil {
		for _, it := range rp.Items {
			xray = xray || it.RestartsXRay
		}
	}
	var update func()
	// Обязательный выбор — в ЗАКРЕПЛЁННОЙ панели над кнопками (вне прокрутки):
	// решение принимается по тому, что человек видит без прокрутки. В
	// прокрутке остаётся только информационная часть.
	var pinned []fyne.CanvasObject
	if compat.NeedAddressConfirm {
		pinned = append(pinned, wrapLabel(migrateAddrConsequence, true))
		v.addrCheck = widget.NewCheck(restoreAddrCheck, func(bool) { update() })
		pinned = append(pinned, v.addrCheck)
		if b.IssuedAddress.Kind == core.AddressKindUnknown {
			sections = append(sections, wrapLabel(migrateAddrHint, false))
		}
	}
	if xray {
		sections = append(sections, restartSections()...)
		v.xrayRadio = widget.NewRadioGroup([]string{migrateXRayRestart, migrateXRaySkip}, func(string) { update() })
		v.xrayRadio.Horizontal = true // одна строка в закреплённой панели
		pinned = append(pinned, wrapLabel(restoreXRayHint, true), v.xrayRadio)
	}
	// единственное, что пишется на диск, — автокопия ЦЕЛИ
	warn := wrapLabel("", false)
	v.reason = wrapLabel("", true)
	v.pw, v.pw2 = widget.NewPasswordEntry(), widget.NewPasswordEntry()
	v.pw.SetPlaceHolder(fmt.Sprintf("Пароль автокопии (не короче %d символов)", core.BackupPasswordMin))
	v.pw2.SetPlaceHolder("Повторите пароль")
	v.pw.OnChanged = func(string) { update() }
	v.pw2.OnChanged = func(string) { update() }
	v.mode = widget.NewRadioGroup([]string{backupWithPassword, backupNoPassword}, func(string) { update() })
	v.mode.Horizontal = true
	pwRow := container.NewGridWithColumns(2, v.pw, v.pw2)
	pwRow.Hide()
	// пояснение про автокопию и предупреждение выбранного режима — в
	// прокручиваемой части: в закреплённой панели только сам выбор
	sections = append(sections, wrapLabel(migrateAutoCopyNote, false), warn)
	pinned = append(pinned, wrapLabel(migrateAutoCopyAsk, true), v.mode, pwRow, v.reason)
	v.pinned = pinned
	var cw confirmWin
	cw = u.confirmWindowPinned(migrateWinTitle, sections, pinned, migrateApplyText, true, func() {
		if rp.NeedsTargetConfirm() {
			v.users = u.targetConfirm(rp, func() { u.doMigrate(m, v, true) })
			v.users.onCancel(u.closeMigDst)
			return
		}
		u.doMigrate(m, v, false)
	}, 900)
	v.d, v.apply = cw.d, cw.ok
	cw.onCancel(u.closeMigDst) // отмена окна подтверждения — сессия цели закрыта
	update = func() {
		// reason — первая непройденная причина, по порядку важности
		reason := ""
		pwOK := true
		warn.SetText("")
		pwRow.Hide()
		switch v.mode.Selected {
		case backupNoPassword:
			warn.SetText(core.AutoCopyUnencryptedNote)
		case backupWithPassword:
			pwRow.Show()
			warn.SetText(core.BackupPasswordWarning)
			switch {
			case core.ValidateBackupPassword(core.NewSecret([]byte(v.pw.Text))) != nil:
				pwOK = false
			case v.pw.Text != v.pw2.Text:
				pwOK = false
			}
		}
		switch {
		case compat.Stop || rp == nil:
			reason = migrateReasonStop
		case v.addrCheck != nil && !v.addrCheck.Checked:
			reason = migrateReasonAddr
		case xray && v.xrayRadio.Selected == "":
			reason = migrateReasonXRay
		case v.mode.Selected == "":
			reason = migrateReasonMode
		case !pwOK && core.ValidateBackupPassword(core.NewSecret([]byte(v.pw.Text))) != nil:
			reason = fmt.Sprintf(migrateReasonPwShort, core.BackupPasswordMin)
		case !pwOK:
			reason = migrateReasonPwDiff
		}
		if reason == "" {
			v.reason.SetText(migrateReasonReady)
			v.apply.Enable()
		} else {
			v.reason.SetText(reason)
			v.apply.Disable()
		}
		cw.refit()
	}
	update()
	return v
}

// runMigrateCtx — запись на цель (синхронно; для теста и фоновой задачи).
func (u *ui) runMigrateCtx(ctx context.Context, m *core.Migration, layer core.BackupLayer, xrayOK, targetOK, addrOK bool, now time.Time, progress core.ProgressFunc) (string, []core.RestoreOutcome, error) {
	if layer == nil {
		return "", nil, errors.New("не выбрано, защищать ли автокопию нового сервера паролем — замена запрещена")
	}
	dir, err := core.UserBackupsDir()
	if err == nil {
		err = os.MkdirAll(dir, 0o700)
	}
	if err != nil {
		return "", nil, errors.New("каталог автокопии не определён — замена запрещена: " + err.Error())
	}
	return m.Apply(core.MigrateOptions{AddressConfirmed: addrOK, RestoreOptions: core.RestoreOptions{
		AutoCopyDir: dir, ToolVersion: version.String(), Now: now, Resolve: backupResolve, Layer: layer,
		ConfirmXRay: func() bool { return xrayOK }, TargetConfirmed: targetOK, Ctx: ctx, Progress: progress}})
}

func (u *ui) doMigrate(m *core.Migration, v *migrateView, targetOK bool) {
	xrayOK := v.xrayRadio != nil && v.xrayRadio.Selected == migrateXRayRestart
	addrOK := v.addrCheck == nil || v.addrCheck.Checked
	layer := v.layer()
	enc := layer != nil && layer.Name() == core.PasswordLayerName
	v.d.Hide()
	ctx, cancel := context.WithCancel(context.Background())
	u.setBusy(true)
	pv := u.progressWindow("Перенос на новый сервер", cancel)
	u.lastProgress = pv
	goSafe(func() {
		defer cancel()
		auto, outs, err := u.runMigrateCtx(ctx, m, layer, xrayOK, targetOK, addrOK, time.Now(), pv.report)
		uiDo(func() {
			u.setBusy(false)
			u.closeMigDst()
			if u.opFinished(err) {
				return
			}
			u.migrateResult(auto, enc, outs, err)
			u.closeNotDoneNote()
			u.refresh()
		})
	})
}

// migrateResult — итог: заметный заголовок одного из трёх исходов, затем
// подробности из core (путь автокопии нового сервера, по контейнерам).
func (u *ui) migrateResult(auto string, enc bool, outs []core.RestoreOutcome, err error) dialog.Dialog {
	st, head := migrateVerdict(err, outs)
	hl := wrapLabel(head, true)
	switch st {
	case migDone:
		hl.Importance = widget.SuccessImportance
	case migNotDone:
		hl.Importance = widget.WarningImportance
	default:
		hl.Importance = widget.DangerImportance
	}
	var body string
	switch {
	case err != nil:
		body = core.MaskText(err.Error())
		if auto != "" && !strings.Contains(body, auto) {
			body += "\nАвтокопия нового сервера уже сохранена: " + auto
		}
		body += "\n" + migrateNoDiskText + "\n" + migrateSrcSafeText
	default:
		body = migrateSrcSafeText + "\n" + strings.Join(core.MigrationOutcomeLines(auto, enc, outs), "\n")
	}
	d := dialog.NewCustom("Итог переноса", "Закрыть", container.NewVScroll(container.NewVBox(hl, wrapLabel(body, false))), u.win)
	sizeDialog(d, fyne.NewSize(700, 580))
	d.Show()
	return d
}
