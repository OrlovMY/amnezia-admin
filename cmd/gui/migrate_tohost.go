package main

// «Перенести на сервер…» → режим «Новый чистый сервер (по IP/имени)» (PR 7б
// плана «перенос на чистый сервер»). Образец — CLI `migrate -to-host`
// (cmd/cli/migrate_tohost.go, отчёт ОТЧЁТ-MIGRATE-TO-HOST.md): тот же
// порядок, те же тексты ядра, тот же смысл трёх исходов.
//
// Поток: адрес/порт/пользователь → «Подключиться» (ConnectNew: ключи ПК; не
// вышло — окно снова, с полем пароля и причиной по исходу ключей; ключ хоста
// — тот же TOFU/known_hosts с подтверждением отпечатка) → сверка «один ли
// сервер» → копия источника в память → предпроверка (ProvisionCheckFor,
// порты копии) → PlanInstall → InstallPreview → адрес выдачи
// (TargetAddressCheck) → ОДНО окно со всем этим и обязательными выборами в
// закреплённой панели → «Установить и перенести» → Install → перенос
// клиентов (PrepareMigration с той же копией + Apply) → ключ vpn:// (только
// с согласия; BuildAdminKey → VerifyAdminKey → файл) → итог: перенесено /
// не перенесено / НЕИЗВЕСТНО.
//
// Секреты: пароль входа и пароль для ключа держатся в core.Secret и
// затираются (Wipe) после использования и при любом закрытии; поля паролей
// очищаются сразу после чтения. Честно: строки Entry.Text (и копия, которую
// делает SSH-библиотека) — строки Go, их затереть нельзя — как в CLI.
// Ключ vpn:// пишется только в файл (Reveal), на экран — путь. Все тексты
// ошибок — через core.MaskText.

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/storage"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"amnezia-admin/core"
	"amnezia-admin/internal/version"
)

// Тексты режима «новый чистый сервер» (сторожа тестов берут их отсюда).
const (
	migrateModeKey       = "Сервер с Amnezia (ключ vpn://)"
	migrateModeHost      = "Новый чистый сервер (по IP/имени)"
	toHostConnTitle      = "Новый чистый сервер"
	toHostConnectText    = "Подключиться"
	toHostWinTitle       = "Шаг 2 из 2: выборы — установка Amnezia и перенос"
	toHostApplyText      = "Установить и перенести"
	toHostReplaceCheck   = "Понимаю: на новый сервер будет поставлена Amnezia (см. «Установка изменит»), и в неё будут записаны клиенты старого сервера"
	toHostConsentText    = "Выдать ключ vpn:// с паролем внутри"
	toHostConsentNote    = "Ключ vpn:// нового сервера (как «полный доступ» в приложении Amnezia) выдаётся только с вашего согласия (галка внизу, по умолчанию выключена): в ключ кладётся пароль, и кто получит ключ — получит root-доступ к серверу. Если вход был по ключу ПК, пароля у программы нет — его нужно ввести рядом с галкой. Ключ пишется только в файл; на экране — путь к нему."
	toHostModeLabel      = "Автокопия нового сервера:"
	toHostOpenDirText    = "Открыть папку"
	toHostCancelTitle    = "Прервать установку?"
	toHostNoSleepWin     = "До итога не закрывайте крышку ноутбука и не рвите сеть (сон ПК программа на это время запретит)."
	toHostNoSleepOther   = "До итога не закрывайте крышку ноутбука, не усыпляйте ПК и не рвите сеть (на этой ОС программа сон не запрещает)."
	toHostCancelYes      = "Прервать после установки (клиентов не переносить)"
	toHostNoCancelApply  = "Идёт запись клиентов на новый сервер — запись клиентов прервать нельзя, дождитесь итога."
	toHostCancelNo       = "Продолжить установку"
	toHostCancelWarn     = "Установку прервать нельзя: она дойдёт до конца — до последнего контейнера плана (ядро не останавливает установку посреди работы). После этого программа покажет НАСТОЯЩИЙ итог установки по контейнерам (что встало, что откатилось), клиентов переносить НЕ будет и ключ vpn:// НЕ выдаст. Новый сервер останется с Amnezia, но без клиентов и без ключа: чтобы продолжить, понадобится вручную удалить контейнеры (docker rm -f …) и повторить перенос, или взять ключ в приложении Amnezia. Старый сервер не изменён."
	toHostPwHint         = "Пароль (не отображается и не сохраняется)"
	toHostKeyPwHint      = "Пароль root для ключа vpn://"
	toHostReasonConnHost = "«Подключиться» недоступна: укажите IP или DNS-имя (без пользователя и порта)."
	toHostReasonConnVpn  = "«Подключиться» недоступна: здесь нужен адрес сервера, а не ключ vpn:// (для ключа — режим «" + migrateModeKey + "»)."
	toHostReasonConnPort = "«Подключиться» недоступна: порт SSH — число 1…65535."
	toHostReasonConnUser = "«Подключиться» недоступна: укажите пользователя SSH."
	toHostReasonConnPw   = "«Подключиться» недоступна: введите пароль (вход ключами ПК не удался — причина выше)."
	toHostReasonConnOK   = "Сначала вход ключами ПК; если не выйдет — программа попросит пароль."
	toHostReasonConnPwOK = "Будут предъявлены ключи ПК, затем пароль."
	toHostReasonProv     = "«Установить и перенести» недоступна: предпроверка нового сервера не дала «можно ставить» (см. выше)."
	toHostReasonPlan     = "«Установить и перенести» недоступна: план установки не готов или перечень изменений не составлен (см. выше)."
	toHostReasonReplace  = "«Установить и перенести» недоступна: подтвердите установку и запись клиентов (галка выше)."
	toHostReasonKeyPw    = "«Установить и перенести» недоступна: введите пароль для ключа или снимите галку выдачи ключа."
	toHostReasonReady    = "Всё подтверждено — можно ставить и переносить."
	toHostReviewTitle    = "Шаг 1 из 2: просмотр — что будет на новом сервере"
	toHostNextText       = "Далее: выборы"
	toHostBackText       = "Назад"
	toHostReasonNext     = "Прочитайте план и перечень изменений; выборы и запуск — на следующем шаге."
)

// Швы теста: каждое обращение к серверу и к диску.
var (
	toHostConnectNew = core.ConnectNew
	toHostCollect    = func(ctx context.Context, s *core.Session, now time.Time, p core.ProgressFunc) (*core.Backup, error) {
		return s.CollectBackupCtx(ctx, version.String(), now, backupResolve, p)
	}
	toHostProvCheck = func(s *core.Session, b *core.Backup) core.ProvisionReport { return s.ProvisionCheckFor(b) }
	toHostInstall   = core.Install
	// toHostApply — перенос клиентов на поставленный сервер: тот же путь,
	// что режим «ключ vpn://» (PrepareMigration + Apply), с уже прочитанной
	// копией источника.
	toHostApply = func(ctx context.Context, src, dst *core.Session, b *core.Backup, layer core.BackupLayer, xrayOK, addrOK bool, now time.Time, p core.ProgressFunc) (string, []core.RestoreOutcome, error) {
		m, err := core.PrepareMigration(ctx, src, dst, core.MigrationOptions{ToolVersion: version.String(), Now: now, Resolve: backupResolve, Progress: p, Source: b})
		if err != nil {
			return "", nil, err
		}
		if m.Plan != nil && m.Plan.NeedsTargetConfirm() {
			// на только что поставленном сервере пользователей быть не должно;
			// спрашивать «всё равно записать» после установки — нельзя
			return "", nil, errors.New("на новом сервере после установки уже есть пользователи — запись не выполнена (повторный перенос — режимом «" + migrateModeKey + "»)")
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
			ConfirmXRay: func() bool { return xrayOK }, TargetConfirmed: false, Ctx: ctx, Progress: p}})
	}
	toHostKeyContainers = func(s *core.Session, names []string) ([]core.AdminKeyContainer, []string, error) {
		return s.AdminKeyContainersFromServer(names)
	}
	toHostVerify = core.VerifyAdminKey
	// toHostKeepAwake — запрет сна на время установки и переноса.
	toHostKeepAwake = core.KeepAwake
	toHostKeyDir    = func() (string, error) {
		d, err := core.UserConfigsDir()
		if err != nil {
			return "", err
		}
		return filepath.Join(filepath.Dir(d), "Ключи доступа"), nil
	}
	toHostOpenDir = func(dir string) error {
		u, err := url.Parse(storage.NewFileURI(dir).String())
		if err != nil {
			return err
		}
		return fyne.CurrentApp().OpenURL(u)
	}
	// toHostBeforeInstall — шов теста: фоновая работа ждёт, пока тест
	// нажмёт «Отмена» во время установки.
	toHostBeforeInstall func()
)

// toHostValidate — причина, по которой «Подключиться» недоступна ("" — можно).
func toHostValidate(host, port, user string) string {
	h := strings.TrimSpace(host)
	switch {
	case strings.HasPrefix(strings.ToLower(h), "vpn://"):
		return toHostReasonConnVpn
	case h == "" || strings.ContainsAny(h, " /@:") && net.ParseIP(h) == nil:
		return toHostReasonConnHost
	}
	if p, err := strconv.Atoi(strings.TrimSpace(port)); err != nil || p < 1 || p > 65535 {
		return toHostReasonConnPort
	}
	if strings.TrimSpace(user) == "" {
		return toHostReasonConnUser
	}
	return ""
}

// toHostConnView — окно адреса и входа (поля — для тестов).
type toHostConnView struct {
	d                    dialog.Dialog
	host, port, user, pw *widget.Entry
	why                  *msgText // почему спрашивается пароль ("" — не спрашивается)
	reason               *msgText
	ok                   *escButton
}

// toHostConnect — окно «Новый чистый сервер». keysWhy != "" — вход ключами
// ПК уже не удался: показано поле пароля и причина по исходу ключей.
func (u *ui) toHostConnect(host, port, user, keysWhy string) *toHostConnView {
	v := &toHostConnView{host: widget.NewEntry(), port: widget.NewEntry(), user: widget.NewEntry(), pw: widget.NewPasswordEntry()}
	u.toHostConnShown = v
	v.host.SetPlaceHolder("IP или DNS-имя нового сервера")
	v.host.SetText(host)
	v.port.SetText(port)
	v.user.SetText(user)
	v.pw.SetPlaceHolder(toHostPwHint)
	v.why = wrapLabel("", true)
	v.reason = wrapLabel("", true)
	form := container.New(layout.NewFormLayout(), msgLabel("Адрес:"), v.host, msgLabel("Порт SSH:"), v.port, msgLabel("Пользователь:"), v.user)
	sections := []fyne.CanvasObject{
		wrapLabel("Новый сервер — чистый: Amnezia на нём ещё нет, ключа vpn:// у него нет. Программа войдёт по SSH (ключами этого компьютера, а если не выйдет — по паролю; пароль используется один раз и не сохраняется — кроме случая, когда вы на следующем шаге разрешите положить его в ключ vpn://), "+
			"проверит сервер, покажет план установки и всё, что изменится, и только после вашего подтверждения поставит Amnezia и перенесёт клиентов. Старый сервер только читается.", false),
		form,
	}
	pinned := []fyne.CanvasObject{}
	if keysWhy != "" {
		v.why.SetText("Вход ключами ПК не удался: " + keysWhy + ". Введите пароль " + strings.TrimSpace(user) + ".")
		pinned = append(pinned, v.why, v.pw)
	}
	pinned = append(pinned, v.reason)
	var cw confirmWin
	cw = u.confirmWindowPinned(toHostConnTitle, sections, pinned, toHostConnectText, false, func() {
		var pw []byte
		if keysWhy != "" {
			pw = []byte(v.pw.Text)
		}
		v.pw.SetText("") // пароль в поле не остаётся
		u.toHostConnectRun(v.host.Text, v.port.Text, v.user.Text, pw)
	}, 640)
	v.d, v.ok = cw.d, cw.ok
	update := func(string) {
		r := toHostValidate(v.host.Text, v.port.Text, v.user.Text)
		if r == "" && keysWhy != "" && v.pw.Text == "" {
			r = toHostReasonConnPw
		}
		if r == "" {
			if keysWhy != "" {
				v.reason.SetText(toHostReasonConnPwOK)
			} else {
				v.reason.SetText(toHostReasonConnOK)
			}
			v.ok.Enable()
		} else {
			v.reason.SetText(r)
			v.ok.Disable()
		}
		cw.refit()
	}
	for _, e := range []*widget.Entry{v.host, v.port, v.user, v.pw} {
		e.OnChanged = update
	}
	update("")
	if keysWhy != "" {
		u.focusField(v.pw)
	} else {
		u.focusField(v.host)
	}
	return v
}

// toHostState — всё, что прочитано до установки (только чтение).
type toHostState struct {
	host, port, user string
	src, dst         *core.Session
	att              core.KeyAttempt
	loginPw          core.Secret // пустой — вход был по ключу ПК
	b                *core.Backup
	rep              core.ProvisionReport
	plan             core.InstallPlan
	preview          []string
	previewErr       error
	needAddr         bool
	addrText         string
}

// toHostConnectRun — вход и всё чтение до окна подтверждения — в фоне.
func (u *ui) toHostConnectRun(host, port, user string, pw []byte) {
	u.closeMigDst()
	host, port, user = strings.TrimSpace(host), strings.TrimSpace(port), strings.TrimSpace(user)
	ctx, cancel := context.WithCancel(context.Background())
	u.setBusy(true)
	pv := u.progressWindow("Подключение к новому серверу", cancel)
	u.lastProgress = pv
	knownHosts := filepath.Join(core.DefaultVaultDir(), "known_hosts")
	src := u.sess
	goSafe(func() {
		defer cancel()
		st, stop, keysWhy, err := u.toHostPrepare(ctx, src, host, port, user, pw, knownHosts, pv)
		clear(pw)
		uiDo(func() {
			u.setBusy(false)
			closeDst := func() {
				if st != nil && st.dst != nil {
					migClose(st.dst)
				}
				if st != nil {
					st.loginPw.Wipe()
				}
			}
			if u.opFinished(err) {
				closeDst()
				return
			}
			switch {
			case keysWhy != "":
				closeDst()
				u.toHostConnect(host, port, user, keysWhy)
				if err != nil { // пароль уже был и не подошёл — сказать поверх
					u.migrateInfo("Вход не выполнен", core.MaskText(err.Error()))
				}
			case errors.Is(err, core.ErrCanceled):
				closeDst()
				u.migrateInfo("Перенос отменён", "Отменено — на серверах ничего не изменено.")
			case stop != "":
				closeDst()
				u.migrateInfo("Перенос остановлен", stop)
			case err != nil:
				closeDst()
				u.migrateInfo("Перенос невозможен", "Перенос невозможен, на серверах ничего не изменено: "+core.MaskText(err.Error()))
			default:
				u.migDst = st.dst
				u.toHostLogin = &st.loginPw
				u.toHostWindow(st)
			}
		})
	})
}

// toHostPrepare — фон. keysWhy != "" — нужен (снова) пароль: исход ключей.
func (u *ui) toHostPrepare(ctx context.Context, src *core.Session, host, port, user string, pw []byte, knownHosts string, pv *progressView) (st *toHostState, stop, keysWhy string, err error) {
	st = &toHostState{host: host, port: port, user: user, src: src}
	auth := core.AuthSource{}
	if pw != nil {
		auth.Password = func(core.KeyAttempt) ([]byte, error) {
			st.loginPw = core.NewSecret(pw)
			return append([]byte(nil), pw...), nil
		}
	}
	pv.report(core.Progress{Text: "вход на новый сервер (ключи ПК" + map[bool]string{true: ", затем пароль", false: ""}[pw != nil] + ")…"})
	dst, att, err := toHostConnectNew(host, port, user, auth, core.HostKeyPolicy{
		KnownHostsPath: knownHosts,
		Prompt:         u.hostKeyPrompt, // отпечаток показывается и подтверждается
		OnChanged: func(h, knownFp, presentedFp string) {
			uiDo(func() {
				u.migrateInfo("Ключ нового сервера изменился", fmt.Sprintf("Сервер %s.\nСохранённый отпечаток: %s\nПолученный: %s\n"+
					"Так бывает после переустановки сервера. Если вы его не переустанавливали — возможна подмена: не подключайтесь.", h, knownFp, presentedFp))
			})
		},
	})
	if err != nil {
		var ae *core.AuthError
		if errors.As(err, &ae) {
			if !ae.PasswordTried {
				return st, "", ae.Keys.Reason(), nil
			}
			return st, "", ae.Keys.Reason(), errors.New(core.MaskText(ae.Error()))
		}
		return st, "", "", errors.New("подключение к новому серверу не удалось: " + core.MaskText(err.Error()))
	}
	st.dst, st.att = dst, att
	if ctx.Err() != nil {
		return st, "", "", core.ErrCanceled
	}
	if v, why := core.SameServer(src, dst, backupResolve); v != core.SameNo {
		return st, migrateSameText(v, why), "", nil
	}
	pv.report(core.Progress{Text: "чтение старого сервера в память…"})
	b, err := toHostCollect(ctx, src, time.Now(), pv.report)
	if err != nil {
		if errors.Is(err, core.ErrCanceled) {
			return st, "", "", core.ErrCanceled
		}
		return st, "", "", errors.New("старый сервер не прочитан: " + core.MaskText(err.Error()))
	}
	st.b = b
	pv.report(core.Progress{Text: "предпроверка нового сервера (только чтение)…"})
	st.rep = toHostProvCheck(dst, b)
	st.plan = core.PlanInstall(b, nil)
	st.preview, st.previewErr = core.InstallPreview(st.plan)
	st.needAddr, st.addrText = core.TargetAddressCheck(b, host, backupResolve)
	if ctx.Err() != nil {
		return st, "", "", core.ErrCanceled
	}
	return st, "", "", nil
}

// toHostLoginLine — как выполнен вход (исход ключей — всегда).
func toHostLoginLine(st *toHostState) string {
	if st.att.Outcome == core.KeysAccepted {
		return "Вход на новый сервер: по ключу ПК (" + st.att.Reason() + ")."
	}
	return "Вход на новый сервер: по паролю. Ключи ПК: " + st.att.Reason() + ". Пароль не сохраняется."
}

// toHostPlanLines — план: Verdict()+Reason по контейнеру (не String()
// состояния), не поставленные — целиком, готовность с оговоркой
// NeedsMeasurement, оговорка о версии программы.
func toHostPlanLines(plan core.InstallPlan) []string {
	out := []string{"План установки на новый сервер:"}
	for _, it := range plan.Items {
		l := "  " + it.Container + ": " + it.Verdict()
		if it.Reason != "" {
			l += " — " + it.Reason
		}
		if it.Revision != "" {
			l += " [скрипты " + it.Revision + "]"
		}
		out = append(out, l)
	}
	for _, s := range plan.Skipped {
		out = append(out, "  Не ставится: "+s.Container+" — "+s.Reason)
	}
	switch {
	case !plan.Ready():
		out = append(out, "Готовность: НЕ готов — установка не начнётся.")
	case plan.NeedsMeasurement():
		out = append(out, "Готовность: готов по скриптам; совпадение с копией подтвердится только измерением после установки.")
	default:
		out = append(out, "Готовность: готов.")
	}
	out = append(out, "Ревизии скриптов установки закреплены в этой сборке программы ("+version.String()+"); другая версия amnezia-admin может ставить другую ревизию.")
	return out
}

// toHostView — окно до установки (поля — для тестов).
type toHostView struct {
	d         dialog.Dialog
	apply     *escButton
	replace   *widget.Check
	addrCheck *widget.Check
	xrayRadio *widget.RadioGroup
	mode      *widget.RadioGroup
	pw, pw2   *widget.Entry
	consent   *widget.Check
	keyPw     *widget.Entry // nil — вход был по паролю, он и пойдёт в ключ
	reason    *msgText
	pinned    []fyne.CanvasObject
	text      string
}

func (v *toHostView) layer() core.BackupLayer {
	switch v.mode.Selected {
	case backupWithPassword:
		return core.PasswordLayer{Password: core.NewSecret([]byte(v.pw.Text))}
	case backupNoPassword:
		return core.PlainLayer{}
	}
	return nil
}

// toHostReview — шаг «Просмотр» (поля — для тестов).
type toHostReview struct {
	d      dialog.Dialog
	next   *escButton
	back   *escButton
	reason *msgText
	text   string
}

// toHostWindow — шаг 1 «Просмотр»: стороны, вход, предпроверка, план,
// изменения на хосте (полный текст) — на всё окно, с прокруткой; «Назад» —
// к окну адреса (сессия нового сервера закрывается), «Далее: выборы» — к
// шагу 2. Далее погашена, если ставить нельзя или неизвестно.
func (u *ui) toHostWindow(st *toHostState) *toHostReview {
	r := &toHostReview{}
	u.toHostReviewed = r
	var sections []fyne.CanvasObject
	var all []string
	add := func(lines []string, bold bool, imp widget.Importance) {
		if len(lines) == 0 {
			return
		}
		l := wrapLabel(strings.Join(lines, "\n"), bold)
		l.Importance = imp
		sections = append(sections, l)
		all = append(all, lines...)
	}
	add([]string{migrateSide("Источник (только чтение)", st.src), migrateSide("Новый сервер (сюда будет записано)", st.dst), toHostLoginLine(st), migrateNoDiskText}, false, widget.MediumImportance)
	// предпроверка — по пункту, три исхода видны и цветом
	add([]string{"Предпроверка нового сервера (только чтение):"}, true, widget.MediumImportance)
	for _, it := range st.rep.Items {
		imp := widget.SuccessImportance
		switch it.State {
		case core.ProvBad:
			imp = widget.DangerImportance
		case core.ProvUnknown:
			imp = widget.WarningImportance
		}
		add([]string{fmt.Sprintf("  %s: %s — %s", it.What, it.State, it.Reason)}, false, imp)
	}
	verdict := st.rep.Verdict()
	vl := []string{"Итог предпроверки: " + verdict.String() + "."}
	switch verdict {
	case core.ProvVerdictUnknown:
		vl = append(vl, "Часть пунктов узнать не удалось — это не «годится». Ничего не изменено.")
	case core.ProvVerdictNo:
		if toHostNotClean(st.rep) {
			vl = append(vl, "Новый сервер не чистый: на нём уже есть контейнеры Amnezia. Снос существующего — отдельный шаг, в этой версии его нет. Если у вас есть его ключ vpn:// — выберите режим «"+migrateModeKey+"».")
		}
		vl = append(vl, "Ничего не изменено.")
	}
	add(vl, true, widget.MediumImportance)
	add(toHostPlanLines(st.plan), false, widget.MediumImportance)
	if st.previewErr != nil {
		add([]string{"Перечень изменений на хосте не составлен — установка не начнётся: " + core.MaskText(st.previewErr.Error())}, true, widget.DangerImportance)
	} else {
		add(append([]string{"Установка изменит на новом сервере:"}, st.preview...), false, widget.MediumImportance)
	}
	add([]string{"Источник после переезда продолжит работать. Клиенты, подключённые по DNS-имени, перейдут на новый сервер после смены записи DNS."}, false, widget.MediumImportance)
	if st.needAddr {
		add([]string{"Адрес: " + st.addrText}, false, widget.MediumImportance)
	}
	r.text = strings.Join(all, "\n")
	reason := ""
	switch {
	case verdict != core.ProvVerdictYes:
		reason = toHostReasonProv
	case !st.plan.Ready() || st.previewErr != nil:
		reason = toHostReasonPlan
	}
	r.reason = wrapLabel(strings.Replace(reason, "«"+toHostApplyText+"»", "«"+toHostNextText+"»", 1), true)
	if reason == "" {
		r.reason.SetText(toHostReasonNext)
	}
	cw := u.confirmWindowPinned(toHostReviewTitle, sections, []fyne.CanvasObject{r.reason}, toHostNextText, false, func() { u.toHostChoices(st) }, 900)
	r.d, r.next, r.back = cw.d, cw.ok, cw.cancel
	r.back.SetText(toHostBackText)
	cw.onCancel(func() { // «Назад»/Esc — к окну адреса; цель закрыта
		st.loginPw.Wipe()
		u.closeMigDst()
		u.toHostConnect(st.host, st.port, st.user, "")
	})
	if reason != "" {
		r.next.Disable()
	}
	// просмотр — на всё окно: прокрутка не по содержимому, а по окну
	sizeDialog(r.d, u.win.Canvas().Size())
	return r
}

// toHostSummary — краткая сводка плана: одна строка на контейнер.
func toHostSummary(plan core.InstallPlan) []string {
	out := []string{"Будет поставлено (подробно — на шаге «Просмотр»):"}
	for _, it := range plan.Items {
		l := "  " + it.Container
		if it.Revision != "" {
			l += " [скрипты " + it.Revision + "]"
		}
		out = append(out, l+" — "+it.Verdict())
	}
	if n := len(plan.Skipped); n > 0 {
		out = append(out, fmt.Sprintf("  Не ставится из копии: %d (список — на шаге «Просмотр»)", n))
	}
	return out
}

// toHostChoices — шаг 2 «Выборы»: сводка плана и обязательные выборы в
// закреплённой панели; «Назад» — к просмотру (сессия остаётся).
func (u *ui) toHostChoices(st *toHostState) *toHostView {
	v := &toHostView{}
	u.toHostShown = v
	summary := toHostSummary(st.plan)
	v.text = strings.Join(summary, "\n")
	sections := []fyne.CanvasObject{wrapLabel(v.text, false), wrapLabel(migrateAutoCopyNote, false)}
	warn := wrapLabel("", false)
	sections = append(sections, warn)
	xray := false
	for _, it := range st.plan.Items {
		xray = xray || it.Container == "amnezia-xray"
	}
	var update func()
	var pinned []fyne.CanvasObject
	v.replace = widget.NewCheck(toHostReplaceCheck, func(bool) { update() })
	pinned = append(pinned, v.replace)
	if st.needAddr {
		v.addrCheck = widget.NewCheck(restoreAddrCheck, func(bool) { update() })
		pinned = append(pinned, wrapLabel(migrateAddrConsequence, true), v.addrCheck)
	}
	if xray {
		sections = append(sections, restartSections()...)
		v.xrayRadio = widget.NewRadioGroup([]string{migrateXRayRestart, migrateXRaySkip}, func(string) { update() })
		v.xrayRadio.Horizontal = true
		pinned = append(pinned, container.NewBorder(nil, nil, msgLabelStyle(restoreXRayHint, fyne.TextAlignLeading, fyne.TextStyle{Bold: true}), nil, v.xrayRadio))
	}
	v.pw, v.pw2 = widget.NewPasswordEntry(), widget.NewPasswordEntry()
	v.pw.SetPlaceHolder(fmt.Sprintf("Пароль автокопии (не короче %d символов)", core.BackupPasswordMin))
	v.pw2.SetPlaceHolder("Повторите пароль")
	v.pw.OnChanged = func(string) { update() }
	v.pw2.OnChanged = func(string) { update() }
	v.mode = widget.NewRadioGroup([]string{backupWithPassword, backupNoPassword}, func(string) { update() })
	v.mode.Horizontal = true
	pwRow := container.NewGridWithColumns(2, v.pw, v.pw2)
	pwRow.Hide()
	v.consent = widget.NewCheck(toHostConsentText, func(bool) { update() }) // по умолчанию выкл.
	var keyRow fyne.CanvasObject = v.consent
	if st.loginPw.Len() == 0 {
		v.keyPw = widget.NewPasswordEntry()
		v.keyPw.SetPlaceHolder(toHostKeyPwHint)
		v.keyPw.OnChanged = func(string) { update() }
		v.keyPw.Hide()
		keyRow = container.NewGridWithColumns(2, v.consent, v.keyPw)
	}
	v.reason = wrapLabel("", true)
	sections = append(sections, wrapLabel(migrateAutoCopyAsk, false), wrapLabel(toHostConsentNote, false))
	noSleep := toHostNoSleepOther
	if core.KeepAwakeSupported {
		noSleep = toHostNoSleepWin
	}
	pinned = append(pinned, container.NewBorder(nil, nil, msgLabelStyle(toHostModeLabel, fyne.TextAlignLeading, fyne.TextStyle{Bold: true}), nil, v.mode), pwRow, keyRow, wrapLabel(noSleep, true), v.reason)
	v.pinned = pinned
	var cw confirmWin
	cw = u.confirmWindowPinned(toHostWinTitle, sections, pinned, toHostApplyText, true, func() { u.toHostRun(st, v) }, 900)
	v.d, v.apply = cw.d, cw.ok
	cw.cancel.SetText(toHostBackText)
	cw.onCancel(func() { u.toHostWindow(st) }) // «Назад» — к просмотру
	update = func() {
		warn.SetText("")
		pwRow.Hide()
		pwShort, pwDiff := false, false
		switch v.mode.Selected {
		case backupNoPassword:
			warn.SetText(core.AutoCopyUnencryptedNote)
		case backupWithPassword:
			pwRow.Show()
			warn.SetText(core.BackupPasswordWarning)
			pwShort = core.ValidateBackupPassword(core.NewSecret([]byte(v.pw.Text))) != nil
			pwDiff = v.pw.Text != v.pw2.Text
		}
		if v.keyPw != nil {
			if v.consent.Checked {
				v.keyPw.Show()
			} else {
				v.keyPw.Hide()
			}
		}
		btn := func(s string) string {
			return strings.Replace(s, "«Перенести»", "«"+toHostApplyText+"»", 1)
		}
		reason := ""
		switch {
		case st.rep.Verdict() != core.ProvVerdictYes:
			reason = toHostReasonProv
		case !st.plan.Ready() || st.previewErr != nil:
			reason = toHostReasonPlan
		case !v.replace.Checked:
			reason = toHostReasonReplace
		case v.addrCheck != nil && !v.addrCheck.Checked:
			reason = btn(migrateReasonAddr)
		case xray && v.xrayRadio.Selected == "":
			reason = btn(migrateReasonXRay)
		case v.mode.Selected == "":
			reason = btn(migrateReasonMode)
		case pwShort:
			reason = btn(fmt.Sprintf(migrateReasonPwShort, core.BackupPasswordMin))
		case pwDiff:
			reason = btn(migrateReasonPwDiff)
		case v.consent.Checked && v.keyPw != nil && v.keyPw.Text == "":
			reason = toHostReasonKeyPw
		}
		if reason == "" {
			v.reason.SetText(toHostReasonReady)
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

// toHostNotClean — пункт о контейнерах Amnezia НЕ годится (как в CLI).
func toHostNotClean(r core.ProvisionReport) bool {
	for _, it := range r.Items {
		if it.State == core.ProvBad && strings.Contains(strings.ToLower(it.What), "контейнер") {
			return true
		}
	}
	return false
}

// toHostOutcome — всё, что известно после «Установить и перенести».
type toHostOutcome struct {
	canceled bool // «Отмена» нажата и подтверждена
	res      core.InstallResult
	applied  bool // перенос клиентов запускался
	auto     string
	outs     []core.RestoreOutcome
	err      error
	enc      bool
	consent  bool
	keyPath  string
	keyLines []string
	names    []string
	notes    []string // маркер, запрет сна — что сказать в итоге
	// markerErr — маркер новой установки не начат (ErrOpMarkerPending /
	// ErrOpMarkerNotWritten): установка не начиналась, маркер не снимается.
	markerErr error
	addr      bool // адрес выдачи подтверждался
	xraySkip  bool // XRay оставлен как есть
}

// toHostVerdict — один из трёх исходов. «Неизвестно» проверяется раньше
// остальных: неизмеренная установка — НЕИЗВЕСТНО. «Отмена» установку не
// прерывает (ядро её не принимает): итог установки — измеренный, как есть.
func toHostVerdict(o toHostOutcome) (migState, string) {
	r := o.res
	if !r.ReadyForRestore() {
		switch {
		case r.Refused != "":
			return migNotDone, "НЕ ПЕРЕНЕСЕНО — установка не начиналась, на новом сервере ничего не изменено."
		case r.Measure == nil:
			return migUnknown, "НЕИЗВЕСТНО — установка не измерена: программа не знает, что стоит на новом сервере. Клиенты не перенесены. Проверьте сервер вручную."
		}
		return migNotDone, "НЕ ПЕРЕНЕСЕНО — установка не удалась (подробности ниже); клиенты не перенесены."
	}
	if !o.applied {
		return migNotDone, "НЕ ПЕРЕНЕСЕНО — Amnezia на новом сервере поставлена, перенос клиентов не начинался (отменено)."
	}
	st, head := migrateVerdict(o.err, o.outs)
	if o.err != nil && st == migNotDone {
		head = "НЕ ПЕРЕНЕСЕНО — Amnezia на новом сервере поставлена, клиенты не перенесены: на неё ничего не записано (подробности ниже)."
	}
	return st, head
}

// toHostRun — установка, перенос и ключ в фоне; «Отмена» — только с
// предупреждением, что прерванная установка = «неизвестно».
func (u *ui) toHostRun(st *toHostState, v *toHostView) {
	o := toHostOutcome{consent: v.consent.Checked, addr: st.needAddr}
	xrayOK := v.xrayRadio != nil && v.xrayRadio.Selected == migrateXRayRestart
	o.xraySkip = v.xrayRadio != nil && !xrayOK
	addrOK := v.addrCheck == nil || v.addrCheck.Checked
	layer := v.layer()
	o.enc = layer != nil && layer.Name() == core.PasswordLayerName
	var keyPw core.Secret
	if o.consent {
		if v.keyPw != nil {
			keyPw = core.NewSecret([]byte(v.keyPw.Text))
		} else {
			keyPw = core.NewSecret(st.loginPw.Bytes())
		}
	}
	if v.keyPw != nil {
		v.keyPw.SetText("")
	}
	v.pw.SetText("")
	v.pw2.SetText("")
	st.loginPw.Wipe()
	for _, it := range st.plan.Items {
		o.names = append(o.names, it.Container)
	}
	ctx, cancel := context.WithCancel(context.Background())
	var canceled, applying atomic.Bool
	u.setBusy(true)
	var pv *progressView
	pv = u.progressWindow("Установка Amnezia и перенос", func() {})
	// Установка и перенос пишут на сервер: writing — закрыть программу
	// нельзя (крестик говорит почему). «Отмена» на установке — своя: через
	// окно с честным предупреждением; на переносе клиентов — погашена.
	pv.writing = true
	ask := func() {
		if pv.cancel.Disabled() || applying.Load() {
			return
		}
		pv.cancel.Disable()
		cd := u.newConfirm(toHostCancelTitle, toHostCancelWarn, func(yes bool) {
			if !yes || applying.Load() {
				u.closeAfterOp = false // закрытие (если просили) отменено человеком
				if applying.Load() {
					pv.note.SetText(toHostNoCancelApply)
					return
				}
				pv.note.SetText("")
				pv.cancel.Enable()
				return
			}
			canceled.Store(true)
			pv.note.SetText("Отмена принята: установка идёт до конца, затем — её итог; клиенты переноситься не будут.")
			cancel()
		})
		cd.SetConfirmText(toHostCancelYes)
		cd.SetDismissText(toHostCancelNo)
		cd.Show()
	}
	pv.cancel.OnTapped, pv.cancel.onEsc = ask, ask
	u.lastProgress = pv
	goSafe(func() {
		defer cancel()
		defer keyPw.Wipe()
		if toHostBeforeInstall != nil {
			toHostBeforeInstall()
		}
		// маркер незавершённой операции — ДО первой записи на цель; без него
		// обрыв посреди установки не оставил бы следа (аудит AU M1)
		mk := core.OpMarker{Target: st.host, Started: time.Now(), Step: "установка Amnezia", Installed: o.names, Tool: version.String()}
		if err := core.BeginOpMarker(mk); err != nil {
			o.markerErr = err
			why := " — без него обрыв посреди установки остался бы без следа"
			if errors.Is(err, core.ErrOpMarkerPending) {
				why = ""
			}
			o.res = core.InstallResult{Refused: core.MaskText(err.Error()) + why}
		} else {
			stopAwake, awake := toHostKeepAwake()
			defer stopAwake()
			if awake {
				o.notes = append(o.notes, "Сон ПК был запрещён на время установки и переноса.")
			} else if core.KeepAwakeSupported {
				o.notes = append(o.notes, "Запретить сон ПК не удалось — установка шла без этой защиты.")
			}
			pv.report(core.Progress{Text: "Шаг 1 из 3: установка Amnezia на новый сервер (это может занять несколько минут)…"})
			o.res = toHostInstall(st.dst, st.plan, core.InstallOptions{Backup: st.b, Resolve: backupResolve, PreviewAccepted: true})
			if o.res.ReadyForRestore() {
				mk.Step = "перенос клиентов"
				if err := core.WriteOpMarker(mk); err != nil {
					o.notes = append(o.notes, "Маркер незавершённой операции не обновлён (останется шаг «установка»): "+core.MaskText(err.Error()))
				}
			}
		}
		o.canceled = canceled.Load()
		if o.res.ReadyForRestore() {
			applying.Store(true) // с этого места «Прервать» не принимается
			uiDo(func() {
				pv.cancel.Disable()
				pv.note.SetText(toHostNoCancelApply)
			})
		}
		if o.res.ReadyForRestore() && ctx.Err() == nil {
			pv.report(core.Progress{Text: "Шаг 2 из 3: перенос клиентов на новый сервер…"})
			o.applied = true
			o.auto, o.outs, o.err = toHostApply(ctx, st.src, st.dst, st.b, layer, xrayOK, addrOK, time.Now(), pv.report)
		}
		// ключ — и при неудаче переноса: без него поставленный сервер не
		// продолжить ничем (как CLI, ревью PR #70, H1б)
		o.canceled = canceled.Load()
		if toHostKeyAllowed(o) {
			pv.report(core.Progress{Text: "Шаг 3 из 3: ключ vpn:// нового сервера…"})
			o.keyPath, o.keyLines = toHostIssueKey(st, o.names, keyPw, time.Now())
		}
		// маркер снимается только при ИЗМЕРЕННОМ итоге
		if vst, vhead := toHostVerdict(o); vst == migUnknown {
			o.notes = append(o.notes, "Маркер незавершённой операции оставлен ("+strings.SplitN(vhead, " —", 2)[0]+"): программа напомнит о нём при следующем запуске.")
		} else if o.markerErr == nil { // свой маркер не писался — чужой не трогать
			if err := core.ClearOpMarker(); err != nil {
				o.notes = append(o.notes, "Маркер незавершённой операции не удалён (при следующем запуске будет ложное напоминание): "+core.MaskText(err.Error()))
			}
		}
		uiDo(func() {
			u.setBusy(false)
			u.closeMigDst()
			if u.opFinished(nil) {
				return
			}
			u.toHostResult(st, o)
			u.closeNotDoneNote()
			u.refresh()
		})
	})
}

// toHostKeyAllowed — выдавать ли ключ: согласие, установка готова и либо
// отмены не было, либо перенос к ней уже полностью выполнен (решение ядра,
// ревью PR #71 L2: без ключа поставленный сервер не продолжить).
func toHostKeyAllowed(o toHostOutcome) bool {
	if !o.consent || !o.res.ReadyForRestore() {
		return false
	}
	if !o.canceled {
		return true
	}
	if !o.applied || o.err != nil || len(o.outs) == 0 {
		return false
	}
	for _, x := range o.outs {
		if x.State != core.RestoreDone {
			return false
		}
	}
	return true
}

// toHostIssueKey — сборка, проверка входом и запись ключа (фон). Путь ""
// — ключ не выдан, причина в строках. Ключ на экран не выводится.
func toHostIssueKey(st *toHostState, names []string, pw core.Secret, now time.Time) (string, []string) {
	var lines []string
	if pw.Len() == 0 {
		return "", []string{"Ключ vpn:// не выдан: пароля нет."}
	}
	cs, notes, err := toHostKeyContainers(st.dst, names)
	if err != nil {
		return "", []string{"Ключ vpn:// не выдан: " + core.MaskText(err.Error())}
	}
	lines = append(lines, notes...)
	port, err := strconv.Atoi(st.port)
	if err != nil { // проверено в окне адреса; ноль в ключ не идёт
		return "", append(lines, "Ключ vpn:// не выдан: порт SSH не разобран.")
	}
	in := core.AdminKeyInput{Host: st.host, Port: port, User: st.user, Password: pw, PasswordConsent: true,
		Containers: cs, DefaultContainer: names[0], Description: st.host}
	key, err := core.BuildAdminKey(in)
	if err != nil {
		return "", append(lines, "Ключ vpn:// не выдан: "+core.MaskText(err.Error()))
	}
	verr := toHostVerify(key, in, st.dst.HostKeyFingerprint, filepath.Join(core.DefaultVaultDir(), "known_hosts"))
	switch {
	case errors.Is(verr, core.ErrAdminKeyAuthRejected):
		return "", append(lines, "Ключ НЕ годится: новый сервер не принял пароль из ключа — пароль не подошёл или вход по паролю на сервере выключен (PasswordAuthentication no). Ключ vpn:// не выдан.")
	case errors.Is(verr, core.ErrAdminKeyMismatch):
		return "", append(lines, "Ключ vpn:// НЕ выдан — собранный ключ не совпал с ожидаемым: "+core.MaskText(verr.Error()))
	case verr != nil:
		lines = append(lines, "Ключ проверить не удалось (это не «ключ плохой» и не «ключ хороший»): "+core.MaskText(verr.Error()))
	}
	path, err := toHostWriteKey(st.host, key, now)
	if err != nil {
		return "", append(lines, "Ключ vpn:// не выдан: записать файл не удалось ("+core.MaskText(err.Error())+"). Перенос этим не затронут.")
	}
	perm := "права 0600 — только владелец"
	if runtime.GOOS == "windows" {
		perm = "доступ — по правам каталога " + filepath.Dir(path) + "; права 0600 на Windows не ставятся"
	}
	lines = append(lines, "Ключ vpn:// записан в файл ("+perm+"): "+path,
		"В файле — пароль "+st.user+" нового сервера: храните его как пароль, не пересылайте открыто; после импорта в приложение Amnezia удалите файл.")
	if verr == nil {
		lines = append(lines, "Ключ проверен: разобран и вход на новый сервер по нему выполнен.")
	}
	return path, lines
}

// toHostWriteKey — ключ в новый файл каталога ключей (core.WriteAdminKeyFile,
// общая с CLI). Возвращает абсолютный путь.
func toHostWriteKey(host string, key core.AdminKey, now time.Time) (string, error) {
	dir, err := toHostKeyDir()
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	return core.WriteAdminKeyFile(filepath.Join(dir, core.AdminKeyFileName(host, now)), key)
}

// toHostInstallFailedLines — после неудачной установки: что осталось.
func toHostInstallFailedLines(res core.InstallResult) []string {
	out := []string{"Клиенты НЕ перенесены. Старый сервер не изменён и продолжает работать."}
	if res.Refused != "" {
		return append(out, "Установка не начиналась — на новом сервере ничего не изменено.")
	}
	var left []string
	unknown := false
	for _, c := range res.Containers {
		switch {
		case c.Rollback == core.RollbackDone:
		case c.Rollback == core.RollbackFailed:
			left = append(left, c.RollbackLeft...)
		case c.Rollback == core.RollbackUnknown:
			unknown = true
			left = append(left, c.Container+" (не подтверждено)")
		case c.Outcome == core.InstallInstalled:
			left = append(left, c.Container)
		}
	}
	switch {
	case len(left) > 0:
		out = append(out, "На новом сервере осталось: "+strings.Join(left, ", ")+". Повторная установка откажет («сервер не чистый»); снос — в следующей версии, вручную: docker rm -f <контейнер> (и docker volume rm для тома XRay).")
	case unknown || res.Measure == nil:
		out = append(out, "Что осталось на новом сервере — неизвестно; проверьте docker ps -a перед повтором.")
	default:
		out = append(out, "По измерению отката контейнеров Amnezia на новом сервере не осталось (Docker, если ставился, остался). Устраните причину и повторите.")
	}
	return out
}

// toHostResult — итог: заголовок одного из трёх исходов, ход по шагам,
// путь к файлу ключа (сам ключ не показывается) с «Открыть папку»,
// подсказка продолжения, если клиенты не перенесены после установки.
func (u *ui) toHostResult(st *toHostState, o toHostOutcome) dialog.Dialog {
	s, head := toHostVerdict(o)
	hl := wrapLabel(head, true)
	switch s {
	case migDone:
		hl.Importance = widget.SuccessImportance
	case migNotDone:
		hl.Importance = widget.WarningImportance
	default:
		hl.Importance = widget.DangerImportance
	}
	var body []string
	body = append(body, migrateSrcSafeText, "", "Шаг 1. Установка Amnezia:")
	body = append(body, o.res.Lines()...)
	installed := o.res.ReadyForRestore()
	if !installed {
		body = append(body, toHostInstallFailedLines(o.res)...)
	}
	body = append(body, "", "Шаг 2. Перенос клиентов:")
	switch {
	case !installed:
		body = append(body, "не выполнялся (установка не готова).")
	case !o.applied:
		body = append(body, "перенос клиентов не выполнялся (отменено).")
	case o.err != nil:
		t := core.MaskText(o.err.Error())
		if o.auto != "" && !strings.Contains(t, o.auto) {
			t += "\nАвтокопия нового сервера уже сохранена: " + o.auto
		}
		body = append(body, t)
	default:
		body = append(body, core.MigrationOutcomeLines(o.auto, o.enc, o.outs)...)
	}
	body = append(body, "", "Шаг 3. Ключ vpn:// нового сервера:")
	switch {
	case !o.consent:
		body = append(body, "не выдавался: согласия положить пароль в ключ не было.")
	case !installed:
		body = append(body, "не выдавался: установка не готова.")
	case !toHostKeyAllowed(o):
		body = append(body, "не выдавался: отменено.")
	default:
		body = append(body, o.keyLines...)
	}
	transferred := s == migDone
	if installed && !transferred {
		body = append(body, "", "ПЕРЕНОС НЕ ЗАВЕРШЁН. На новом сервере поставлены контейнеры Amnezia ("+strings.Join(o.names, ", ")+"); старый сервер не изменён и продолжает работать.")
		switch {
		case o.canceled && o.keyPath == "":
			body = append(body, "Продолжить режимом «"+migrateModeKey+"» нельзя: ключа нового сервера нет. Варианты: удалить поставленные контейнеры (docker rm -f "+strings.Join(o.names, " ")+"; для XRay и docker volume rm его тома) и повторить перенос на чистый сервер с нуля; или добавить сервер в приложение Amnezia (логин и пароль), взять из него ключ «полный доступ» и продолжить режимом «"+migrateModeKey+"».")
		case o.keyPath != "":
			sh, ps := core.ContinueHint(core.ContinueHintOptions{KeyPath: o.keyPath, AddressChanges: o.addr,
				PasswordAsk: o.enc, NoPassword: !o.enc, SkipXRay: o.xraySkip})
			body = append(body, "Продолжить перенос на уже поставленный сервер: «Копия…» → «"+migrateMenuText+"» → режим «"+migrateModeKey+"» → кнопка «"+migrateFromFileText+"» и выберите файл "+o.keyPath+
				" (ключ читается из файла напрямую — не копируйте его через буфер обмена).",
				"Или командой: "+sh, "PowerShell: "+ps)
		default:
			body = append(body, "Ключ нового сервера не выдан — продолжить можно, только добавив сервер в приложение Amnezia (логин и пароль) и взяв из него ключ «полный доступ»; затем режим «"+migrateModeKey+"». Повторная установка откажет: сервер уже не чистый.")
		}
	} else if transferred && o.keyPath == "" {
		body = append(body, "", "Перенос выполнен, но ключ vpn:// нового сервера не выдан. Программа управляет сервером только по ключу: добавьте новый сервер в приложение Amnezia (адрес "+st.host+", пользователь "+st.user+", пароль) и выгрузите из него ключ «полный доступ».")
	}
	if len(o.notes) > 0 {
		body = append(append(body, ""), o.notes...)
	}
	objs := []fyne.CanvasObject{hl, withCopy(wrapLabel(strings.Join(body, "\n"), false))}
	if o.keyPath != "" {
		dir := filepath.Dir(o.keyPath)
		objs = append(objs, widget.NewButtonWithIcon(toHostOpenDirText, theme.FolderOpenIcon(), func() {
			if err := toHostOpenDir(dir); err != nil {
				u.migrateInfo("Папка не открыта", "Откройте вручную: "+dir+"\n"+core.MaskText(err.Error()))
			}
		}))
	}
	d := dialog.NewCustom("Итог установки и переноса", "Закрыть", container.NewVScroll(container.NewVBox(objs...)), u.win)
	sizeDialog(d, fyne.NewSize(760, 580))
	d.Show()
	return d
}

// showOpMarker — при запуске: прошлая установка не завершена (или маркер не
// прочитан) — сказать; «Понятно — убрать» снимает маркер, «Оставить» — нет.
func (u *ui) showOpMarker() dialog.Dialog {
	m, err := core.ReadOpMarker()
	var text string
	switch {
	case err != nil:
		text = core.MaskText(err.Error()) + " — итог прошлой установки на новый сервер может быть неизвестен. Проверьте сервер вручную."
	case m != nil:
		text = m.Text()
	default:
		return nil
	}
	cw := u.confirmWindowBtn(opMarkerTitle, []fyne.CanvasObject{wrapLabel(text, false)}, opMarkerClear, false, func() {
		if err := core.ClearOpMarker(); err != nil {
			u.migrateInfo("Маркер не убран", core.MaskText(err.Error()))
		}
	}, 640)
	cw.cancel.SetText(opMarkerKeep)
	return cw.d
}

const (
	opMarkerTitle = "Прошлая установка не завершена"
	opMarkerClear = "Понятно — убрать"
	opMarkerKeep  = "Оставить"
)
