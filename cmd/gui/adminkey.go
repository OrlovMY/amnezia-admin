package main

// «Выдать ключ vpn://…» — повторная выдача админского ключа для открытого
// сервера (то же, что команда admin-key CLI). Ключ собирается из
// ФАКТИЧЕСКОГО состояния сервера (core.AdminKeyReissuePlan), проверяется
// VerifyAdminKey и пишется только в НОВЫЙ файл (имя — в окне согласия,
// каталог — в системном окне; core.WriteAdminKeyFile: O_EXCL, права 0600
// при создании; существующий файл не перезаписывается, место не в файловой
// системе — отказ). На экран ключ не выводится: в окнах — путь и перечень
// контейнеров. Описание, DNS и контейнер по умолчанию переносятся из ключа
// открытого сервера (как в CLI).
//
// Порядок: чтение сервера (фон) → окно согласия: что войдёт в ключ, чего
// НЕ будет; имя файла; ОТДЕЛЬНЫЕ флажки согласия на пароль в ключе и (если
// есть пробелы) на неполный ключ — без них кнопка погашена (как
// -include-password и -allow-partial CLI) → сборка и проверка входом (фон)
// → выбор каталога → итог.
//
// Итог — одно из четырёх состояний кодов CLI (0/1/2/4), первой строкой:
// «неизвестно» не сливается ни с «выдан», ни с «не выдан».

import (
	"errors"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/widget"

	"amnezia-admin/core"
)

// Подписи.
const (
	adminKeyMenuText    = "Выдать ключ vpn://…"
	adminKeyTitle       = "Ключ vpn:// сервера"
	adminKeyOKFull      = "Выдать ключ"
	adminKeyOKPartial   = "Выдать неполный ключ"
	adminKeyReadingText = "Читаю с сервера контейнеры и параметры протоколов…"
	// adminKeyPwCheck — согласие на пароль в ключе (CLI: -include-password).
	adminKeyPwCheck = "Согласен: в файле ключа будет пароль (или приватный SSH-ключ) — кто получит файл, получит root-доступ к серверу"
	// adminKeyPartialCheck — согласие на неполный ключ (CLI: -allow-partial).
	adminKeyPartialCheck = "Согласен выдать НЕПОЛНЫЙ ключ — без контейнеров, перечисленных выше"
	adminKeyNameLabel    = "Имя файла:"
	adminKeyNeedPw       = "Кнопка погашена: нет согласия на пароль в ключе."
	adminKeyNeedPartial  = "Кнопка погашена: нет согласия на неполный ключ."
)

// adminKeyOutcome — итог выдачи; значения — коды выхода admin-key CLI.
type adminKeyOutcome int

const (
	akIssued    adminKeyOutcome = 0 // выдан, записан, проверен входом
	akNotIssued adminKeyOutcome = 1 // измерено: ключ не выдан/не записан
	akNoConsent adminKeyOutcome = 2 // нет согласия или данных входа, выбор отменён
	akUnknown   adminKeyOutcome = 4 // неизвестно: не прочитано или не проверено
)

// adminKeyOutcomeHead — первая строка итога; у каждого состояния своя.
func adminKeyOutcomeHead(o adminKeyOutcome) string {
	switch o {
	case akIssued:
		return "Итог: ключ выдан и проверен."
	case akNotIssued:
		return "Итог: ключ НЕ выдан."
	case akNoConsent:
		return "Итог: ключ не выдан — нет согласия или нужных данных, либо выбор отменён."
	}
	return "Итог: НЕИЗВЕСТНО — это не «выдан и годен» и не «не выдан»; подробности ниже."
}

// adminKeyNameErr — имя файла ключа (после обрезки пробелов по краям):
// только имя, без каталога; не имя устройства Windows (NUL, CON, COM1,
// «nul.txt»… — на всех ОС); без хвостовых точек. Вторая защита — в
// core.WriteAdminKeyFile (путь обязан остаться обычным файлом в каталоге).
func adminKeyNameErr(name string) error {
	return core.AdminKeyFileNameErr(strings.TrimSpace(name))
}

// adminKeyMeta — поля ключа открытого сервера, которые переносятся в
// выдаваемый ключ (ревью PR #75, M1).
type adminKeyMeta struct {
	Description, DNS1, DNS2, Default string
}

func adminKeyMetaOf(cfg map[string]any) adminKeyMeta {
	return adminKeyMeta{Description: core.Str(cfg, "description"), DNS1: core.Str(cfg, "dns1"),
		DNS2: core.Str(cfg, "dns2"), Default: core.Str(cfg, "defaultContainer")}
}

// Швы теста.
var (
	guiAdminKeyPlan = func(s *core.Session, preferDefault string) (core.AdminKeyReissue, error) {
		return s.AdminKeyReissuePlan(preferDefault)
	}
	guiAdminKeyVerify = core.VerifyAdminKey
	// guiAdminKeySave — выбор каталога и запись в файл name; done получает
	// путь или ошибку (путь "" и ошибка nil — человек отменил выбор).
	guiAdminKeySave = func(u *ui, name string, key core.AdminKey, done func(string, error)) {
		fd := dialog.NewFolderOpen(func(dir fyne.ListableURI, err error) {
			if err != nil {
				done("", err)
				return
			}
			if dir == nil {
				done("", nil)
				return
			}
			done(adminKeySaveTo(dir, name, key))
		}, u.win)
		fd.Show()
	}
)

// errAdminKeyNotFS — выбранное место не каталог файловой системы: права
// 0600 там не установить, а «записан, права не известны» — не ответ.
var errAdminKeyNotFS = errors.New("выбранное место — не каталог файловой системы: права 0600 там не установить, ключ не записан; выберите обычный каталог")

// adminKeySaveTo — ключ в НОВЫЙ файл name каталога dir (O_EXCL, 0600);
// существующий файл не перезаписывается.
func adminKeySaveTo(dir fyne.URI, name string, key core.AdminKey) (string, error) {
	if dir.Scheme() != "file" {
		return "", errAdminKeyNotFS
	}
	if err := adminKeyNameErr(name); err != nil {
		return "", err
	}
	return core.WriteAdminKeyFile(filepath.Join(dir.Path(), strings.TrimSpace(name)), key)
}

// adminKeyPlanLines — что войдёт в ключ и чего НЕ будет; can — можно ли
// выдавать; okText — надпись кнопки (неполный — словами на кнопке).
func adminKeyPlanLines(r core.AdminKeyReissue, user, host string) (lines []string, okText string, can bool) {
	for _, c := range r.Containers {
		lines = append(lines, "В ключ: "+c.Name+" — параметры прочитаны с сервера.")
	}
	for _, g := range r.Gaps {
		lines = append(lines, "НЕ в ключ: "+g.Container+" — "+g.Reason)
	}
	lines = append(lines, r.Notes...)
	if len(r.Containers) == 0 {
		return append(lines, "", "Ключ не выдаётся: "+core.ErrAdminKeyNoContainers.Error()+"."), "", false
	}
	okText = adminKeyOKFull
	if len(r.Gaps) > 0 {
		var n []string
		for _, g := range r.Gaps {
			n = append(n, g.Container)
		}
		lines = append(lines, "", "Ключ будет НЕПОЛНЫМ: в нём не будет "+strings.Join(n, ", ")+". Выдать его можно только явно — флажком согласия и кнопкой «"+adminKeyOKPartial+"».")
		okText = adminKeyOKPartial
	}
	lines = append(lines, "", "В ключе будет пароль "+user+"@"+host+" (или приватный SSH-ключ): кто получит ключ — получит root-доступ к серверу; отозвать это можно только сменой пароля на самом сервере. Ключ запишется в НОВЫЙ файл в каталоге, который вы выберете (существующий не перезаписывается); на экран он не выводится.")
	return lines, okText, true
}

// adminKeyIssue — сборка и проверка входом (фон). key.Len()==0 — не выдан;
// o — итог (для выданного: akIssued — проверен, akUnknown — не проверен);
// lines — что сказать человеку. consent — согласие на пароль в ключе;
// partialConsent — на неполный ключ (нужно, только если есть пробелы).
// Проверяются здесь, а не только погашенной кнопкой (второй слой).
func adminKeyIssue(sess *core.Session, r core.AdminKeyReissue, meta adminKeyMeta, consent, partialConsent bool) (core.AdminKey, adminKeyOutcome, []string) {
	if !consent {
		return core.AdminKey{}, akNoConsent, []string{"Ключ vpn:// не выдан: нет согласия положить в него пароль."}
	}
	if len(r.Gaps) > 0 && !partialConsent {
		return core.AdminKey{}, akNoConsent, []string{"Ключ vpn:// не выдан: нет согласия на неполный ключ."}
	}
	c := sess.Creds
	if c == nil {
		return core.AdminKey{}, akNoConsent, []string{"Ключ vpn:// не выдан: у открытого сервера нет данных входа (адрес, пользователь, пароль) — переподключитесь к серверу."}
	}
	// Как CLI (cmd/cli/adminkey.go, «в текущем ключе нет пароля SSH» →
	// exitAdminKeyNo = 1): в ключе открытого сервера нет пароля — измерено
	// «не выдан», а не ошибка использования.
	if c.Password == "" {
		return core.AdminKey{}, akNotIssued, []string{"Ключ vpn:// не выдан: в ключе открытого сервера нет пароля SSH, а выдаваемому ключу нужен способ входа. Окно программы пароль не спрашивает — выдайте ключ командой: amnezia-admin admin-key -host " + c.Host + " -user " + c.User + " -out <файл> (она спросит пароль в терминале)."}
	}
	port, err := strconv.Atoi(c.Port)
	if err != nil || port < 1 || port > 65535 {
		return core.AdminKey{}, akNoConsent, []string{"Ключ vpn:// не выдан: порт SSH открытого сервера не 1…65535."}
	}
	in := core.AdminKeyInput{Host: c.Host, Port: port, User: c.User, Password: core.NewSecret([]byte(c.Password)), PasswordConsent: consent,
		Containers: r.Containers, DefaultContainer: r.Default, Description: meta.Description, DNS1: meta.DNS1, DNS2: meta.DNS2}
	key, err := core.BuildAdminKey(in)
	if err != nil {
		return core.AdminKey{}, akNotIssued, []string{"Ключ vpn:// не выдан: " + core.MaskText(err.Error())}
	}
	verr := guiAdminKeyVerify(key, in, sess.HostKeyFingerprint, filepath.Join(core.DefaultVaultDir(), "known_hosts"))
	switch {
	case errors.Is(verr, core.ErrAdminKeyAuthRejected):
		return core.AdminKey{}, akNotIssued, []string{"Ключ НЕ годится: сервер не принял пароль из ключа — пароль не подошёл или вход по паролю на сервере выключен (PasswordAuthentication no). Ключ vpn:// не выдан. С другим паролем — командой amnezia-admin admin-key -host " + c.Host + " -out <файл> (спросит пароль в терминале)."}
	case errors.Is(verr, core.ErrAdminKeyMismatch):
		return core.AdminKey{}, akNotIssued, []string{"Ключ vpn:// НЕ выдан — собранный ключ не совпал с ожидаемым: " + core.MaskText(verr.Error())}
	case verr != nil:
		return key, akUnknown, []string{"Ключ проверить не удалось (это не «ключ плохой» и не «ключ хороший»): " + core.MaskText(verr.Error()) + ". Ключ НЕ проверен входом — проверьте его импортом в приложение Amnezia."}
	}
	return key, akIssued, []string{"Ключ проверен: разобран и вход на сервер по нему выполнен."}
}

// adminKeyResultText — итог после окна сохранения; verified — итог
// adminKeyIssue (akIssued или akUnknown). Записан и проверен — akIssued;
// записан, не проверен — akUnknown; не записан — akNotIssued; каталог не
// выбран — akNoConsent.
func adminKeyResultText(path string, err error, user string, partial []string, verified adminKeyOutcome, lines []string) (adminKeyOutcome, string) {
	switch {
	case err != nil:
		return akNotIssued, adminKeyOutcomeHead(akNotIssued) + "\nКлюч vpn:// НЕ записан: " + core.MaskText(err.Error())
	case path == "":
		return akNoConsent, adminKeyOutcomeHead(akNoConsent) + "\nКлюч vpn:// не записан: каталог не выбран."
	}
	perm := "права 0600 — только владелец"
	if runtime.GOOS == "windows" {
		perm = "доступ — по правам каталога " + filepath.Dir(path) + "; права 0600 на Windows не ставятся"
	}
	o := akUnknown
	if verified == akIssued {
		o = akIssued
	}
	out := append([]string{adminKeyOutcomeHead(o), "Ключ vpn:// записан в файл (" + perm + "): " + path,
		"В файле — пароль " + user + " сервера: храните его как пароль, не пересылайте открыто; после импорта в приложение Amnezia удалите файл."}, lines...)
	if len(partial) > 0 {
		out = append(out, "Ключ НЕПОЛНЫЙ: в нём нет "+strings.Join(partial, ", ")+".")
	}
	return o, strings.Join(out, "\n")
}

// adminKeyAsk — пункт «Выдать ключ vpn://…».
func (u *ui) adminKeyAsk() {
	if u.busy || u.sess == nil {
		return
	}
	sess, meta := u.sess, u.keyMeta
	u.setBusy(true)
	if u.status != nil {
		u.status.SetText(adminKeyReadingText)
	}
	goSafe(func() {
		r, err := guiAdminKeyPlan(sess, meta.Default)
		uiDo(func() {
			u.setBusy(false)
			if u.sess != sess {
				return
			}
			if err != nil {
				u.showInfo(adminKeyTitle, adminKeyOutcomeHead(akUnknown)+"\nКлюч vpn:// не выдан — состояние сервера неизвестно: "+core.MaskText(err.Error()))
				return
			}
			u.adminKeyConfirm(sess, r, meta)
		})
	})
}

// adminKeyGate — почему кнопка выдачи погашена ("" — можно выдавать).
func adminKeyGate(pwConsent, partialConsent bool, name string) string {
	switch {
	case !pwConsent:
		return adminKeyNeedPw
	case !partialConsent:
		return adminKeyNeedPartial
	}
	if err := adminKeyNameErr(name); err != nil {
		return "Кнопка погашена: " + err.Error() + "."
	}
	return ""
}

// adminKeyConfirm — окно согласия по прочитанному плану.
func (u *ui) adminKeyConfirm(sess *core.Session, r core.AdminKeyReissue, meta adminKeyMeta) {
	user, host := "", ""
	if sess.Creds != nil {
		user, host = sess.Creds.User, sess.Creds.Host
	}
	lines, okText, can := adminKeyPlanLines(r, user, host)
	if !can {
		// как код 4 CLI: ни у одного контейнера параметры не прочитаны
		u.showInfo(adminKeyTitle, adminKeyOutcomeHead(akUnknown)+"\n"+strings.Join(lines, "\n"))
		return
	}
	var partial []string
	for _, g := range r.Gaps {
		partial = append(partial, g.Container)
	}
	name := widget.NewEntry()
	name.SetText(core.AdminKeyFileName(host, time.Now()))
	pwCheck := widget.NewCheck(adminKeyPwCheck, nil) // по умолчанию выкл.
	var partCheck *widget.Check
	reason := wrapLabel("", true)
	pinned := []fyne.CanvasObject{container.NewBorder(nil, nil, msgLabel(adminKeyNameLabel), nil, name), pwCheck}
	if len(partial) > 0 {
		partCheck = widget.NewCheck(adminKeyPartialCheck, nil) // по умолчанию выкл.
		pinned = append(pinned, partCheck)
	}
	pinned = append(pinned, reason)
	cw := u.confirmWindowPinned(adminKeyTitle, []fyne.CanvasObject{wrapLabel(strings.Join(lines, "\n"), false)}, pinned, okText, true, func() {
		consent, fileName := pwCheck.Checked, strings.TrimSpace(name.Text)
		partialConsent := partCheck != nil && partCheck.Checked
		u.setBusy(true)
		goSafe(func() {
			key, verified, res := adminKeyIssue(sess, r, meta, consent, partialConsent)
			uiDo(func() {
				u.setBusy(false)
				if key.Len() == 0 {
					u.showInfo(adminKeyTitle, adminKeyOutcomeHead(verified)+"\n"+strings.Join(res, "\n"))
					return
				}
				guiAdminKeySave(u, fileName, key, func(path string, err error) {
					_, text := adminKeyResultText(path, err, user, partial, verified, res)
					u.showInfo(adminKeyTitle, text)
				})
			})
		})
	}, 640)
	update := func() {
		why := adminKeyGate(pwCheck.Checked, partCheck == nil || partCheck.Checked, name.Text)
		reason.SetText(why)
		if why == "" {
			cw.ok.Enable()
		} else {
			cw.ok.Disable()
		}
	}
	pwCheck.OnChanged = func(bool) { update() }
	if partCheck != nil {
		partCheck.OnChanged = func(bool) { update() }
	}
	name.OnChanged = func(string) { update() }
	update()
}
