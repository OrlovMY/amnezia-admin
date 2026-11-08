package main

// «Выдать ключ vpn://…» — повторная выдача админского ключа для открытого
// сервера (то же, что команда admin-key CLI). Ключ собирается из
// ФАКТИЧЕСКОГО состояния сервера (core.AdminKeyReissuePlan), проверяется
// VerifyAdminKey и пишется только в НОВЫЙ файл в каталоге, выбранном в
// системном окне (core.WriteAdminKeyFile: O_EXCL, права 0600 при создании;
// существующий файл не перезаписывается, место не в файловой системе —
// отказ). На экран ключ не выводится: в окнах — путь и перечень контейнеров.
// Описание, DNS и контейнер по умолчанию переносятся из ключа открытого
// сервера (как в CLI).
//
// Порядок: чтение сервера (фон) → окно согласия: что войдёт в ключ, чего
// НЕ будет (неполный ключ — отдельной надписью кнопки), предупреждение о
// пароле → сборка и проверка входом (фон) → выбор каталога → итог.

import (
	"errors"
	"fmt"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/dialog"

	"amnezia-admin/core"
)

// Подписи.
const (
	adminKeyMenuText    = "Выдать ключ vpn://…"
	adminKeyTitle       = "Ключ vpn:// сервера"
	adminKeyOKFull      = "Выдать ключ"
	adminKeyOKPartial   = "Выдать неполный ключ"
	adminKeyReadingText = "Читаю с сервера контейнеры и параметры протоколов…"
)

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
	// guiAdminKeySave — выбор каталога и запись; done получает путь или
	// ошибку (путь "" и ошибка nil — человек отменил выбор).
	guiAdminKeySave = func(u *ui, host string, key core.AdminKey, done func(string, error)) {
		fd := dialog.NewFolderOpen(func(dir fyne.ListableURI, err error) {
			if err != nil {
				done("", err)
				return
			}
			if dir == nil {
				done("", nil)
				return
			}
			done(adminKeySaveTo(dir, host, key, time.Now()))
		}, u.win)
		fd.Show()
	}
)

// errAdminKeyNotFS — выбранное место не каталог файловой системы: права
// 0600 там не установить, а «записан, права не известны» — не ответ.
var errAdminKeyNotFS = errors.New("выбранное место — не каталог файловой системы: права 0600 там не установить, ключ не записан; выберите обычный каталог")

// adminKeySaveTo — ключ в НОВЫЙ файл каталога dir (O_EXCL, 0600);
// существующий файл не перезаписывается.
func adminKeySaveTo(dir fyne.URI, host string, key core.AdminKey, now time.Time) (string, error) {
	if dir.Scheme() != "file" {
		return "", errAdminKeyNotFS
	}
	return core.WriteAdminKeyFile(filepath.Join(dir.Path(), core.AdminKeyFileName(host, now)), key)
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
		lines = append(lines, "", "Ключ будет НЕПОЛНЫМ: в нём не будет "+strings.Join(n, ", ")+". Выдать его можно только явно — кнопкой «"+adminKeyOKPartial+"».")
		okText = adminKeyOKPartial
	}
	lines = append(lines, "", "В ключе будет пароль "+user+"@"+host+" (или приватный SSH-ключ): кто получит ключ — получит root-доступ к серверу. Ключ запишется в файл, который вы выберете; на экран он не выводится.")
	return lines, okText, true
}

// adminKeyIssue — сборка и проверка входом (фон). key.Len()==0 — не выдан;
// lines — что сказать человеку.
func adminKeyIssue(sess *core.Session, r core.AdminKeyReissue, meta adminKeyMeta) (core.AdminKey, []string) {
	c := sess.Creds
	if c == nil || c.Password == "" {
		return core.AdminKey{}, []string{"Ключ vpn:// не выдан: в ключе открытого сервера нет пароля SSH, а выдаваемому ключу нужен способ входа. Окно программы пароль не спрашивает — выдайте ключ командой: amnezia-admin admin-key -host " + c.Host + " -user " + c.User + " -out <файл> (она спросит пароль в терминале)."}
	}
	port := 0
	if _, err := fmt.Sscanf(c.Port, "%d", &port); err != nil || port < 1 || port > 65535 {
		return core.AdminKey{}, []string{"Ключ vpn:// не выдан: порт SSH открытого сервера не 1…65535."}
	}
	in := core.AdminKeyInput{Host: c.Host, Port: port, User: c.User, Password: core.NewSecret([]byte(c.Password)), PasswordConsent: true,
		Containers: r.Containers, DefaultContainer: r.Default, Description: meta.Description, DNS1: meta.DNS1, DNS2: meta.DNS2}
	key, err := core.BuildAdminKey(in)
	if err != nil {
		return core.AdminKey{}, []string{"Ключ vpn:// не выдан: " + core.MaskText(err.Error())}
	}
	verr := guiAdminKeyVerify(key, in, sess.HostKeyFingerprint, filepath.Join(core.DefaultVaultDir(), "known_hosts"))
	switch {
	case errors.Is(verr, core.ErrAdminKeyAuthRejected):
		return core.AdminKey{}, []string{"Ключ НЕ годится: сервер не принял пароль из ключа — пароль не подошёл или вход по паролю на сервере выключен (PasswordAuthentication no). Ключ vpn:// не выдан. С другим паролем — командой amnezia-admin admin-key -host " + c.Host + " -out <файл> (спросит пароль в терминале)."}
	case errors.Is(verr, core.ErrAdminKeyMismatch):
		return core.AdminKey{}, []string{"Ключ vpn:// НЕ выдан — собранный ключ не совпал с ожидаемым: " + core.MaskText(verr.Error())}
	case verr != nil:
		return key, []string{"Ключ проверить не удалось (это не «ключ плохой» и не «ключ хороший»): " + core.MaskText(verr.Error()) + ". Проверьте его импортом в приложение Amnezia."}
	}
	return key, []string{"Ключ проверен: разобран и вход на сервер по нему выполнен."}
}

// adminKeyResultText — итог после окна сохранения.
func adminKeyResultText(path string, err error, user string, partial []string, lines []string) string {
	switch {
	case err != nil:
		return "Ключ vpn:// НЕ записан: " + core.MaskText(err.Error())
	case path == "":
		return "Ключ vpn:// не записан: каталог не выбран."
	}
	perm := "права 0600 — только владелец"
	if runtime.GOOS == "windows" {
		perm = "доступ — по правам каталога " + filepath.Dir(path) + "; права 0600 на Windows не ставятся"
	}
	out := append([]string{"Ключ vpn:// записан в файл (" + perm + "): " + path,
		"В файле — пароль " + user + " сервера: храните его как пароль, не пересылайте открыто; после импорта в приложение Amnezia удалите файл."}, lines...)
	if len(partial) > 0 {
		out = append(out, "Ключ НЕПОЛНЫЙ: в нём нет "+strings.Join(partial, ", ")+".")
	}
	return strings.Join(out, "\n")
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
				u.showInfo(adminKeyTitle, "Ключ vpn:// не выдан — состояние сервера неизвестно: "+core.MaskText(err.Error()))
				return
			}
			u.adminKeyConfirm(sess, r, meta)
		})
	})
}

// adminKeyConfirm — окно согласия по прочитанному плану.
func (u *ui) adminKeyConfirm(sess *core.Session, r core.AdminKeyReissue, meta adminKeyMeta) {
	user, host := "", ""
	if sess.Creds != nil {
		user, host = sess.Creds.User, sess.Creds.Host
	}
	lines, okText, can := adminKeyPlanLines(r, user, host)
	if !can {
		u.showInfo(adminKeyTitle, strings.Join(lines, "\n"))
		return
	}
	var partial []string
	for _, g := range r.Gaps {
		partial = append(partial, g.Container)
	}
	u.confirmWindowBtn(adminKeyTitle, []fyne.CanvasObject{wrapLabel(strings.Join(lines, "\n"), false)}, okText, true, func() {
		u.setBusy(true)
		goSafe(func() {
			key, res := adminKeyIssue(sess, r, meta)
			uiDo(func() {
				u.setBusy(false)
				if key.Len() == 0 {
					u.showInfo(adminKeyTitle, strings.Join(res, "\n"))
					return
				}
				guiAdminKeySave(u, host, key, func(path string, err error) {
					u.showInfo(adminKeyTitle, adminKeyResultText(path, err, user, partial, res))
				})
			})
		})
	}, 640)
}
