package main

// «Выдать ключ vpn://…» — повторная выдача админского ключа для открытого
// сервера (то же, что команда admin-key CLI). Ключ собирается из
// ФАКТИЧЕСКОГО состояния сервера (core.AdminKeyReissuePlan), проверяется
// VerifyAdminKey и пишется только в файл, выбранный в системном окне
// сохранения (права 0600). На экран ключ не выводится: в окнах — путь к
// файлу и перечень контейнеров.
//
// Порядок: чтение сервера (фон) → окно согласия: что войдёт в ключ, чего
// НЕ будет (неполный ключ — отдельной надписью кнопки), предупреждение о
// пароле → сборка и проверка входом (фон) → окно сохранения → итог.

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/storage"

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

// Швы теста.
var (
	guiAdminKeyPlan = func(s *core.Session) (core.AdminKeyReissue, error) {
		return s.AdminKeyReissuePlan("")
	}
	guiAdminKeyVerify = core.VerifyAdminKey
	// guiAdminKeySave — выбор файла и запись; done получает путь или ошибку
	// (путь "" и ошибка nil — человек отменил выбор).
	guiAdminKeySave = func(u *ui, host string, key core.AdminKey, done func(string, error)) {
		fd := dialog.NewFileSave(func(w fyne.URIWriteCloser, err error) {
			if err != nil {
				done("", err)
				return
			}
			if w == nil {
				done("", nil)
				return
			}
			done(writeChosenAdminKey(w, key))
		}, u.win)
		fd.SetFileName(core.AdminKeyFileName(host, time.Now()))
		fd.SetFilter(storage.NewExtensionFileFilter([]string{".txt"}))
		fd.Show()
	}
)

// writeChosenAdminKey — ключ (только Reveal) в выбранный файл, права 0600;
// не вышло — файл удаляется, текст ошибки без содержимого ключа.
func writeChosenAdminKey(w fyne.URIWriteCloser, key core.AdminKey) (string, error) {
	where := w.URI().Path()
	isFile := w.URI().Scheme() == "file"
	if isFile {
		// права — ДО записи секрета: файл, созданный окном выбора, мог
		// получить права по umask
		if err := chmodChosen(where, 0o600); err != nil {
			_ = w.Close()
			_ = os.Remove(where)
			return "", fmt.Errorf("ключ НЕ записан в %s: %w (%v) — файл с паролем сервера могли бы прочитать другие пользователи", where, errPermsNotLimited, err)
		}
	}
	_, werr := w.Write([]byte(key.Reveal() + "\n"))
	cerr := w.Close()
	if werr == nil {
		werr = cerr
	}
	if werr != nil {
		if isFile {
			_ = os.Remove(where)
		}
		return "", fmt.Errorf("ключ НЕ записан в %s", where)
	}
	return where, nil
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
func adminKeyIssue(sess *core.Session, r core.AdminKeyReissue) (core.AdminKey, []string) {
	c := sess.Creds
	if c == nil || c.Password == "" {
		return core.AdminKey{}, []string{"Ключ vpn:// не выдан: в ключе открытого сервера нет пароля SSH — ключ без способа входа бесполезен."}
	}
	port := 0
	if _, err := fmt.Sscanf(c.Port, "%d", &port); err != nil || port < 1 || port > 65535 {
		return core.AdminKey{}, []string{"Ключ vpn:// не выдан: порт SSH открытого сервера не 1…65535."}
	}
	in := core.AdminKeyInput{Host: c.Host, Port: port, User: c.User, Password: core.NewSecret([]byte(c.Password)), PasswordConsent: true,
		Containers: r.Containers, DefaultContainer: r.Default, Description: c.Host}
	key, err := core.BuildAdminKey(in)
	if err != nil {
		return core.AdminKey{}, []string{"Ключ vpn:// не выдан: " + core.MaskText(err.Error())}
	}
	verr := guiAdminKeyVerify(key, in, sess.HostKeyFingerprint, filepath.Join(core.DefaultVaultDir(), "known_hosts"))
	switch {
	case errors.Is(verr, core.ErrAdminKeyAuthRejected):
		return core.AdminKey{}, []string{"Ключ НЕ годится: сервер не принял пароль из ключа — пароль не подошёл или вход по паролю на сервере выключен (PasswordAuthentication no). Ключ vpn:// не выдан."}
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
		return "Ключ vpn:// не записан: файл не выбран."
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
	sess := u.sess
	u.setBusy(true)
	if u.status != nil {
		u.status.SetText(adminKeyReadingText)
	}
	goSafe(func() {
		r, err := guiAdminKeyPlan(sess)
		uiDo(func() {
			u.setBusy(false)
			if u.sess != sess {
				return
			}
			if err != nil {
				u.showInfo(adminKeyTitle, "Ключ vpn:// не выдан — состояние сервера неизвестно: "+core.MaskText(err.Error()))
				return
			}
			u.adminKeyConfirm(sess, r)
		})
	})
}

// adminKeyConfirm — окно согласия по прочитанному плану.
func (u *ui) adminKeyConfirm(sess *core.Session, r core.AdminKeyReissue) {
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
			key, res := adminKeyIssue(sess, r)
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
