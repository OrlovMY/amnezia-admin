package main

// Копия пользователей и переезд (5/5): «Копия…» на главном экране —
// сохранить копию сервера (громкое предупреждение «НЕ ЗАШИФРОВАН» в окне
// сохранения, SEC-01) и восстановить из копии на этом (новом) сервере:
// проверка совместимости, предпросмотр, отдельные галки «адрес» и
// «перезапустить XRay», кнопка опасного вида. Ввода пароля нет (Р-1 не
// решён). Тексты — из core (одни с CLI).

import (
	"errors"
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
	backupMenuTitle    = "Копия пользователей"
	backupSaveText     = "Сохранить копию сервера…"
	backupRestoreText  = "Восстановить из копии…"
	backupSaveOK       = "Сохранить"
	restoreApplyText   = "Заменить данные сервера"
	restoreAddrCheck   = "Понимаю: адрес другой или не проверен — выданные конфиги могут не работать"
	restoreXRayCheck   = "Перезапустить XRay (все подключения XRay оборвутся)"
	backupCopyPathText = "Скопировать путь"
)

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
		wrapLabel("Копия нужна для переезда на новый сервер: ключ сервера, клиенты, параметры протоколов. Приватных ключей клиентов на сервере нет и в копии тоже — выданные конфиги продолжат работать, если сервер получит прежний адрес или конфиги выданы по имени.", false),
		save, restore)
	d = dialog.NewCustom(backupMenuTitle, "Закрыть", body, u.win)
	d.Resize(fyne.NewSize(560, 260))
	d.Show()
}

// backupDialog — окно сохранения: предупреждение SEC-01 до записи.
func (u *ui) backupDialog() dialog.Dialog {
	dir, err := core.UserBackupsDir()
	where := "Файл будет записан в каталог: " + dir
	if err != nil {
		where = "Каталог копий не определён: " + err.Error()
	}
	return u.confirmWindow("Сохранить копию сервера", []fyne.CanvasObject{
		wrapLabel(core.BackupUnencryptedWarning, true),
		wrapLabel(where, false),
	}, backupSaveOK, false, func() { u.doBackup(dir, err) })
}

// runBackupTo — снять копию и записать в dir (синхронно; для теста и для
// фоновой задачи).
func (u *ui) runBackupTo(dir string, now time.Time) (string, *core.Backup, error) {
	b, err := u.sess.CollectBackup(version.String(), now, backupResolve)
	if err != nil {
		return "", nil, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", b, err
	}
	p := filepath.Join(dir, core.BackupFileName(b.Server.Host, now))
	if err := core.WriteBackupFile(p, b, core.PlainLayer{}); err != nil {
		return "", b, err
	}
	return p, b, nil
}

func (u *ui) doBackup(dir string, dirErr error) {
	if dirErr != nil {
		u.showError(dirErr)
		return
	}
	u.setBusy(true)
	goSafe(func() {
		p, b, err := u.runBackupTo(dir, time.Now())
		fyne.Do(func() {
			u.setBusy(false)
			u.backupResult(p, b, err)
		})
	})
}

// backupResult — итог: состав копии, абсолютный путь, «Скопировать путь».
func (u *ui) backupResult(path string, b *core.Backup, err error) dialog.Dialog {
	var lines []string
	if b != nil {
		lines = core.BackupSummaryLines(b)
	}
	if err != nil {
		lines = append(lines, "", "Копия НЕ записана: "+core.MaskText(err.Error()))
	} else {
		lines = append(lines, "", "Копия записана: "+path)
	}
	objs := []fyne.CanvasObject{wrapLabel(strings.Join(lines, "\n"), false)}
	if err == nil {
		objs = append(objs, widget.NewButtonWithIcon(backupCopyPathText, theme.ContentCopyIcon(), func() {
			u.copyToClipboard(path, "Путь к копии скопирован в буфер обмена")
		}))
	}
	d := dialog.NewCustom("Копия сервера", "Закрыть", container.NewVScroll(container.NewVBox(objs...)), u.win)
	d.Resize(fyne.NewSize(640, 460))
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
func (u *ui) restorePrepare(path string) (*core.Backup, *core.CompatReport, *core.RestorePlan, error, error) {
	b, err := core.ReadBackupFile(path, core.PlainLayer{})
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

func (u *ui) restoreFromFile(path string) {
	u.setBusy(true)
	goSafe(func() {
		b, compat, rp, planErr, err := u.restorePrepare(path)
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
	apply     *widget.Button
	addrCheck *widget.Check
	xrayCheck *widget.Check
	text      string
}

// restoreWindow — сводка копии, проверка цели, план; кнопка замены
// включена, только если нет СТОП, план построен и (при необходимости)
// подтверждён адрес.
func (u *ui) restoreWindow(b *core.Backup, compat *core.CompatReport, rp *core.RestorePlan, planErr error) *restoreView {
	v := &restoreView{}
	lines := core.BackupSummaryLines(b)
	lines = append(lines, "")
	lines = append(lines, core.CompatLines(compat)...)
	switch {
	case compat.Stop:
		lines = append(lines, "", "ПЕРЕЕЗД ОСТАНОВЛЕН до записи: исправьте расхождения на новом сервере и повторите. Обновление версии при переезде программа не делает.")
	case planErr != nil:
		lines = append(lines, "", "План не построен: "+core.MaskText(planErr.Error()))
	case rp != nil:
		lines = append(lines, "")
		lines = append(lines, core.RestorePlanLines(rp)...)
	}
	v.text = strings.Join(lines, "\n")
	objs := []fyne.CanvasObject{wrapLabel(v.text, false)}
	xray := false
	if rp != nil {
		for _, it := range rp.Items {
			xray = xray || it.RestartsXRay
		}
	}
	update := func() {}
	if compat.NeedAddressConfirm {
		v.addrCheck = widget.NewCheck(restoreAddrCheck, func(bool) { update() })
		objs = append(objs, v.addrCheck)
	}
	if xray {
		objs = append(objs, restartSections()...)
		v.xrayCheck = widget.NewCheck(restoreXRayCheck, nil)
		objs = append(objs, v.xrayCheck)
	}
	v.apply = widget.NewButtonWithIcon(restoreApplyText, theme.WarningIcon(), func() { u.doRestore(rp, v) })
	v.apply.Importance = widget.DangerImportance
	update = func() {
		ok := !compat.Stop && planErr == nil && rp != nil && (v.addrCheck == nil || v.addrCheck.Checked)
		if ok {
			v.apply.Enable()
		} else {
			v.apply.Disable()
		}
	}
	update()
	content := container.NewBorder(nil, container.NewCenter(v.apply), nil, nil, container.NewVScroll(container.NewVBox(objs...)))
	v.d = dialog.NewCustom("Восстановить из копии на этом сервере", "Отмена", content, u.win)
	v.d.Resize(fyne.NewSize(760, 560))
	v.d.Show()
	return v
}

// runRestore — замена (синхронно; для теста и для фоновой задачи).
func (u *ui) runRestore(rp *core.RestorePlan, xrayOK bool, now time.Time) (string, []core.RestoreOutcome, error) {
	dir, err := core.UserBackupsDir()
	if err == nil {
		err = os.MkdirAll(dir, 0o700)
	}
	if err != nil {
		return "", nil, errors.New("каталог автокопии не определён — замена запрещена: " + err.Error())
	}
	return u.sess.Restore(rp, core.RestoreOptions{AutoCopyDir: dir, ToolVersion: version.String(), Now: now,
		Resolve: backupResolve, Layer: core.PlainLayer{}, ConfirmXRay: func() bool { return xrayOK }})
}

func (u *ui) doRestore(rp *core.RestorePlan, v *restoreView) {
	xrayOK := v.xrayCheck != nil && v.xrayCheck.Checked
	v.d.Hide()
	u.setBusy(true)
	goSafe(func() {
		auto, outs, err := u.runRestore(rp, xrayOK, time.Now())
		fyne.Do(func() {
			u.setBusy(false)
			u.restoreResult(auto, outs, err)
			u.refresh()
		})
	})
}

func (u *ui) restoreResult(auto string, outs []core.RestoreOutcome, err error) dialog.Dialog {
	text := ""
	if err != nil {
		text = "Ничего не записано: " + core.MaskText(err.Error())
	} else {
		text = strings.Join(core.RestoreOutcomeLines(auto, outs), "\n")
	}
	d := dialog.NewCustom("Итог восстановления", "Закрыть", container.NewVScroll(wrapLabel(text, false)), u.win)
	d.Resize(fyne.NewSize(700, 480))
	d.Show()
	return d
}
