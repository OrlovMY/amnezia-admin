package main

// Окно прогресса долгих операций копии (отзыв владельца на v0.5.0-rc.1):
// полоса «X из Y» (или бесконечная на неделимом этапе — шифровании),
// подпись этапа и единственная кнопка «Отмена». Главное окно на время
// операции недоступно (setBusy). У восстановления «Отмена» выключается с
// началом записи на сервер: прерывать запись A3б посередине опаснее.

import (
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"amnezia-admin/core"
)

// Подписи окна прогресса.
const (
	progressCancelText   = "Отмена"
	progressCancelingTxt = "Отмена… дождитесь остановки (шифрование паролем не прерывается)"
	progressNoCancelTxt  = "Идёт запись на сервер — отменить нельзя, дождитесь итога"
)

// progressView — окно прогресса (поля — для тестов).
type progressView struct {
	d      dialog.Dialog
	bar    *widget.ProgressBar
	inf    *widget.ProgressBarInfinite
	label  *widget.Label
	note   *widget.Label
	cancel *widget.Button
}

// progressWindow — показать окно прогресса; onCancel — по «Отмена».
func (u *ui) progressWindow(title string, onCancel func()) *progressView {
	v := &progressView{bar: widget.NewProgressBar(), inf: widget.NewProgressBarInfinite(),
		label: wrapLabel("подготовка…", false), note: wrapLabel("", false)}
	v.inf.Hide()
	v.cancel = widget.NewButtonWithIcon(progressCancelText, theme.CancelIcon(), func() {
		if v.cancel.Disabled() {
			return // запись на сервер уже идёт
		}
		v.cancel.Disable()
		v.note.SetText(progressCancelingTxt)
		onCancel()
	})
	body := container.NewVBox(v.label, v.bar, v.inf, v.note)
	v.d = dialog.NewCustomWithoutButtons(title, container.NewBorder(nil, container.NewCenter(v.cancel), nil, nil, body), u.win)
	sizeDialog(v.d, fyne.NewSize(560, 240))
	v.d.Show()
	return v
}

// apply — событие прогресса (в потоке интерфейса).
func (v *progressView) apply(p core.Progress) {
	v.label.SetText(p.Text)
	if p.Total > 0 {
		v.inf.Hide()
		v.bar.Show()
		v.bar.Max = float64(p.Total)
		v.bar.SetValue(float64(p.Done))
	} else {
		v.bar.Hide()
		v.inf.Show()
	}
	if p.Writing && !v.cancel.Disabled() {
		v.cancel.Disable()
		v.note.SetText(progressNoCancelTxt)
	} else if p.Writing {
		v.note.SetText(progressNoCancelTxt)
	}
}

// report — получатель прогресса из фоновой операции.
func (v *progressView) report(p core.Progress) { fyne.Do(func() { v.apply(p) }) }
