package main

// Окно прогресса долгих операций копии (отзыв владельца на v0.5.0-rc.1):
// полоса «X из Y» (или бесконечная на неделимом этапе — шифровании),
// подпись этапа и единственная кнопка «Отмена». Главное окно на время
// операции недоступно (setBusy). У восстановления «Отмена» выключается с
// началом записи на сервер: прерывать запись A3б посередине опаснее.

import (
	"errors"
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
	cancel *escButton
	// writing — началась запись на сервер (отмена и закрытие программы
	// недоступны)
	writing bool
	// onCancel — отмена операции
	onCancel func()
}

// progressWindow — показать окно прогресса; onCancel — по «Отмена».
func (u *ui) progressWindow(title string, onCancel func()) *progressView {
	v := &progressView{bar: widget.NewProgressBar(), inf: widget.NewProgressBarInfinite(),
		label: wrapLabel("подготовка…", false), note: wrapLabel("", false), onCancel: onCancel}
	v.inf.Hide()
	// AU-UX П-4: Esc — «Отмена» (через фокус, как в остальных окнах)
	v.cancel = newEscButton(progressCancelText, theme.CancelIcon(), v.doCancel, v.doCancel)
	body := container.NewVBox(v.label, v.bar, v.inf, v.note)
	v.d = dialog.NewCustomWithoutButtons(title, container.NewBorder(nil, container.NewCenter(v.cancel), nil, nil, body), u.win)
	sizeDialog(v.d, fyne.NewSize(560, 240))
	v.d.Show()
	u.win.Canvas().Focus(v.cancel)
	u.op = v
	return v
}

// doCancel — «Отмена» (кнопка, Esc, закрытие программы до записи).
func (v *progressView) doCancel() {
	if v.cancel.Disabled() || v.writing {
		return // запись на сервер уже идёт или отмена уже нажата
	}
	v.cancel.Disable()
	v.note.SetText(progressCancelingTxt)
	v.onCancel()
}

// закрытие программы во время операции (AU-UX П-1)
const progressCloseWriting = "Идёт запись на сервер — закрыть программу сейчас нельзя, дождитесь итога."

// closeIntercept — перехват закрытия главного окна (крестик, Alt+F4):
// вне операции — закрыть; во время записи на сервер — не закрывать и
// сказать почему; во время чтения/шифрования/записи файла — отменить
// операцию и закрыть после её корректного завершения (временный файл
// удалён).
func (u *ui) closeIntercept() {
	v := u.op
	switch {
	case v == nil:
		u.closeWindow()
	case v.writing:
		dialog.NewInformation("Закрыть нельзя", progressCloseWriting, u.win).Show()
	default:
		u.closeAfterOp = true
		v.doCancel()
	}
}

// closeWindow — закрыть программу (шов теста: тестовое окно дважды не
// закрывается).
func (u *ui) closeWindow() {
	if u.closeWin != nil {
		u.closeWin()
		return
	}
	u.win.Close()
}

// closeNotDone — запрошенное закрытие не выполнено: операция дошла до
// конца (AU-UX П-5).
const closeNotDone = "Закрыть программу не удалось: запись уже шла и отменить её было нельзя. Вот итог — программа остаётся открытой."

// opFinished — конец операции: окно прогресса убрано. Если программу
// просили закрыть и операция завершилась ОТМЕНОЙ — закрыть (true). Если
// она дошла до конца (ядро уже прошло последнюю точку отмены и записало) —
// НЕ закрывать: итог обязан быть показан (AU-UX П-5), закрытие помечается
// как невыполненное.
func (u *ui) opFinished(err error) bool {
	if u.op != nil {
		u.op.d.Hide()
	}
	u.op = nil
	if !u.closeAfterOp {
		return false
	}
	u.closeAfterOp = false
	if errors.Is(err, core.ErrCanceled) {
		u.closeWindow()
		return true
	}
	u.closeRefused = true
	return false
}

// closeNotDoneNote — сказать, что закрытие не выполнено (после итога).
func (u *ui) closeNotDoneNote() {
	if u.closeRefused {
		u.closeRefused = false
		dialog.NewInformation("Программа не закрыта", closeNotDone, u.win).Show()
	}
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
	if p.Writing {
		v.writing = true
		v.cancel.Disable()
		v.note.SetText(progressNoCancelTxt)
	}
}

// report — получатель прогресса из фоновой операции.
func (v *progressView) report(p core.Progress) { fyne.Do(func() { v.apply(p) }) }
