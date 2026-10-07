package main

// Диалог «найдена проблема на сервере» (05.10, Ubuntu 26.04): после
// подключения программа проверяет контейнеры WG (core.Diagnose) и, если
// проблема найдена, предлагает исправить её явно — «Исправить» / «Не
// сейчас», — с последствиями, инструкцией для ручного исправления и кнопкой
// «Скопировать команды». Команды в окне, в буфере и исполняемые — одни:
// core.FixCommands. Если проверка не удалась — окно говорит это прямо и
// исправления не предлагает.

import (
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"amnezia-admin/core"
)

// Подписи окна.
const (
	diagTitleProblem = "Найдена проблема на сервере"
	diagTitleUnknown = "Проверить сервер не удалось"
	diagFixText      = "Исправить"
	diagLaterText    = "Не сейчас"
	diagCloseText    = "Закрыть"
	diagCopyText     = "Скопировать команды"
	diagCopiedText   = "Команды скопированы в буфер обмена"
	diagManualIntro  = "Если не хотите, чтобы программа делала это сама, выполните на сервере по SSH:"
	diagResultTitle  = "Итог исправления"
)

// diagView — окно диагностики (поля — для тестов).
type diagView struct {
	d      dialog.Dialog
	plan   core.FixPlan
	fix    *escButton // nil — исправлять нечего
	later  *escButton
	copy   *widget.Button
	copied *widget.Label
	cmds   *widget.Label
}

// diagnoseAfterConnect — проверка в фоне после подключения (шов теста:
// diagnoseOnConnect=false выключает).
var diagnoseOnConnect = true

func (u *ui) diagnoseAfterConnect(sess *core.Session, cs []core.Container) {
	if !diagnoseOnConnect {
		return
	}
	goSafe(func() {
		rep := sess.Diagnose(cs)
		fyne.Do(func() {
			if u.sess != sess {
				return // уже другое подключение
			}
			u.onDiagReport(rep)
		})
	})
}

// Строки состояния диагностики.
const (
	diagNoteUnknown   = "Проверка окружения сервера (AppArmor/iptables) не удалась — подробно: amnezia-admin diagnose"
	diagNoteDismissed = "На сервере найдена проблема окружения (AppArmor/iptables), окно скрыто по «Не сейчас» — подробно: amnezia-admin diagnose"
)

// onDiagReport — что показать по итогам проверки: окно проблемы (в очереди
// за «Сохранить ключ?»), строку состояния при «не удалось узнать» (без
// окна поверх работы) или при скрытом «Не сейчас» окне.
func (u *ui) onDiagReport(rep core.DiagReport) {
	switch {
	case rep.HasProblem() && u.diagDismissed[u.sess.Creds.Host]:
		u.setDiagNote(diagNoteDismissed)
	case rep.HasProblem():
		u.setDiagNote("")
		if u.diagHold {
			u.diagPending = &rep
			return
		}
		u.showDiagDialog(rep)
	case rep.HasUnknown():
		u.setDiagNote(diagNoteUnknown)
	default:
		u.setDiagNote("")
	}
}

// releaseDiagHold — окно «Сохранить ключ?» закрыто: показать отложенное.
func (u *ui) releaseDiagHold() {
	u.diagHold = false
	if p := u.diagPending; p != nil {
		u.diagPending = nil
		u.showDiagDialog(*p)
	}
}

// setDiagNote — строка о диагностике; refresh дописывает её к своему тексту.
func (u *ui) setDiagNote(n string) {
	old := u.diagNote
	u.diagNote = n
	if u.status == nil {
		return
	}
	t := u.status.Text
	if old != "" {
		t = strings.TrimSuffix(t, " · "+old)
	}
	u.status.SetText(u.withDiagNote(t))
}

// withDiagNote — текст строки состояния с припиской диагностики.
func (u *ui) withDiagNote(t string) string {
	if u.diagNote == "" || strings.HasSuffix(t, u.diagNote) {
		return t
	}
	if t == "" {
		return u.diagNote
	}
	return t + " · " + u.diagNote
}

// diagShort — проблема коротко (полная причина — в CLI diagnose).
var diagShort = map[string]string{
	"AppArmor": "AppArmor: профили wg/wg-quick сервера не дают поднять интерфейс VPN",
	"iptables": "iptables: legacy без таблицы nat — у клиентов нет интернета",
}

// diagLines — строки отчёта, достойные окна: проблемы и «не удалось
// узнать» (исход «нет» в окно не идёт — окно о проблемах).
func diagLines(rep core.DiagReport) []string {
	var out []string
	for _, kind := range []string{"AppArmor", "iptables"} {
		var yes []string
		for _, c := range rep.Containers {
			f := c.AppArmor
			if kind == "iptables" {
				f = c.IPTables
			}
			switch f.State {
			case core.DiagYes:
				yes = append(yes, c.Name)
			case core.DiagUnknown:
				out = append(out, c.Name+" — "+kind+": не удалось узнать — "+f.Reason)
			}
		}
		if len(yes) > 0 {
			out = append(out, strings.Join(yes, ", ")+" — "+diagShort[kind])
		}
	}
	for _, n := range rep.Unfixable() {
		out = append(out, n+" — iptables: программа исправить не может (в образе нет xtables-nft-multi или узнать это не удалось); переустановите протокол из новой версии Amnezia.")
	}
	return out
}

// showDiagDialog — окно проблемы; nil — проблемы нет (окно «не удалось
// узнать» не показывается — это строка состояния, onDiagReport).
func (u *ui) showDiagDialog(rep core.DiagReport) *diagView {
	if !rep.HasProblem() {
		return nil
	}
	v := &diagView{plan: rep.Plan(u.sess.Creds.User)}
	title := diagTitleProblem
	if !rep.HasProblem() {
		title = diagTitleUnknown
	}
	var secs []fyne.CanvasObject
	for _, l := range diagLines(rep) {
		secs = append(secs, wrapLabel(l, false))
	}
	if rep.HasUnknown() {
		secs = append(secs, wrapLabel("По проверкам, которые не удались, исправление не предлагается.", false))
	}
	if !v.plan.Empty() {
		secs = append(secs, wrapLabel("Что изменит «"+diagFixText+"»:", true))
		for _, c := range v.plan.Consequences() {
			secs = append(secs, wrapLabel("• "+c, false))
		}
		secs = append(secs, wrapLabel(diagManualIntro, true))
		v.cmds = widget.NewLabelWithStyle(strings.TrimRight(core.FixCommandsText(v.plan), "\n"), fyne.TextAlignLeading, fyne.TextStyle{Monospace: true})
		v.cmds.Wrapping = fyne.TextWrapBreak
		secs = append(secs, v.cmds)
		v.copied = widget.NewLabel("")
		v.copy = widget.NewButtonWithIcon(diagCopyText, theme.ContentCopyIcon(), func() {
			u.copyToClipboard(core.FixCommandsText(v.plan), diagCopiedText)
			v.copied.SetText(diagCopiedText)
		})
		secs = append(secs, container.NewHBox(v.copy, v.copied))
	}
	hide := func() { v.d.Hide() }
	later := func() {
		if u.diagDismissed == nil {
			u.diagDismissed = map[string]bool{}
		}
		u.diagDismissed[u.sess.Creds.Host] = true
		v.d.Hide()
	}
	inner := container.NewVBox(secs...)
	body := container.NewVScroll(inner)
	var buttons fyne.CanvasObject
	if v.plan.Empty() {
		v.later = newEscButton(diagCloseText, theme.CancelIcon(), hide, hide)
		buttons = container.NewCenter(v.later)
	} else {
		v.later = newEscButton(diagLaterText, theme.CancelIcon(), later, later)
		v.fix = newEscButton(diagFixText, theme.WarningIcon(), func() {
			v.d.Hide()
			u.applyDiagFix(v.plan)
		}, hide)
		v.fix.Importance = widget.DangerImportance
		buttons = container.NewCenter(container.NewHBox(v.later, v.fix))
	}
	v.d = dialog.NewCustomWithoutButtons(title, container.NewBorder(nil, buttons, nil, nil, body), u.win)
	u.fitDialog(v.d, inner, body, 900)
	v.d.Show()
	u.win.Canvas().Focus(v.later)
	u.diagShown = v
	return v
}

// applyDiagFix — «Исправить»: команды плана, повторная проверка, итог.
func (u *ui) applyDiagFix(plan core.FixPlan) {
	sess, cs := u.sess, u.containers
	u.setBusy(true)
	goSafe(func() {
		res, err := sess.ApplyFix(plan, cs)
		fyne.Do(func() {
			u.setBusy(false)
			if err != nil {
				u.showError(err)
				return
			}
			u.showFixResult(res)
			u.refresh()
		})
	})
}

// fixResultLines — итог словами: исправлено / НЕ исправлено / неизвестно;
// при прерывании — какие шаги уже выполнены (SEC-01 З3).
func fixResultLines(res core.FixResult) []string {
	out := append([]string(nil), res.Partial()...)
	for _, o := range res.Outcomes {
		out = append(out, o.Text())
	}
	return out
}

// showFixResult — окно итога.
func (u *ui) showFixResult(res core.FixResult) dialog.Dialog {
	var secs []fyne.CanvasObject
	for _, l := range fixResultLines(res) {
		secs = append(secs, wrapLabel(l, false))
	}
	inner := container.NewVBox(secs...)
	d := dialog.NewCustom(diagResultTitle, diagCloseText, inner, u.win)
	u.fitDialog(d, inner, nil, 560)
	d.Show()
	u.diagResult = d
	return d
}
