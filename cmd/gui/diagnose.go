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
			u.showDiagDialog(rep)
		})
	})
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

// showDiagDialog — окно по итогам проверки; nil — показывать нечего
// (проверено, проблем нет, или WG-контейнеров нет).
func (u *ui) showDiagDialog(rep core.DiagReport) *diagView {
	if !rep.HasProblem() && !rep.HasUnknown() {
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
	inner := container.NewVBox(secs...)
	body := container.NewVScroll(inner)
	var buttons fyne.CanvasObject
	if v.plan.Empty() {
		v.later = newEscButton(diagCloseText, theme.CancelIcon(), hide, hide)
		buttons = container.NewCenter(v.later)
	} else {
		v.later = newEscButton(diagLaterText, theme.CancelIcon(), hide, hide)
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

// fixResultLines — итог словами: исправлено / НЕ исправлено / неизвестно.
func fixResultLines(res core.FixResult) []string {
	var out []string
	if res.RunErr != nil {
		out = append(out, res.RunErr.Error())
	}
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
