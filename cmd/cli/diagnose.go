package main

// diagnose — проверка окружения контейнеров WG (AppArmor wg/wg-quick,
// iptables legacy без nat; core/hostdiag.go). Три исхода на каждую проблему;
// исправление — только с флагом -fix и после явного «y» (или -yes), с
// текстом последствий; команды для ручного исправления печатаются всегда,
// когда проблема найдена, — те же строки, что выполнит -fix.

import (
	"fmt"
	"io"
	"strings"

	"amnezia-admin/core"
)

// printDiagReport — отчёт и, если есть что исправлять, последствия и
// команды. Возвращает план.
func printDiagReport(w io.Writer, sess *core.Session, rep core.DiagReport) core.FixPlan {
	plan := rep.Plan(sess.Creds.User)
	if len(rep.Containers) == 0 {
		fmt.Fprintln(w, "Контейнеров WireGuard/AmneziaWG на сервере нет — проверять нечего.")
		return plan
	}
	fmt.Fprintln(w, cHead("Проверка окружения контейнеров (AppArmor, iptables):"))
	for _, l := range rep.Summary() {
		fmt.Fprintln(w, "  "+l)
	}
	if un := rep.Unfixable(); len(un) > 0 {
		fmt.Fprintln(w, cWarn("iptables в "+strings.Join(un, ", ")+": программа исправить не может — нужен образ с xtables-nft-multi (переустановите протокол из новой версии Amnezia)."))
	}
	if rep.HasUnknown() {
		fmt.Fprintln(w, cWarn("Часть проверок не удалась — по ним исправление не предлагается (причины выше)."))
	}
	if plan.Empty() {
		if !rep.HasProblem() && !rep.HasUnknown() {
			fmt.Fprintln(w, cOK("Проблем не найдено."))
		}
		return plan
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, cWarn("Найдена проблема. Что изменит исправление:"))
	for _, c := range plan.Consequences() {
		fmt.Fprintln(w, "  - "+c)
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Чтобы исправить самостоятельно, выполните на сервере (SSH):")
	for _, c := range core.FixCommands(plan) {
		fmt.Fprintln(w, "  "+c)
	}
	return plan
}

// Коды выхода diagnose (договор со скриптами; 1 и 2 — как у остальных
// подкоманд):
//
//	0 — проверено, проблем нет (или всё исправлено);
//	1 — проблема найдена (без -fix), исправлено не всё, или ошибка;
//	2 — исправление не подтверждено (ответ не «y», без терминала нет -yes);
//	3 — проблем не найдено, но часть проверок не удалась.
const (
	diagCodeOK      = 0
	diagCodeProblem = 1
	diagCodeUnknown = 3
)

// diagCode — код по отчёту (без исправления).
func diagCode(rep core.DiagReport) int {
	switch {
	case rep.HasProblem():
		return diagCodeProblem
	case rep.HasUnknown():
		return diagCodeUnknown
	default:
		return diagCodeOK
	}
}

// runDiagnose — подкоманда diagnose [-fix [-yes]].
func runDiagnose(in io.Reader, out, errOut io.Writer, isTTY, yes, fix bool, sess *core.Session, cs []core.Container) int {
	rep := sess.Diagnose(cs)
	plan := printDiagReport(out, sess, rep)
	if plan.Empty() {
		return diagCode(rep)
	}
	if !fix {
		fmt.Fprintln(out)
		fmt.Fprintln(out, "Исправить программой: amnezia-admin diagnose -fix")
		return diagCodeProblem
	}
	if !yes {
		if !isTTY {
			fmt.Fprintln(errOut, "Действие не выполнено: без терминала требуется флаг -yes (для скриптов).")
			return 2
		}
		fmt.Fprint(out, "Исправить сейчас? (y/N): ")
		a := strings.ToLower(strings.TrimSpace(readLine(in)))
		if a != "y" && a != "yes" {
			fmt.Fprintln(out, "Отменено.")
			return 2
		}
	}
	res, err := sess.ApplyFix(plan, cs)
	if err != nil {
		fmt.Fprintln(errOut, "Ошибка:", err)
		return 1
	}
	return printFixResult(out, errOut, res)
}

// printFixResult — честный итог по повторной проверке.
func printFixResult(out, errOut io.Writer, res core.FixResult) int {
	// SEC-01 З3: прерванное исправление называет выполненные шаги. Итог
	// (и код) — по повторной проверке: если она показала «исправлено»,
	// код 0, хотя ошибка напечатана (QA-01 З2, решение).
	for _, l := range res.Partial() {
		fmt.Fprintln(errOut, cWarn(l))
	}
	fmt.Fprintln(out, "Повторная проверка:")
	code := 0
	for _, o := range res.Outcomes {
		line := "  " + o.Text()
		if o.After.State == core.DiagNo {
			line = cOK(line)
		} else {
			line = cWarn(line)
			code = 1
		}
		fmt.Fprintln(out, line)
	}
	return code
}

// diagListNote — строка под списком клиентов (list): проблема найдена или
// проверка не удалась. "" — проверено, проблем нет.
func diagListNote(rep core.DiagReport) string {
	switch {
	case rep.HasProblem():
		return "Внимание: найдена проблема окружения сервера (AppArmor/iptables) — подробно и исправление: amnezia-admin diagnose"
	case rep.HasUnknown():
		return "Проверка окружения сервера (AppArmor/iptables) не удалась — подробно: amnezia-admin diagnose"
	default:
		return ""
	}
}
