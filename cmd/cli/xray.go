package main

// XRay в CLI (AL-01). Отличия от семейства WG:
//   - в списке нет трафика и активности (XRay не отдаёт статистику) — «—» и
//     строка-пояснение, а не 0 и не «не подключался»;
//   - вместо публичного ключа — отпечаток UUID (UUID — учётные данные);
//   - служебный UUID — отдельной строкой без номера (его не выбрать);
//   - каждое действие, меняющее server.json, перезапускает XRay: перед ним —
//     предупреждение и вопрос; -yes печатает предупреждение и продолжает;
//     без терминала и без -yes — отказ, код 2, ни одной записи.

import (
	"fmt"
	"io"
	"strconv"
	"strings"

	"amnezia-admin/core"
)

// listXRay — список клиентов XRay.
func listXRay(w io.Writer, s *core.Session, c *core.Container) ([]core.ClientEntry, error) {
	v, err := s.LoadXRayView(c)
	if err != nil {
		return nil, err
	}
	accW := 0
	for _, cl := range v.Clients {
		if n := len([]rune(core.XRayAccessText(v.Access[cl.ClientID]))); n > accW {
			accW = n
		}
	}
	if accW < len([]rune("Доступ")) {
		accW = len([]rune("Доступ"))
	}
	accW += 2
	fmt.Fprintln(w)
	fmt.Fprintln(w, cHead(pad("#", 4)+pad("Имя", 34)+pad("Создан", 21)+pad("Доступ", accW)+pad("Трафик ↓/↑", 12)+"UUID"))
	fmt.Fprintln(w, cDim(strings.Repeat("─", 4+34+21+accW+12+10)))
	for i, cl := range v.Clients {
		created := cl.Created()
		if r := []rune(created); len(r) > 19 {
			created = string(r[:19])
		}
		acc := v.Access[cl.ClientID]
		name := pad(cl.Name(), 34)
		accText := pad(core.XRayAccessText(acc), accW)
		switch {
		case v.IsInstall(cl):
			// клиент установки: обычная строка, действия недоступны
			accText = cDim(core.XRayAccessText(acc) + "; " + core.XRayInstallNote)
		case acc == core.XRayActive:
			accText = cOK(accText)
		case acc == core.XRayDisabled:
			name = cDim(name)
		default:
			accText = cWarn(accText)
		}
		fmt.Fprintln(w, cNum(pad(strconv.Itoa(i+1), 4))+name+cDim(pad(created, 21))+accText+pad("—", 12)+cDim(core.UUIDPrint(cl.ClientID)))
	}
	// Клиент установки без записи в clientsTable — строкой без номера:
	// выбрать его для действия нельзя (решение владельца 2).
	if v.InstallID != "" && v.InstallListed && !v.InstallInTable {
		fmt.Fprintln(w, pad("", 4)+cDim(pad(core.XRayServiceName, 34)+pad("", 21)+core.XRayInstallNote+"  "+v.InstallPrint))
	}
	if len(v.Clients) == 0 {
		fmt.Fprintln(w, "В clientsTable записей нет.")
	}
	fmt.Fprintln(w, cDim(core.XRayStatsNote))
	for _, n := range core.XRayNotes(v) {
		fmt.Fprintln(w, cWarn(n))
	}
	return v.Clients, nil
}

// confirmXRay — перед записью плана XRay. План без перезапуска (rename,
// отключение уже отрезанного) — без предупреждения; card != nil — карточка
// печатается всегда (как и прежде для del/rekey/отключения).
func confirmXRay(in io.Reader, out, errOut io.Writer, isTTY, yes bool, p *core.Plan, card *ActionCard, question string) (proceed bool, code int) {
	if card != nil {
		card.Restart = p.RestartsXRay()
		return confirmOrExit(in, out, errOut, isTTY, yes, *card)
	}
	if !p.RestartsXRay() {
		return true, 0
	}
	fmt.Fprintln(out)
	fmt.Fprint(out, restartWarningText())
	if yes {
		return true, 0
	}
	if !isTTY {
		fmt.Fprintln(errOut, "Действие не выполнено: без терминала требуется флаг -yes (для скриптов).")
		return false, 2
	}
	fmt.Fprintf(out, "%s и перезапустить XRay? (y/n): ", question)
	answer := strings.ToLower(strings.TrimSpace(readLine(in)))
	if answer == "y" || answer == "yes" {
		return true, 0
	}
	fmt.Fprintln(out, "Отменено.")
	return false, 2
}

// xrayPlanFor — план XRay для подкоманды над записью cl.
func xrayPlanFor(sess *core.Session, cur *core.Container, cmd string, cl core.ClientEntry) (*core.Plan, string, error) {
	switch cmd {
	case "del":
		p, err := sess.PlanDelete(cur, cl.ClientID)
		return p, "удалить", err
	case "toggle":
		enable := cl.Disabled()
		p, err := sess.PlanSetEnabled(cur, cl.ClientID, enable)
		if enable {
			return p, "включить", err
		}
		return p, "отключить", err
	case "rekey":
		p, err := sess.PlanRekey(cur, cl.ClientID)
		return p, "перевыпустить конфиг", err
	}
	return nil, "", fmt.Errorf("команда %q для XRay не поддержана", cmd)
}

// runXRayAction — del/toggle/rekey для XRay: план → карточка с
// предупреждением → запись того же плана. done — что напечатать при успехе.
func runXRayAction(in io.Reader, out, errOut io.Writer, isTTY, yes bool, sess *core.Session, cur *core.Container, cmd string, cl core.ClientEntry) (code int, err error) {
	p, action, err := xrayPlanFor(sess, cur, cmd, cl)
	if err != nil {
		return 1, err
	}
	card := buildCard(sess, cur, cl, action)
	if proceed, c := confirmXRay(in, out, errOut, isTTY, yes, p, &card, ""); !proceed {
		return c, nil
	}
	nu, err := sess.Apply(p)
	if err != nil {
		return 1, err
	}
	switch p.Action {
	case "delete":
		fmt.Fprintf(out, "Пользователь %q удалён.\n", cl.Name())
	case "enable":
		fmt.Fprintf(out, "Пользователь %q включён.\n", cl.Name())
	case "disable":
		fmt.Fprintf(out, "Пользователь %q отключён.\n", cl.Name())
	case "rekey":
		return 0, saveUserConfig(out, nu, cur.Proto)
	}
	if n := p.Note(); n != "" {
		fmt.Fprintln(out, n)
	}
	if p.RestartsXRay() {
		fmt.Fprintln(out, core.XRayVerifyScope)
	}
	return 0, nil
}

// runXRayAdd — add для XRay: план → предупреждение → запись.
func runXRayAdd(in io.Reader, out, errOut io.Writer, isTTY, yes bool, sess *core.Session, cur *core.Container, name string) (code int, err error) {
	p, err := sess.PlanAddUser(cur, name)
	if err != nil {
		return 1, err
	}
	if proceed, c := confirmXRay(in, out, errOut, isTTY, yes, p, nil, fmt.Sprintf("Создать пользователя %q", strings.TrimSpace(name))); !proceed {
		return c, nil
	}
	nu, err := sess.Apply(p)
	if err != nil {
		return 1, err
	}
	fmt.Fprintln(out, core.XRayVerifyScope)
	return 0, saveUserConfig(out, nu, cur.Proto)
}

// showXRayConfig — show-config для XRay: конфиг собирается с сервера (UUID
// хранится там); файл сохраняется в каталог конфигов, содержимое и ссылка
// печатаются только по -print.
func showXRayConfig(w io.Writer, sess *core.Session, cur *core.Container, ident string, printContent bool) error {
	clients, err := sess.LoadClients(cur)
	if err != nil {
		return err
	}
	idx, err := resolveByFlag(w, clients, ident)
	if err != nil {
		return err
	}
	nu, err := sess.XRayClientConfig(cur, clients[idx].ClientID)
	if err != nil {
		return err
	}
	dir, err := core.UserConfigsDir()
	if err != nil {
		return saveFailed(w, nu, err)
	}
	res, err := core.SaveUserConfig(dir, nu)
	if err != nil {
		return saveFailed(w, nu, err)
	}
	fmt.Fprintln(w, "Конфиг XRay собран с сервера и сохранён: "+cAccent(res.Path))
	fmt.Fprintln(w, cWarn(nu.Note))
	if printContent {
		fmt.Fprintln(w, "--- ссылка vless:// (UUID клиента — никому не пересылайте) ---")
		fmt.Fprintln(w, nu.Link)
		fmt.Fprintln(w, "--- конфиг JSON ---")
		fmt.Fprint(w, nu.Config)
	}
	return nil
}
