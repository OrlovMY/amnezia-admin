package core

// Диагностика окружения контейнеров семейства WG (05.10, Ubuntu 26.04,
// ядро 7.0). Две найденные вживую неисправности:
//
//  1. AppArmor: профили /etc/apparmor.d/wg-quick и /etc/apparmor.d/wg
//     (пакет apparmor хоста) привязаны к /usr/bin/wg-quick и /usr/bin/wg и
//     действуют на процессы ВНУТРИ контейнеров: wg-quick не может запустить
//     busybox, wg не может открыть сокет. Итог — интерфейса в контейнере нет,
//     в журнале ядра apparmor="DENIED" profile="wg-quick"/"wg".
//  2. iptables legacy: образ на Alpine 3.15 с iptables 1.8.7 legacy, а в
//     ядре нет таблиц ip_tables legacy — start.sh не ставит MASQUERADE
//     («Table does not exist»): рукопожатие есть, интернета нет.
//
// Признаки — ПО СУЩЕСТВУ (интерфейса нет и отказ AppArmor в журнале;
// iptables legacy и таблицы nat нет), а не по версии ОС: программа — под
// любой сервер Amnezia.
//
// У каждой проблемы ТРИ исхода (CLAUDE.md, «незнание не выдаётся за
// знание»): есть / нет / не удалось узнать — с причиной. Нулевое значение
// DiagState — «не удалось узнать»: забытое присваивание не превращается в
// «нет». Для «не удалось узнать» исправление не предлагается: его нет в
// FixPlan (DiagReport.Plan берёт только DiagYes).
//
// Команды исправления строит ОДНА функция FixCommands: её же текст человек
// копирует в буфер, и её же строки исполняет ApplyFix — инструкция не может
// разойтись с делом (тест TestFixRunsExactlyCopiedCommands).

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// DiagState — исход проверки одной проблемы.
type DiagState int

const (
	// DiagUnknown — узнать не удалось (причина — в DiagFinding.Reason).
	// Нулевое значение намеренно.
	DiagUnknown DiagState = iota
	// DiagNo — проблемы нет (проверено).
	DiagNo
	// DiagYes — проблема есть (проверено).
	DiagYes
)

// String — слово для журнала и тестов.
func (s DiagState) String() string {
	switch s {
	case DiagNo:
		return "нет"
	case DiagYes:
		return "есть"
	default:
		return "не удалось узнать"
	}
}

// DiagFinding — исход и его пояснение.
type DiagFinding struct {
	State  DiagState
	Reason string
}

// ContainerDiag — диагностика одного контейнера.
type ContainerDiag struct {
	Name  string
	Iface string
	// AppArmor — профили wg/wg-quick хоста мешают поднять интерфейс.
	AppArmor DiagFinding
	// IPTables — iptables legacy без таблицы nat (нет MASQUERADE).
	IPTables DiagFinding
	// NFT — есть ли в образе /sbin/xtables-nft-multi (нужен для исправления
	// IPTables). DiagUnknown — проверка контейнера не выполнилась.
	NFT DiagState
}

// DiagReport — итог диагностики сервера.
type DiagReport struct {
	Containers []ContainerDiag
	// loaded — профили wg/wg-quick, загруженные в ядро (из пробы хоста);
	// нужны, чтобы apparmor_parser -R не падал на незагруженном.
	loaded []string
	// profKnown — список загруженных профилей прочитан.
	profKnown bool
}

// HasProblem — есть ли хоть одна проблема (DiagYes).
func (r DiagReport) HasProblem() bool {
	for _, c := range r.Containers {
		if c.AppArmor.State == DiagYes || c.IPTables.State == DiagYes {
			return true
		}
	}
	return false
}

// HasUnknown — есть ли хоть один исход «не удалось узнать».
func (r DiagReport) HasUnknown() bool {
	for _, c := range r.Containers {
		if c.AppArmor.State == DiagUnknown || c.IPTables.State == DiagUnknown {
			return true
		}
	}
	return false
}

// Unfixable — контейнеры с проблемой iptables, которую этим способом не
// исправить: в образе нет xtables-nft-multi (или узнать это не удалось).
func (r DiagReport) Unfixable() []string {
	var out []string
	for _, c := range r.Containers {
		if c.IPTables.State == DiagYes && c.NFT != DiagYes {
			out = append(out, c.Name)
		}
	}
	return out
}

// ---------- пробы ----------

// diagSbin — каталог iptables в образах Amnezia (Alpine).
const diagSbin = "/sbin"

// Метки проб: по ним fakesrv узнаёт команду, и они же — первая строка
// скрипта (команда «:» ничего не делает).
const (
	DiagContainerTag = ": aa-diag-c1;"
	DiagHostTag      = ": aa-diag-h1;"
)

// diagContainerScript — проба внутри контейнера. NATERR — причина для
// человека: первая строка ошибки, кроме «Perhaps…», и строка «Table does
// not exist», если она не первая (вживую первой бывает строка modprobe). Печатает строки
// КЛЮЧ=значение и последней — END: без END проба не считается выполненной.
// Без одинарных кавычек — скрипт идёт в sh -c '…'.
func diagContainerScript(iface, sbin string) string {
	return DiagContainerTag +
		` if ! command -v ip >/dev/null 2>&1; then echo IFACE=unknown; elif ip link show ` + iface + ` >/dev/null 2>&1; then echo IFACE=yes; else echo IFACE=no; fi;` +
		` if command -v iptables >/dev/null 2>&1; then echo "IPTV=$(iptables -V 2>&1 | head -n 1)"; o=$(iptables -t nat -S POSTROUTING 2>&1); echo "NATRC=$?";` +
		` echo "$o" | grep -q MASQUERADE && echo MASQ=yes; echo "$o" | grep -q "does not exist" && echo NOTABLE=yes; f=$(echo "$o" | grep -v "^Perhaps" | head -n 1); tb=$(echo "$o" | grep "does not exist" | head -n 1); if [ -n "$tb" ] && [ "$tb" != "$f" ]; then f="$f; $tb"; fi; echo "NATERR=$f"; else echo IPTV=; fi;` +
		` if [ -x ` + sbin + `/xtables-nft-multi ]; then echo NFT=yes; else echo NFT=no; fi; echo END`
}

// diagContainerCmd — команда пробы контейнера на хосте.
func diagContainerCmd(container, iface string) string {
	return "docker exec " + container + " sh -c '" + diagContainerScript(iface, diagSbin) + "'"
}

// diagHostScript — проба хоста: есть ли AppArmor, какие из профилей
// wg/wg-quick загружены в режиме enforce, какие отказы в журнале ядра.
func diagHostScript(modDir, profFile string) string {
	return DiagHostTag +
		` if [ ! -d ` + modDir + ` ]; then echo AA=none; else echo AA=yes;` +
		` if pl=$(cat ` + profFile + ` 2>/dev/null); then echo PROF=readable; echo "$pl" | grep -E "^(wg-quick|wg) [(]enforce[)]" | sed "s/ .*//; s/^/LOADED=/"; else echo PROF=unreadable; fi; fi;` +
		` if l=$(dmesg 2>/dev/null) || l=$(journalctl -k -q --no-pager 2>/dev/null); then echo LOG=readable;` +
		` echo "$l" | grep "apparmor=.DENIED." | grep -oE "profile=.(wg-quick|wg)[^a-z0-9_-]" | sort -u | sed "s/^profile=.//; s/.$//; s/^/DENIED=/"; else echo LOG=unreadable; fi; echo END`
}

// DiagHostCmd — команда пробы хоста.
func diagHostCmd() string {
	return "sh -c '" + diagHostScript("/sys/module/apparmor", "/sys/kernel/security/apparmor/profiles") + "'"
}

// probe — разобранный вывод пробы: значения по ключу (повторяющиеся — все).
type probe struct {
	ok  bool   // проба выполнилась до конца (есть END)
	err string // почему не выполнилась
	kv  map[string][]string
}

func (p probe) get(k string) string {
	if v := p.kv[k]; len(v) > 0 {
		return v[0]
	}
	return ""
}

func (p probe) has(k string) bool { _, ok := p.kv[k]; return ok }

func parseProbe(out string, runErr error) probe {
	p := probe{kv: map[string][]string{}}
	end := false
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimRight(line, "\r")
		if line == "END" {
			end = true
			continue
		}
		if i := strings.IndexByte(line, '='); i > 0 {
			p.kv[line[:i]] = append(p.kv[line[:i]], line[i+1:])
		}
	}
	switch {
	case runErr != nil:
		p.err = runErr.Error()
	case !end:
		p.err = "проба оборвалась, не дойдя до конца"
	default:
		p.ok = true
	}
	return p
}

// classifyAppArmor — исход проблемы AppArmor для контейнера c по пробе
// контейнера и пробе хоста h. Порядок ветвей важен: «интерфейс есть» —
// единственное, что отвечает «нет» без журнала; все прочие «нет» требуют
// прочитанных данных хоста.
func classifyAppArmor(c probe, iface string, h probe) DiagFinding {
	loaded, denied := wgProfiles(h.kv["LOADED"]), wgProfiles(h.kv["DENIED"])
	switch {
	case !c.ok:
		return DiagFinding{DiagUnknown, "проверка контейнера не выполнилась: " + c.err}
	case c.get("IFACE") == "yes":
		return DiagFinding{DiagNo, "интерфейс " + iface + " есть"}
	case c.get("IFACE") != "no":
		return DiagFinding{DiagUnknown, "в контейнере нет утилиты ip — есть ли интерфейс " + iface + ", не проверить"}
	case !h.ok:
		return DiagFinding{DiagUnknown, "интерфейса " + iface + " нет, а проверка AppArmor на сервере не выполнилась: " + h.err}
	case h.get("AA") == "none":
		return DiagFinding{DiagNo, "AppArmor на сервере нет; интерфейса " + iface + " нет по другой причине"}
	// Б1 (QA-01): «профили прочитаны и не загружены» стоит ВЫШЕ отказов в
	// журнале — журнал хранит отказы до перезагрузки, и после исправления
	// старый DENIED перехватывал бы «нет» (признак 3 CLAUDE.md).
	case h.get("PROF") == "readable" && len(loaded) == 0:
		return DiagFinding{DiagNo, "профили wg/wg-quick не загружены (отказы в журнале, если есть, — прежние); интерфейса " + iface + " нет по другой причине"}
	case len(denied) > 0 && h.get("PROF") == "readable":
		return DiagFinding{DiagYes, "интерфейса " + iface + " нет, профили " + strings.Join(loaded, ", ") + " загружены, в журнале ядра их отказы (" + strings.Join(denied, ", ") + ")"}
	case len(denied) > 0:
		return DiagFinding{DiagYes, "интерфейса " + iface + " нет, в журнале ядра отказы AppArmor профилей " + strings.Join(denied, ", ") + " (список загруженных профилей прочитать не удалось — отказы могут быть прежними)"}
	case h.get("PROF") == "readable":
		return DiagFinding{DiagUnknown, "интерфейса " + iface + " нет, профили " + strings.Join(loaded, ", ") + " включены, но отказов в журнале ядра не видно (журнал мог быть очищен или недоступен)"}
	default:
		return DiagFinding{DiagUnknown, "интерфейса " + iface + " нет, а журнал ядра и список профилей AppArmor прочитать не удалось (нужны права root)"}
	}
}

// classifyIPTables — исход проблемы iptables legacy.
func classifyIPTables(c probe) DiagFinding {
	v := c.get("IPTV")
	switch {
	case !c.ok:
		return DiagFinding{DiagUnknown, "проверка контейнера не выполнилась: " + c.err}
	case v == "":
		return DiagFinding{DiagUnknown, "iptables в контейнере не найден или не ответил"}
	case strings.Contains(v, "nf_tables"):
		return DiagFinding{DiagNo, "iptables работает через nf_tables (" + v + ")"}
	case !strings.Contains(v, "legacy"):
		return DiagFinding{DiagUnknown, "неизвестный вариант iptables: " + v}
	case c.has("NOTABLE"):
		return DiagFinding{DiagYes, "iptables legacy, а в ядре нет таблицы nat (" + c.get("NATERR") + ") — MASQUERADE не ставится, у клиентов нет интернета"}
	case c.get("NATRC") == "0" && c.has("MASQ"):
		return DiagFinding{DiagNo, "iptables legacy работает, MASQUERADE есть"}
	case c.get("NATRC") == "0":
		return DiagFinding{DiagUnknown, "таблица nat есть, но правила MASQUERADE нет — причина не в iptables legacy, этим способом не исправить"}
	default:
		return DiagFinding{DiagUnknown, "iptables -t nat не ответил: " + c.get("NATERR")}
	}
}

func classifyNFT(c probe) DiagState {
	switch {
	case !c.ok:
		return DiagUnknown
	case c.get("NFT") == "yes":
		return DiagYes
	case c.get("NFT") == "no":
		return DiagNo
	default:
		return DiagUnknown
	}
}

// hostNeedsRoot — проба хоста не прочитала то, что требует root.
func hostNeedsRoot(h probe) bool {
	return !h.ok || h.get("LOG") == "unreadable" || h.get("PROF") == "unreadable"
}

// Diagnose — диагностика контейнеров семейства WG из cs. Контейнеры вне
// семейства не проверяются (у них нет wg-quick и NAT-правил start.sh).
// Ошибок не возвращает: всё, что узнать не удалось, — DiagUnknown с
// причиной в отчёте.
func (s *Session) Diagnose(cs []Container) DiagReport {
	type target struct {
		name, iface string
		p           probe
	}
	var ts []target
	for i := range cs {
		f, err := WGFamilyOf(&cs[i])
		if err != nil {
			continue
		}
		out, runErr := s.docker(diagContainerCmd(f.Container, f.Iface), nil)
		ts = append(ts, target{f.Container, f.Iface, parseProbe(out, runErr)})
	}
	var rep DiagReport
	if len(ts) == 0 {
		return rep
	}
	// Проба хоста нужна, только если где-то интерфейса нет.
	needHost := false
	for _, t := range ts {
		if t.p.ok && t.p.get("IFACE") == "no" {
			needHost = true
		}
	}
	h := probe{err: "не выполнялась"}
	if needHost {
		h = s.hostProbe()
		if h.ok {
			rep.loaded = h.kv["LOADED"]
			rep.profKnown = h.get("PROF") == "readable" || h.get("AA") == "none"
		}
	}
	for _, t := range ts {
		rep.Containers = append(rep.Containers, ContainerDiag{
			Name:     t.name,
			Iface:    t.iface,
			AppArmor: classifyAppArmor(t.p, t.iface, h),
			IPTables: classifyIPTables(t.p),
			NFT:      classifyNFT(t.p),
		})
	}
	return rep
}

// hostProbe — проба хоста; не от root и без прав на журнал — повтор через
// sudo -n (не ждёт пароля: без пароля в sudoers — отказ, а не зависание).
func (s *Session) hostProbe() probe {
	out, err := s.run(diagHostCmd(), nil)
	h := parseProbe(out, err)
	if hostNeedsRoot(h) && !s.isRoot() {
		out2, err2 := s.run("sudo -n "+diagHostCmd(), nil)
		if h2 := parseProbe(out2, err2); h2.ok {
			return h2
		}
	}
	return h
}

func (s *Session) isRoot() bool { return s.Creds != nil && s.Creds.User == "root" }

// ---------- исправление ----------

// wgProfiles — имена профилей из вывода сервера, отфильтрованные по
// ЗАКРЫТОМУ списку {wg-quick, wg} (SEC-01 З1): строка с сервера не попадает
// в аргументы apparmor_parser без проверки в Go.
func wgProfiles(xs []string) []string {
	var out []string
	seen := map[string]bool{}
	for _, x := range xs {
		if (x == "wg-quick" || x == "wg") && !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	return out
}

// FixPlan — что исправлять. Только проблемы с исходом DiagYes; iptables —
// только где в образе есть xtables-nft-multi.
type FixPlan struct {
	// AppArmor — контейнеры, у которых интерфейс не поднялся из-за AppArmor.
	AppArmor []string
	// IPTables — контейнеры с iptables legacy без таблицы nat.
	IPTables []string
	// Profiles — профили для apparmor_parser -R (загруженные; если список
	// прочитать не удалось — оба).
	Profiles []string
	// User — пользователь SSH: не root — команды идут через sudo.
	User string
}

// Empty — исправлять нечего.
func (p FixPlan) Empty() bool { return len(p.AppArmor) == 0 && len(p.IPTables) == 0 }

// Plan — план исправления по отчёту. DiagUnknown в план не попадает.
func (r DiagReport) Plan(user string) FixPlan {
	p := FixPlan{User: user}
	for _, c := range r.Containers {
		if c.AppArmor.State == DiagYes {
			p.AppArmor = append(p.AppArmor, c.Name)
		}
		if c.IPTables.State == DiagYes && c.NFT == DiagYes {
			p.IPTables = append(p.IPTables, c.Name)
		}
	}
	if len(p.AppArmor) > 0 {
		if r.profKnown {
			p.Profiles = append(p.Profiles, wgProfiles(r.loaded)...)
		} else {
			p.Profiles = []string{"wg-quick", "wg"}
		}
		sort.Sort(sort.Reverse(sort.StringSlice(p.Profiles))) // wg-quick, wg
	}
	return p
}

// iptablesLinkScript — ссылки iptables* на xtables-nft-multi в контейнере.
func iptablesLinkScript() string {
	return "cd " + diagSbin + " && for f in iptables iptables-save iptables-restore ip6tables ip6tables-save ip6tables-restore; do ln -sf xtables-nft-multi $f || exit 1; done"
}

// FixCommands — ЕДИНСТВЕННЫЙ источник команд исправления: этот текст
// человек копирует кнопкой «Скопировать команды», и эти же строки по одной
// исполняет ApplyFix. Не root — каждая строка через sudo (как
// Session.docker при отказе прав).
func FixCommands(p FixPlan) []string {
	pre := ""
	if p.User != "root" {
		pre = "sudo "
	}
	var cmds []string
	if len(p.AppArmor) > 0 {
		cmds = append(cmds, pre+"ln -sf /etc/apparmor.d/wg-quick /etc/apparmor.d/wg /etc/apparmor.d/disable/")
		if len(p.Profiles) > 0 {
			args := make([]string, len(p.Profiles))
			for i, n := range p.Profiles {
				args[i] = "/etc/apparmor.d/" + n
			}
			cmds = append(cmds, pre+"apparmor_parser -R "+strings.Join(args, " "))
		}
	}
	for _, c := range p.IPTables {
		cmds = append(cmds, pre+"docker exec "+c+" sh -c '"+iptablesLinkScript()+"'")
	}
	if rs := p.restartList(); len(rs) > 0 {
		cmds = append(cmds, pre+"docker restart "+strings.Join(rs, " "))
	}
	return cmds
}

// FixCommandsText — текст для буфера обмена: те же строки FixCommands.
func FixCommandsText(p FixPlan) string { return strings.Join(FixCommands(p), "\n") + "\n" }

func (p FixPlan) restartList() []string {
	set := map[string]bool{}
	for _, c := range append(append([]string(nil), p.AppArmor...), p.IPTables...) {
		set[c] = true
	}
	var out []string
	for c := range set {
		out = append(out, c)
	}
	sort.Strings(out)
	return out
}

// Consequences — что изменится на сервере (текст подтверждения).
func (p FixPlan) Consequences() []string {
	var out []string
	if len(p.AppArmor) > 0 {
		out = append(out, "AppArmor: защита профилей wg и wg-quick снимается на ВСЁМ сервере, а не только в контейнерах Amnezia (вернуть: удалить ссылки из /etc/apparmor.d/disable/ и выполнить apparmor_parser -r для этих профилей).")
	}
	if len(p.IPTables) > 0 {
		out = append(out, "iptables: в контейнере "+strings.Join(p.IPTables, ", ")+" меняются файлы /sbin/iptables*; при пересоздании контейнера из образа исправление пропадёт — проверку нужно будет повторить.")
	}
	if rs := p.restartList(); len(rs) > 0 {
		out = append(out, "Перезапуск "+strings.Join(rs, ", ")+": подключения клиентов этих протоколов оборвутся на несколько секунд.")
	}
	return out
}

// FixOutcome — итог одной исправляемой проблемы после повторной проверки.
type FixOutcome struct {
	Kind      string // "AppArmor" | "iptables"
	Container string
	After     DiagFinding // DiagNo — исправлено; DiagYes — не исправлено; DiagUnknown — неизвестно
}

// Text — итог словами: исправлено / не исправлено / неизвестно.
func (o FixOutcome) Text() string {
	switch o.After.State {
	case DiagNo:
		return o.Kind + " в " + o.Container + ": исправлено"
	case DiagYes:
		return o.Kind + " в " + o.Container + ": НЕ исправлено — " + o.After.Reason
	default:
		return o.Kind + " в " + o.Container + ": неизвестно — " + o.After.Reason
	}
}

// Partial — если исправление прервалось: какие команды уже выполнены
// (SEC-01 З3). Пусто — прерывания не было.
func (r FixResult) Partial() []string {
	if r.RunErr == nil {
		return nil
	}
	done := r.Ran[:len(r.Ran)-1] // последняя — упавшая
	out := []string{"Исправление прервано: " + r.RunErr.Error()}
	if len(done) == 0 {
		return append(out, "До ошибки на сервере ничего не изменено.")
	}
	out = append(out, "Уже выполнено (изменения остались на сервере):")
	for _, c := range done {
		out = append(out, "  "+c)
	}
	return out
}

// FixResult — итог ApplyFix.
type FixResult struct {
	// Ran — выполненные команды (успешно или последняя — с ошибкой).
	Ran []string
	// RunErr — первая упавшая команда (после неё остальные не выполнялись).
	RunErr   error
	Outcomes []FixOutcome
	After    DiagReport
}

// Diag-ожидания после перезапуска: start.sh поднимает интерфейс и NAT не
// мгновенно. Шов теста — SetDiagWaits.
var (
	diagRecheckWait  = 4 * time.Second
	diagRecheckTimes = 4
)

// SetDiagWaits — для тестов; возвращает восстановление.
func SetDiagWaits(wait time.Duration, times int) (restore func()) {
	w, n := diagRecheckWait, diagRecheckTimes
	diagRecheckWait, diagRecheckTimes = wait, times
	return func() { diagRecheckWait, diagRecheckTimes = w, n }
}

// ErrNothingToFix — план пуст.
var ErrNothingToFix = errors.New("исправлять нечего")

// ApplyFix выполняет FixCommands(p) по одной строке (до первой ошибки) и
// проверяет сервер заново. Итог — по ПОВТОРНОЙ проверке, а не по кодам
// команд: «исправлено» только при DiagNo.
func (s *Session) ApplyFix(p FixPlan, cs []Container) (FixResult, error) {
	if p.Empty() {
		return FixResult{}, ErrNothingToFix
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var res FixResult
	for _, c := range FixCommands(p) {
		res.Ran = append(res.Ran, c)
		if _, err := s.run(c, nil); err != nil {
			res.RunErr = fmt.Errorf("команда не выполнилась: %w", err)
			break
		}
	}
	for i := 0; i < diagRecheckTimes; i++ {
		if diagRecheckWait > 0 {
			time.Sleep(diagRecheckWait)
		}
		res.After = s.Diagnose(cs)
		res.Outcomes = outcomes(p, res.After)
		if allFixed(res.Outcomes) {
			break
		}
	}
	return res, nil
}

func outcomes(p FixPlan, r DiagReport) []FixOutcome {
	find := func(name string) (ContainerDiag, bool) {
		for _, c := range r.Containers {
			if c.Name == name {
				return c, true
			}
		}
		return ContainerDiag{}, false
	}
	var out []FixOutcome
	for _, n := range p.AppArmor {
		c, ok := find(n)
		f := c.AppArmor
		if !ok {
			f = DiagFinding{DiagUnknown, "контейнер не проверен повторно (нет в списке запущенных?)"}
		}
		out = append(out, FixOutcome{"AppArmor", n, f})
	}
	for _, n := range p.IPTables {
		c, ok := find(n)
		f := c.IPTables
		if !ok {
			f = DiagFinding{DiagUnknown, "контейнер не проверен повторно (нет в списке запущенных?)"}
		}
		out = append(out, FixOutcome{"iptables", n, f})
	}
	return out
}

func allFixed(xs []FixOutcome) bool {
	for _, o := range xs {
		if o.After.State != DiagNo {
			return false
		}
	}
	return true
}

// Summary — строки отчёта для человека (CLI, GUI): по контейнеру и
// проблеме, все три исхода.
func (r DiagReport) Summary() []string {
	var out []string
	for _, c := range r.Containers {
		out = append(out, fmt.Sprintf("%s — AppArmor: %s (%s)", c.Name, c.AppArmor.State, c.AppArmor.Reason))
		out = append(out, fmt.Sprintf("%s — iptables: %s (%s)", c.Name, c.IPTables.State, c.IPTables.Reason))
		if c.IPTables.State == DiagYes && c.NFT != DiagYes {
			why := "в образе нет " + diagSbin + "/xtables-nft-multi"
			if c.NFT == DiagUnknown {
				why = "не удалось узнать, есть ли в образе xtables-nft-multi"
			}
			out = append(out, fmt.Sprintf("%s — iptables исправить этим способом нельзя: %s", c.Name, why))
		}
	}
	return out
}
