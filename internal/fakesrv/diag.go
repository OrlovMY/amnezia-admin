package fakesrv

// Модель неисправностей Ubuntu 26.04 / ядра 7.0 для core.Diagnose и
// core.ApplyFix (05.10): AppArmor-профили wg/wg-quick хоста, мешающие
// wg-quick в контейнерах amnezia-awg/amnezia-wireguard, и iptables legacy без
// таблицы nat в образе Alpine 3.15. Модель отвечает на пробы и на команды
// исправления по СОСТОЯНИЮ, а не по сценарию: исправление меняет состояние,
// повторная проба видит изменённое.

import (
	"regexp"
	"sort"
	"strings"
)

// Метки проб — копия core.DiagContainerTag / core.DiagHostTag (пакет не
// импортирует core). Совпадение сверяет core/hostdiag_test.go.
const (
	DiagContainerTag = ": aa-diag-c1;"
	DiagHostTag      = ": aa-diag-h1;"
)

// DiagModel — состояние сервера для диагностики. nil в Server.Diag —
// исправный сервер: интерфейсы есть, iptables nf_tables, AppArmor без
// профилей wg.
type DiagModel struct {
	// NoAppArmor — AppArmor на хосте нет.
	NoAppArmor bool
	// Profiles — профили wg/wg-quick, загруженные в ядро (enforce).
	Profiles []string
	// StaleDenied — отказы в журнале от прошлого (профили уже сняты).
	StaleDenied []string
	// IfaceDown — интерфейса нет по причине, не связанной с AppArmor.
	IfaceDown map[string]bool
	// ProfNeedSudo — список профилей читается только под sudo -n (журнал —
	// и без sudo).
	ProfNeedSudo bool
	// FakeLoaded — лишние строки LOADED= в выводе (подсунутое сервером).
	FakeLoaded []string
	// LogUnreadable, ProfUnreadable — журнал ядра / список профилей не
	// читаются (и под sudo тоже).
	LogUnreadable, ProfUnreadable bool
	// NeedSudo — журнал и профили читаются только под sudo -n.
	NeedSudo bool
	// HostFail — проба хоста падает этой ошибкой.
	HostFail error
	// Legacy — контейнеры с iptables legacy без таблицы nat.
	Legacy map[string]bool
	// NoNFT — в образе контейнера нет /sbin/xtables-nft-multi.
	NoNFT map[string]bool
	// ProbeFail — проба контейнера падает этой ошибкой.
	ProbeFail map[string]error
	// Truncate — вывод пробы контейнера обрывается до END (обрыв связи
	// посреди вывода, код 0).
	Truncate map[string]bool
	// NoIP — в контейнере нет утилиты ip.
	NoIP map[string]bool
	// LegacyNoMasq — legacy с таблицей nat, но без MASQUERADE.
	LegacyNoMasq map[string]bool
	// FailFix — команда исправления, содержащая эту подстроку, падает.
	FailFix string
	// IgnoreParser — apparmor_parser -R «успешен», но профили остаются
	// (модель исправления, которое не подействовало).
	IgnoreParser bool

	init     bool
	ifaceUp  map[string]bool
	linked   map[string]bool
	masq     map[string]bool
	denied   []string
	disabled map[string]bool
}

var (
	reDiagC       = regexp.MustCompile(`^docker exec (\S+) sh -c '` + regexp.QuoteMeta(DiagContainerTag))
	reDiagH       = regexp.MustCompile(`^(?:-n )?sh -c '` + regexp.QuoteMeta(DiagHostTag))
	reAADisable   = regexp.MustCompile(`^ln -sf /etc/apparmor\.d/wg-quick /etc/apparmor\.d/wg /etc/apparmor\.d/disable/$`)
	reAAParser    = regexp.MustCompile(`^apparmor_parser -R((?: /etc/apparmor\.d/(?:wg|wg-quick))+)$`)
	reIPTLink     = regexp.MustCompile(`^docker exec (\S+) sh -c 'cd /sbin && for f in iptables iptables-save iptables-restore ip6tables ip6tables-save ip6tables-restore; do ln -sf xtables-nft-multi \$f \|\| exit 1; done'$`)
	reDiagRestart = regexp.MustCompile(`^docker restart ((?:amnezia-(?:awg|wireguard|awg2) ?)+)$`)
)

// wgQuickContainer — контейнеры, где wg-quick/wg лежат в /usr/bin (под
// действием профилей хоста); amnezia-awg2 — awg-quick, не затронут.
func wgQuickContainer(n string) bool { return n == "amnezia-awg" || n == "amnezia-wireguard" }

func (m *DiagModel) ensure(names []string) {
	if m.init {
		return
	}
	m.init = true
	m.ifaceUp, m.linked, m.masq, m.disabled = map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}
	hit := false
	for _, n := range names {
		m.start(n)
		if wgQuickContainer(n) && !m.NoAppArmor && len(m.Profiles) > 0 {
			hit = true
		}
	}
	m.denied = append(m.denied, m.StaleDenied...)
	if hit {
		m.denied = append(m.denied, m.Profiles...)
		sort.Strings(m.denied)
	}
}

// start — (пере)запуск контейнера: интерфейс поднимается, если профили не
// мешают; MASQUERADE ставится, если iptables умеет nat.
func (m *DiagModel) start(n string) {
	m.ifaceUp[n] = !(wgQuickContainer(n) && !m.NoAppArmor && len(m.Profiles) > 0) && !m.IfaceDown[n]
	m.masq[n] = !m.Legacy[n] || m.linked[n]
	if m.LegacyNoMasq[n] && !m.linked[n] {
		m.masq[n] = false
	}
}

func (s *Server) dispatchDiag(cmd string) (string, error, bool) {
	m := s.Diag
	if m == nil {
		m = &DiagModel{}
		s.Diag = m
	}
	m.ensure(s.Names)
	orig := cmd
	if n := len(s.commands); n > 0 {
		orig = s.commands[n-1]
	}
	sudo := strings.HasPrefix(orig, "sudo ")
	if mm := reDiagC.FindStringSubmatch(cmd); mm != nil {
		if err := m.ProbeFail[mm[1]]; err != nil {
			return "", err, true
		}
		if !s.hasName(mm[1]) {
			return "", &ExitError{Cmd: orig, Status: 1, Stderr: "Error response from daemon: No such container: " + mm[1]}, true
		}
		out := m.containerProbe(mm[1])
		if m.Truncate[mm[1]] {
			out = strings.SplitN(out, "\n", 2)[0] + "\n"
		}
		return out, nil, true
	}
	if reDiagH.MatchString(cmd) {
		if m.HostFail != nil {
			return "", m.HostFail, true
		}
		return m.hostProbe(sudo), nil, true
	}
	if m.FailFix != "" && strings.Contains(cmd, m.FailFix) && (reAADisable.MatchString(cmd) || reAAParser.MatchString(cmd) || reIPTLink.MatchString(cmd) || reDiagRestart.MatchString(cmd)) {
		return "", &ExitError{Cmd: orig, Status: 1, Stderr: "fakesrv: имитированный отказ"}, true
	}
	if reAADisable.MatchString(cmd) {
		m.disabled["wg-quick"], m.disabled["wg"] = true, true
		return "", nil, true
	}
	if mm := reAAParser.FindStringSubmatch(cmd); mm != nil {
		for _, p := range strings.Fields(mm[1]) {
			name := strings.TrimPrefix(p, "/etc/apparmor.d/")
			idx := -1
			for i, l := range m.Profiles {
				if l == name {
					idx = i
				}
			}
			if idx < 0 {
				return "", &ExitError{Cmd: orig, Status: 1, Stderr: "apparmor_parser: Unable to remove \"" + name + "\".  Profile doesn't exist"}, true
			}
			if !m.IgnoreParser {
				m.Profiles = append(m.Profiles[:idx], m.Profiles[idx+1:]...)
			}
		}
		return "", nil, true
	}
	if mm := reIPTLink.FindStringSubmatch(cmd); mm != nil {
		if !s.hasName(mm[1]) {
			return "", &ExitError{Cmd: orig, Status: 1, Stderr: "Error: No such container: " + mm[1]}, true
		}
		if !m.NoNFT[mm[1]] {
			m.linked[mm[1]] = true
		}
		return "", nil, true
	}
	if mm := reDiagRestart.FindStringSubmatch(cmd); mm != nil {
		for _, n := range strings.Fields(mm[1]) {
			if !s.hasName(n) {
				return "", &ExitError{Cmd: orig, Status: 1, Stderr: "Error: No such container: " + n}, true
			}
			m.start(n)
		}
		return strings.ReplaceAll(strings.TrimSpace(mm[1]), " ", "\n"), nil, true
	}
	return "", nil, false
}

func (s *Server) hasName(n string) bool {
	for _, x := range s.Names {
		if x == n {
			return true
		}
	}
	return false
}

func (m *DiagModel) containerProbe(n string) string {
	var b strings.Builder
	switch {
	case m.NoIP[n]:
		b.WriteString("IFACE=unknown\n")
	case m.ifaceUp[n]:
		b.WriteString("IFACE=yes\n")
	default:
		b.WriteString("IFACE=no\n")
	}
	switch {
	case m.Legacy[n] && !m.linked[n] && !m.LegacyNoMasq[n]:
		b.WriteString("IPTV=iptables v1.8.7 (legacy)\nNATRC=3\nNOTABLE=yes\nNATERR=iptables v1.8.7 (legacy): can't initialize iptables table `nat': Table does not exist (do you need to insmod?)\n")
	case m.LegacyNoMasq[n] && !m.linked[n]:
		b.WriteString("IPTV=iptables v1.8.7 (legacy)\nNATRC=0\nNATERR=-P POSTROUTING ACCEPT\n")
	default:
		b.WriteString("IPTV=iptables v1.8.7 (nf_tables)\nNATRC=0\n")
		if m.masq[n] {
			b.WriteString("MASQ=yes\nNATERR=-A POSTROUTING -s 10.8.1.0/24 -o eth0 -j MASQUERADE\n")
		} else {
			b.WriteString("NATERR=-P POSTROUTING ACCEPT\n")
		}
	}
	if m.NoNFT[n] {
		b.WriteString("NFT=no\n")
	} else {
		b.WriteString("NFT=yes\n")
	}
	b.WriteString("END\n")
	return b.String()
}

func (m *DiagModel) hostProbe(sudo bool) string {
	var b strings.Builder
	root := !m.NeedSudo || sudo
	if m.NoAppArmor {
		b.WriteString("AA=none\n")
	} else {
		b.WriteString("AA=yes\n")
		if m.ProfUnreadable || !root || (m.ProfNeedSudo && !sudo) {
			b.WriteString("PROF=unreadable\n")
		} else {
			b.WriteString("PROF=readable\n")
			for _, p := range append(append([]string(nil), m.Profiles...), m.FakeLoaded...) {
				b.WriteString("LOADED=" + p + "\n")
			}
		}
	}
	if m.LogUnreadable || !root {
		b.WriteString("LOG=unreadable\n")
	} else {
		b.WriteString("LOG=readable\n")
		for _, d := range m.denied {
			b.WriteString("DENIED=" + d + "\n")
		}
	}
	b.WriteString("END\n")
	return b.String()
}
