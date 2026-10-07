package main

// diagnose (AppArmor/iptables, core/hostdiag.go) через ПОЛНЫЙ run() против
// fakesrv.ListenSSH.

import (
	"bytes"
	"strings"
	"testing"

	"amnezia-admin/core"
	"amnezia-admin/internal/fakesrv"
)

func diagRun(t *testing.T, m *fakesrv.DiagModel, args ...string) (code int, out, errOut string, exec *fakesrv.Server, key, kh string) {
	t.Helper()
	t.Cleanup(core.SetDiagWaits(0, 2))
	key, kh, exec = setupFakeSSHForRunWithExec(t)
	exec.Configure(func(s *fakesrv.Server) {
		s.Names = []string{"amnezia-awg", "amnezia-wireguard"}
		s.Diag = m
	})
	var o, e bytes.Buffer
	code = run(append(append([]string{}, args...), "-key", key), strings.NewReader(""), &o, &e, kh)
	return code, stripANSI(o.String()), e.String(), exec, key, kh
}

func fixCmdsRan(exec *fakesrv.Server) []string {
	var out []string
	for _, c := range exec.Commands() {
		if strings.Contains(c, "aa-diag-") {
			continue // проба, не исправление
		}
		if strings.Contains(c, "apparmor") || strings.HasPrefix(c, "docker restart") || strings.Contains(c, "xtables-nft-multi") {
			out = append(out, c)
		}
	}
	return out
}

// TestRunDiagnosePrintsSameCommands — без -fix: ни одной команды
// исправления, а напечатанные команды — ровно FixCommands плана.
func TestRunDiagnosePrintsSameCommands(t *testing.T) {
	m := &fakesrv.DiagModel{Profiles: []string{"wg-quick", "wg"}, Legacy: map[string]bool{"amnezia-awg": true}}
	code, out, _, exec, _, _ := diagRun(t, m, "diagnose")
	if code != 1 {
		t.Fatalf("code=%d", code)
	}
	if ran := fixCmdsRan(exec); len(ran) != 0 {
		t.Fatalf("без -fix выполнено: %q", ran)
	}
	plan := core.FixPlan{AppArmor: []string{"amnezia-awg", "amnezia-wireguard"}, IPTables: []string{"amnezia-awg"}, Profiles: []string{"wg-quick", "wg"}, User: "root"}
	want := core.FixCommands(plan)
	i := strings.Index(out, "Чтобы исправить самостоятельно")
	if i < 0 {
		t.Fatalf("нет инструкции:\n%s", out)
	}
	var got []string
	for _, l := range strings.Split(out[i:], "\n")[1:] {
		if !strings.HasPrefix(l, "  ") {
			break
		}
		got = append(got, strings.TrimPrefix(l, "  "))
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("напечатано:\n%s\nожидалось:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	for _, w := range []string{"ВСЁМ сервере", "оборвутся", "пересоздании контейнера", "diagnose -fix"} {
		if !strings.Contains(out, w) {
			t.Errorf("нет %q", w)
		}
	}
}

// TestRunDiagnoseFixNeedsConfirm — -fix без терминала и без -yes: отказ,
// код 2, ни одной команды исправления.
func TestRunDiagnoseFixNeedsConfirm(t *testing.T) {
	code, _, errOut, exec, _, _ := diagRun(t, &fakesrv.DiagModel{Profiles: []string{"wg-quick"}}, "diagnose", "-fix")
	if code != 2 || !strings.Contains(errOut, "-yes") {
		t.Fatalf("code=%d stderr=%s", code, errOut)
	}
	if ran := fixCmdsRan(exec); len(ran) != 0 {
		t.Fatalf("без подтверждения выполнено: %q", ran)
	}
}

// TestRunDiagnoseFixYes — -fix -yes: исправлено по повторной проверке;
// исполнены ровно напечатанные команды.
func TestRunDiagnoseFixYes(t *testing.T) {
	code, out, errOut, exec, _, _ := diagRun(t, &fakesrv.DiagModel{Profiles: []string{"wg-quick", "wg"}}, "diagnose", "-fix", "-yes")
	if code != 0 {
		t.Fatalf("code=%d stderr=%s\n%s", code, errOut, out)
	}
	if !strings.Contains(out, "AppArmor в amnezia-awg: исправлено") || !strings.Contains(out, "AppArmor в amnezia-wireguard: исправлено") {
		t.Fatalf("%s", out)
	}
	want := core.FixCommands(core.FixPlan{AppArmor: []string{"amnezia-awg", "amnezia-wireguard"}, Profiles: []string{"wg-quick", "wg"}, User: "root"})
	if got := fixCmdsRan(exec); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("выполнено %q, ожидалось %q", got, want)
	}
}

// TestRunDiagnoseUnknownNoFix — «не удалось узнать»: сказано прямо,
// исправление не предлагается и с -fix -yes не выполняется.
func TestRunDiagnoseUnknownNoFix(t *testing.T) {
	m := &fakesrv.DiagModel{Profiles: []string{"wg-quick"}, LogUnreadable: true, ProfUnreadable: true}
	code, out, _, exec, _, _ := diagRun(t, m, "diagnose", "-fix", "-yes")
	if code != 3 {
		t.Fatalf("code=%d", code)
	}
	if !strings.Contains(out, "AppArmor: не удалось узнать") || !strings.Contains(out, "исправление не предлагается") {
		t.Fatalf("%s", out)
	}
	if strings.Contains(out, "Проблем не найдено") || strings.Contains(out, "Чтобы исправить") {
		t.Fatalf("незнание выдано за ответ:\n%s", out)
	}
	if ran := fixCmdsRan(exec); len(ran) != 0 {
		t.Fatalf("при «не удалось узнать» выполнено: %q", ran)
	}
}

// TestRunListDiagNote — list говорит о проблеме и о неудавшейся проверке
// разными строками; на исправном сервере — молчит.
func TestRunListDiagNote(t *testing.T) {
	for _, tc := range []struct {
		name string
		m    *fakesrv.DiagModel
		want string
	}{
		{"проблема", &fakesrv.DiagModel{Profiles: []string{"wg-quick"}}, "найдена проблема окружения"},
		{"не удалось", &fakesrv.DiagModel{Profiles: []string{"wg-quick"}, LogUnreadable: true, ProfUnreadable: true}, "не удалась"},
		{"исправно", nil, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, out, errOut, _, _, _ := diagRun(t, tc.m, "list")
			if code != 0 {
				t.Fatalf("code=%d %s", code, errOut)
			}
			has := strings.Contains(out, "AppArmor/iptables")
			if tc.want == "" && has || tc.want != "" && !strings.Contains(out, tc.want) {
				t.Fatalf("%s", out)
			}
		})
	}
}
