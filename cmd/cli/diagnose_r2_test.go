package main

// Круг 2 ревью PR #44: коды выхода diagnose (QA-01 Б2, З4) и прерванное
// исправление (SEC-01 З3).

import (
	"strings"
	"testing"

	"amnezia-admin/internal/fakesrv"
)

// TestRunDiagnoseExitCodes — договор кодов: 0 нет проблем / всё
// исправлено; 1 найдена без -fix или исправлено не всё; 3 только «не
// удалось узнать». Каждый случай — боевым путём run() на fakesrv.
func TestRunDiagnoseExitCodes(t *testing.T) {
	for _, tc := range []struct {
		name string
		m    *fakesrv.DiagModel
		args []string
		code int
		want string
	}{
		{"исправно", nil, []string{"diagnose"}, 0, "Проблем не найдено"},
		{"проблема без -fix", &fakesrv.DiagModel{Profiles: []string{"wg-quick"}}, []string{"diagnose"}, 1, "diagnose -fix"},
		{"всё исправлено", &fakesrv.DiagModel{Profiles: []string{"wg-quick"}}, []string{"diagnose", "-fix", "-yes"}, 0, ": исправлено"},
		{"не подействовало — НЕ исправлено", &fakesrv.DiagModel{Profiles: []string{"wg-quick"}, IgnoreParser: true}, []string{"diagnose", "-fix", "-yes"}, 1, "НЕ исправлено"},
		{"только не удалось узнать", &fakesrv.DiagModel{Profiles: []string{"wg-quick"}, LogUnreadable: true, ProfUnreadable: true}, []string{"diagnose"}, 3, "не удалось узнать"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, out, errOut, _, _, _ := diagRun(t, tc.m, tc.args...)
			if code != tc.code || !strings.Contains(out, tc.want) {
				t.Fatalf("code=%d (ждали %d), нет %q?\n%s\n%s", code, tc.code, tc.want, out, errOut)
			}
		})
	}
}

// TestRunDiagnosePartialNamed — прерванное исправление: напечатано, какие
// шаги уже выполнены; код 1.
func TestRunDiagnosePartialNamed(t *testing.T) {
	code, out, errOut, _, _, _ := diagRun(t, &fakesrv.DiagModel{Profiles: []string{"wg-quick"}, FailFix: "apparmor_parser"}, "diagnose", "-fix", "-yes")
	errOut = stripANSI(errOut)
	if code != 1 || !strings.Contains(errOut, "Уже выполнено") || !strings.Contains(errOut, "ln -sf /etc/apparmor.d/wg-quick") {
		t.Fatalf("code=%d\n%s\n%s", code, out, errOut)
	}
}
