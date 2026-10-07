package core_test

// Круг 2 ревью PR #44 (QA-01 Б1/З1, SEC-01 З1/З3).

import (
	"reflect"
	"strings"
	"testing"

	"amnezia-admin/core"
	"amnezia-admin/internal/fakesrv"
)

// TestDiagStaleDeniedNotYes — Б1 (QA-01, признак 3): сервер уже исправлен
// (профили сняты), в журнале остались прежние отказы, а wg0 нет по другой
// причине — исход «нет», не «есть»; исправление не предлагается.
func TestDiagStaleDeniedNotYes(t *testing.T) {
	m := &fakesrv.DiagModel{StaleDenied: []string{"wg-quick", "wg"}, IfaceDown: map[string]bool{"amnezia-awg": true}}
	sess, _, cs := diagSrv(t, "root", []string{"amnezia-awg"}, m)
	rep := sess.Diagnose(cs)
	if got := diagOf(t, rep, "amnezia-awg").AppArmor; got.State != core.DiagNo {
		t.Fatalf("старый отказ дал %v (%s)", got.State, got.Reason)
	}
	if !rep.Plan("root").Empty() {
		t.Fatal("предложено исправление, которое ничего не изменит")
	}
}

// TestDiagProfilesNeedSudo — З1 (QA-01): журнал читается без sudo, список
// профилей — только через sudo -n. Повтор обязан состояться: иначе план не
// знает, какие профили загружены, apparmor_parser -R получает оба и падает
// на незагруженном.
func TestDiagProfilesNeedSudo(t *testing.T) {
	m := &fakesrv.DiagModel{Profiles: []string{"wg-quick"}, ProfNeedSudo: true}
	sess, _, cs := diagSrv(t, "admin", []string{"amnezia-awg"}, m)
	plan := sess.Diagnose(cs).Plan("admin")
	if !reflect.DeepEqual(plan.Profiles, []string{"wg-quick"}) {
		t.Fatalf("профили плана %q, ожидалось [wg-quick]", plan.Profiles)
	}
	res, err := sess.ApplyFix(plan, cs)
	if err != nil || res.RunErr != nil || len(res.Outcomes) != 1 || res.Outcomes[0].After.State != core.DiagNo {
		t.Fatalf("%v %v %+v", err, res.RunErr, res.Outcomes)
	}
}

// TestDiagLoadedClosedList — SEC-01 З1: имена профилей из вывода сервера
// попадают в apparmor_parser -R только из закрытого списка {wg-quick, wg}.
func TestDiagLoadedClosedList(t *testing.T) {
	m := &fakesrv.DiagModel{Profiles: []string{"wg-quick"}, FakeLoaded: []string{"wg-quick; reboot", "evil", "/etc/passwd"}}
	sess, _, cs := diagSrv(t, "root", []string{"amnezia-awg"}, m)
	plan := sess.Diagnose(cs).Plan("root")
	if !reflect.DeepEqual(plan.Profiles, []string{"wg-quick"}) {
		t.Fatalf("профили плана %q", plan.Profiles)
	}
	for _, c := range core.FixCommands(plan) {
		if strings.Contains(c, "reboot") || strings.Contains(c, "evil") || strings.Contains(c, "passwd") {
			t.Fatalf("подсунутое сервером попало в команду: %q", c)
		}
	}
}

// TestFixPartialNamesDoneSteps — SEC-01 З3: прерванное исправление
// называет уже выполненные шаги; упало на первом — «ничего не изменено».
func TestFixPartialNamesDoneSteps(t *testing.T) {
	m := &fakesrv.DiagModel{Profiles: []string{"wg-quick"}, FailFix: "apparmor_parser"}
	sess, _, cs := diagSrv(t, "root", []string{"amnezia-awg"}, m)
	res, _ := sess.ApplyFix(sess.Diagnose(cs).Plan("root"), cs)
	all := strings.Join(res.Partial(), "\n")
	if !strings.Contains(all, "Уже выполнено") || !strings.Contains(all, "  ln -sf /etc/apparmor.d/wg-quick") || strings.Contains(all, "  apparmor_parser") {
		t.Fatalf("%s", all)
	}
	m2 := &fakesrv.DiagModel{Profiles: []string{"wg-quick"}, FailFix: "ln -sf"}
	sess2, _, cs2 := diagSrv(t, "root", []string{"amnezia-awg"}, m2)
	res2, _ := sess2.ApplyFix(sess2.Diagnose(cs2).Plan("root"), cs2)
	if all2 := strings.Join(res2.Partial(), "\n"); !strings.Contains(all2, "ничего не изменено") {
		t.Fatalf("%s", all2)
	}
	sess3, _, cs3 := diagSrv(t, "root", []string{"amnezia-awg"}, &fakesrv.DiagModel{Profiles: []string{"wg-quick"}})
	if res3, _ := sess3.ApplyFix(sess3.Diagnose(cs3).Plan("root"), cs3); res3.Partial() != nil {
		t.Fatalf("без прерывания: %q", res3.Partial())
	}
}
