package core_test

// Диагностика AppArmor/iptables (core/hostdiag.go). Три вида тестов:
//   - различения (табличные, через боевой путь Diagnose на fakesrv): «не
//     удалось узнать» ≠ «нет» в каждом месте, где данных может не быть;
//   - доезда: Diagnose → Plan → ApplyFix → повторная проверка на модели
//     сервера, которая меняет состояние от команд исправления;
//   - настоящей оболочки: пробы исполняются sh с подменёнными ip/iptables/
//     dmesg — разбор проверяется на выводе настоящего скрипта, а не модели.

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"amnezia-admin/core"
	"amnezia-admin/internal/fakesrv"
)

func diagSrv(t *testing.T, user string, names []string, m *fakesrv.DiagModel) (*core.Session, *fakesrv.Server, []core.Container) {
	t.Helper()
	t.Cleanup(core.SetDiagWaits(0, 2))
	srv := fakesrv.New()
	srv.Names = names
	srv.Diag = m
	sess := core.NewSessionWithRunner(srv, &core.ServerCreds{Host: "203.0.113.10", User: user, Password: "x"})
	cs, err := sess.FindContainers()
	if err != nil {
		t.Fatal(err)
	}
	return sess, srv, cs
}

func diagOf(t *testing.T, rep core.DiagReport, name string) core.ContainerDiag {
	t.Helper()
	for _, c := range rep.Containers {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("контейнера %s нет в отчёте: %+v", name, rep)
	return core.ContainerDiag{}
}

// TestDiagTagsMatchFakesrv — метки проб в модели и в ядре совпадают: иначе
// модель молча перестала бы отвечать на пробы и все тесты доезда видели бы
// «не удалось узнать».
func TestDiagTagsMatchFakesrv(t *testing.T) {
	if core.DiagContainerTag != fakesrv.DiagContainerTag || core.DiagHostTag != fakesrv.DiagHostTag {
		t.Fatal("метки проб core и fakesrv разошлись")
	}
}

// TestDiagnoseThreeStates — таблица исходов боевым путём. Случаи «данных
// нет» (журнал не читается, проба упала, нет утилиты ip) обязаны дать
// DiagUnknown — НЕ DiagNo, и в план исправления не попасть.
func TestDiagnoseThreeStates(t *testing.T) {
	all := []string{"amnezia-awg", "amnezia-wireguard", "amnezia-awg2"}
	cases := []struct {
		name    string
		user    string
		m       *fakesrv.DiagModel
		aa, ipt map[string]core.DiagState
		planAA  []string
		planIPT []string
	}{
		{"исправный сервер", "root", nil,
			map[string]core.DiagState{"amnezia-awg": core.DiagNo, "amnezia-wireguard": core.DiagNo, "amnezia-awg2": core.DiagNo},
			map[string]core.DiagState{"amnezia-awg": core.DiagNo, "amnezia-wireguard": core.DiagNo, "amnezia-awg2": core.DiagNo}, nil, nil},
		{"AppArmor мешает wg-quick", "root", &fakesrv.DiagModel{Profiles: []string{"wg", "wg-quick"}},
			map[string]core.DiagState{"amnezia-awg": core.DiagYes, "amnezia-wireguard": core.DiagYes, "amnezia-awg2": core.DiagNo},
			map[string]core.DiagState{"amnezia-awg": core.DiagNo}, []string{"amnezia-awg", "amnezia-wireguard"}, nil},
		{"AppArmor: журнал и профили не читаются — НЕ «нет»", "root", &fakesrv.DiagModel{Profiles: []string{"wg-quick"}, LogUnreadable: true, ProfUnreadable: true},
			map[string]core.DiagState{"amnezia-awg": core.DiagUnknown, "amnezia-wireguard": core.DiagUnknown, "amnezia-awg2": core.DiagNo},
			nil, nil, nil},
		{"AppArmor: только журнал не читается, профиль загружен — НЕ «нет»", "root", &fakesrv.DiagModel{Profiles: []string{"wg-quick"}, LogUnreadable: true},
			map[string]core.DiagState{"amnezia-awg": core.DiagUnknown}, nil, nil, nil},
		{"AppArmor: проба хоста упала — НЕ «нет»", "root", &fakesrv.DiagModel{Profiles: []string{"wg-quick"}, HostFail: errors.New("сеть")},
			map[string]core.DiagState{"amnezia-awg": core.DiagUnknown, "amnezia-awg2": core.DiagNo}, nil, nil, nil},
		{"не root: журнал читается через sudo -n", "admin", &fakesrv.DiagModel{Profiles: []string{"wg-quick"}, NeedSudo: true},
			map[string]core.DiagState{"amnezia-awg": core.DiagYes}, nil, []string{"amnezia-awg", "amnezia-wireguard"}, nil},
		{"AppArmor на хосте нет", "root", &fakesrv.DiagModel{NoAppArmor: true},
			map[string]core.DiagState{"amnezia-awg": core.DiagNo}, nil, nil, nil},
		{"проба контейнера упала — оба исхода «не удалось»", "root", &fakesrv.DiagModel{ProbeFail: map[string]error{"amnezia-wireguard": errors.New("docker exec: отказ")}},
			map[string]core.DiagState{"amnezia-wireguard": core.DiagUnknown, "amnezia-awg": core.DiagNo},
			map[string]core.DiagState{"amnezia-wireguard": core.DiagUnknown, "amnezia-awg": core.DiagNo}, nil, nil},
		{"вывод пробы оборван до END — «не удалось», хоть IFACE=yes и успел", "root", &fakesrv.DiagModel{Truncate: map[string]bool{"amnezia-awg": true}},
			map[string]core.DiagState{"amnezia-awg": core.DiagUnknown, "amnezia-wireguard": core.DiagNo},
			map[string]core.DiagState{"amnezia-awg": core.DiagUnknown}, nil, nil},
		{"нет утилиты ip — интерфейс не проверить", "root", &fakesrv.DiagModel{NoIP: map[string]bool{"amnezia-awg": true}},
			map[string]core.DiagState{"amnezia-awg": core.DiagUnknown}, nil, nil, nil},
		{"iptables legacy без nat", "root", &fakesrv.DiagModel{Legacy: map[string]bool{"amnezia-awg": true, "amnezia-wireguard": true}},
			nil, map[string]core.DiagState{"amnezia-awg": core.DiagYes, "amnezia-wireguard": core.DiagYes, "amnezia-awg2": core.DiagNo}, nil, []string{"amnezia-awg", "amnezia-wireguard"}},
		{"iptables legacy, но xtables-nft-multi нет — проблема есть, исправления нет", "root", &fakesrv.DiagModel{Legacy: map[string]bool{"amnezia-awg": true}, NoNFT: map[string]bool{"amnezia-awg": true}},
			nil, map[string]core.DiagState{"amnezia-awg": core.DiagYes}, nil, nil},
		{"legacy с nat без MASQUERADE — причина другая, «не удалось»", "root", &fakesrv.DiagModel{LegacyNoMasq: map[string]bool{"amnezia-awg": true}},
			nil, map[string]core.DiagState{"amnezia-awg": core.DiagUnknown}, nil, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sess, _, cs := diagSrv(t, tc.user, all, tc.m)
			rep := sess.Diagnose(cs)
			if len(rep.Containers) != 3 {
				t.Fatalf("проверено %d контейнеров, ожидалось 3", len(rep.Containers))
			}
			for n, want := range tc.aa {
				if got := diagOf(t, rep, n).AppArmor; got.State != want {
					t.Errorf("%s AppArmor: %v (%s), ожидалось %v", n, got.State, got.Reason, want)
				}
			}
			for n, want := range tc.ipt {
				if got := diagOf(t, rep, n).IPTables; got.State != want {
					t.Errorf("%s iptables: %v (%s), ожидалось %v", n, got.State, got.Reason, want)
				}
			}
			if tc.m != nil && tc.m.HostFail != nil && !strings.Contains(diagOf(t, rep, "amnezia-awg").AppArmor.Reason, tc.m.HostFail.Error()) {
				t.Errorf("причина не называет отказ пробы хоста: %q", diagOf(t, rep, "amnezia-awg").AppArmor.Reason)
			}
			for _, c := range rep.Containers {
				for _, f := range []core.DiagFinding{c.AppArmor, c.IPTables} {
					if f.Reason == "" {
						t.Errorf("%s: исход %v без причины", c.Name, f.State)
					}
				}
			}
			p := rep.Plan(tc.user)
			if !reflect.DeepEqual(p.AppArmor, tc.planAA) || !reflect.DeepEqual(p.IPTables, tc.planIPT) {
				t.Errorf("план AppArmor=%v iptables=%v, ожидалось %v / %v", p.AppArmor, p.IPTables, tc.planAA, tc.planIPT)
			}
		})
	}
}

// TestDiagSkipsNonWG — XRay и прочие не проверяются; нечего проверять —
// пустой отчёт, без ложной «проблемы» и без «не удалось».
func TestDiagSkipsNonWG(t *testing.T) {
	sess, srv, cs := diagSrv(t, "root", []string{"amnezia-xray", "amnezia-openvpn"}, &fakesrv.DiagModel{Profiles: []string{"wg-quick"}})
	rep := sess.Diagnose(cs)
	if len(rep.Containers) != 0 || rep.HasProblem() || rep.HasUnknown() {
		t.Fatalf("%+v", rep)
	}
	for _, c := range srv.Commands() {
		if strings.Contains(c, "aa-diag") {
			t.Errorf("проба запущена: %.80q", c)
		}
	}
}

// TestFixRunsExactlyCopiedCommands — «Исправить» исполняет РОВНО те строки,
// что человек копирует (FixCommandsText), в том же порядке, — и итог по
// повторной проверке «исправлено».
func TestFixRunsExactlyCopiedCommands(t *testing.T) {
	for _, user := range []string{"root", "admin"} {
		t.Run(user, func(t *testing.T) {
			m := &fakesrv.DiagModel{Profiles: []string{"wg", "wg-quick"}, NeedSudo: user != "root", Legacy: map[string]bool{"amnezia-awg": true}}
			sess, srv, cs := diagSrv(t, user, []string{"amnezia-awg", "amnezia-wireguard", "amnezia-awg2"}, m)
			rep := sess.Diagnose(cs)
			plan := rep.Plan(user)
			copied := strings.Split(strings.TrimRight(core.FixCommandsText(plan), "\n"), "\n")
			before := len(srv.Commands())
			res, err := sess.ApplyFix(plan, cs)
			if err != nil {
				t.Fatal(err)
			}
			var ran []string
			for _, c := range srv.Commands()[before:] {
				if !strings.Contains(c, "aa-diag") {
					ran = append(ran, c)
				}
			}
			if !reflect.DeepEqual(ran, copied) || !reflect.DeepEqual(res.Ran, copied) {
				t.Fatalf("исполнено не то, что скопировано:\nисполнено %q\nскопировано %q", ran, copied)
			}
			if len(copied) < 4 {
				t.Fatalf("тест перестал что-либо проверять: %q", copied)
			}
			for _, c := range copied {
				if (user == "root") == strings.HasPrefix(c, "sudo ") {
					t.Errorf("sudo у %s: %q", user, c)
				}
			}
			if res.RunErr != nil || len(res.Outcomes) != 3 {
				t.Fatalf("%v %+v", res.RunErr, res.Outcomes)
			}
			for _, o := range res.Outcomes {
				if o.After.State != core.DiagNo || !strings.HasSuffix(o.Text(), "исправлено") {
					t.Errorf("%s", o.Text())
				}
			}
		})
	}
}

// TestFixOutcomeThreeStates — итог честный: «не исправлено», если
// повторная проверка видит проблему; «неизвестно», если повторная проверка
// не удалась; «исправлено» — только по DiagNo.
func TestFixOutcomeThreeStates(t *testing.T) {
	t.Run("не подействовало", func(t *testing.T) {
		m := &fakesrv.DiagModel{Profiles: []string{"wg-quick"}, IgnoreParser: true}
		sess, _, cs := diagSrv(t, "root", []string{"amnezia-awg"}, m)
		res, err := sess.ApplyFix(sess.Diagnose(cs).Plan("root"), cs)
		if err != nil || len(res.Outcomes) != 1 || res.Outcomes[0].After.State != core.DiagYes || !strings.Contains(res.Outcomes[0].Text(), "НЕ исправлено") {
			t.Fatalf("%v %+v", err, res.Outcomes)
		}
	})
	t.Run("повторная проверка не удалась", func(t *testing.T) {
		m := &fakesrv.DiagModel{Profiles: []string{"wg-quick"}}
		sess, srv, cs := diagSrv(t, "root", []string{"amnezia-awg"}, m)
		plan := sess.Diagnose(cs).Plan("root")
		srv.Configure(func(s *fakesrv.Server) { s.Diag.ProbeFail = map[string]error{"amnezia-awg": errors.New("обрыв")} })
		res, err := sess.ApplyFix(plan, cs)
		if err != nil || len(res.Outcomes) != 1 || res.Outcomes[0].After.State != core.DiagUnknown || !strings.Contains(res.Outcomes[0].Text(), "неизвестно") {
			t.Fatalf("%v %+v", err, res.Outcomes)
		}
	})
	t.Run("команда упала — остальные не выполняются", func(t *testing.T) {
		m := &fakesrv.DiagModel{Profiles: []string{"wg-quick"}, FailFix: "apparmor_parser"}
		sess, srv, cs := diagSrv(t, "root", []string{"amnezia-awg"}, m)
		res, _ := sess.ApplyFix(sess.Diagnose(cs).Plan("root"), cs)
		if res.RunErr == nil || res.Outcomes[0].After.State == core.DiagNo {
			t.Fatalf("%v %+v", res.RunErr, res.Outcomes)
		}
		for _, c := range srv.Commands() {
			if strings.HasPrefix(c, "docker restart") {
				t.Errorf("после упавшей команды выполнено %q", c)
			}
		}
	})
	t.Run("пустой план — отказ", func(t *testing.T) {
		sess, _, cs := diagSrv(t, "root", []string{"amnezia-awg"}, nil)
		if _, err := sess.ApplyFix(core.FixPlan{User: "root"}, cs); !errors.Is(err, core.ErrNothingToFix) {
			t.Fatal(err)
		}
	})
}

// TestFixConsequencesNamed — текст последствий называет все три вещи
// задания: защита снимается на всём сервере; перезапуск рвёт подключения;
// исправление iptables пропадёт при пересоздании контейнера.
func TestFixConsequencesNamed(t *testing.T) {
	p := core.FixPlan{AppArmor: []string{"amnezia-awg"}, IPTables: []string{"amnezia-awg"}, Profiles: []string{"wg-quick"}, User: "root"}
	all := strings.Join(p.Consequences(), "\n")
	for _, want := range []string{"ВСЁМ сервере", "оборвутся", "пересоздании контейнера", "amnezia-awg"} {
		if !strings.Contains(all, want) {
			t.Errorf("нет %q в:\n%s", want, all)
		}
	}
}

// ---------- настоящая оболочка ----------

func writeExe(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/sh\n"+body), 0o700); err != nil {
		t.Fatal(err)
	}
}

func runSh(t *testing.T, shim, script string) string {
	t.Helper()
	sh, err := fakesrv.FindSh()
	if err != nil {
		t.Fatal(err)
	}
	full := `PATH="$(cd "` + filepath.ToSlash(shim) + `" && pwd):$PATH"; ` + script
	out, err := exec.Command(sh, "-c", full).CombinedOutput()
	if err != nil {
		t.Fatalf("sh: %v\n%s", err, out)
	}
	return string(out)
}

// TestDiagProbesRealShell — пробы исполняются настоящим sh: разбор
// проверен на выводе НАСТОЯЩЕГО скрипта (кавычки, $?, grep), а не модели.
func TestDiagProbesRealShell(t *testing.T) {
	t.Run("контейнер: legacy без nat, интерфейса нет, nft есть", func(t *testing.T) {
		shim, sbin := t.TempDir(), t.TempDir()
		writeExe(t, shim, "ip", "exit 1\n")
		writeExe(t, shim, "iptables", `case "$1" in -V) echo "iptables v1.8.7 (legacy)";; *) echo "iptables v1.8.7 (legacy): can not initialize iptables table nat: Table does not exist (do you need to insmod?)" >&2; echo "Perhaps iptables or your kernel needs to be upgraded." >&2; exit 3;; esac`+"\n")
		writeExe(t, sbin, "xtables-nft-multi", "exit 0\n")
		out := runSh(t, shim, core.DiagContainerScriptForTest("wg0", filepath.ToSlash(sbin)))
		c := core.ParseProbeForTest(out)
		if got := core.ClassifyIPTablesForTest(c); got.State != core.DiagYes {
			t.Errorf("iptables: %v %s\n%s", got.State, got.Reason, out)
		}
		if !strings.Contains(core.ProbeGetForTest(c, "NATERR"), "Table does not exist") {
			t.Errorf("причина — не первая строка ошибки (вживую последняя строка — «Perhaps…»): %q", core.ProbeGetForTest(c, "NATERR"))
		}
		if core.ProbeGetForTest(c, "IFACE") != "no" || core.ProbeGetForTest(c, "NFT") != "yes" {
			t.Errorf("вывод:\n%s", out)
		}
	})
	t.Run("контейнер: nf_tables с MASQUERADE, интерфейс есть, nft нет", func(t *testing.T) {
		shim, sbin := t.TempDir(), t.TempDir()
		writeExe(t, shim, "ip", "exit 0\n")
		writeExe(t, shim, "iptables", `case "$1" in -V) echo "iptables v1.8.10 (nf_tables)";; *) echo "-P POSTROUTING ACCEPT"; echo "-A POSTROUTING -s 10.8.1.0/24 -o eth0 -j MASQUERADE";; esac`+"\n")
		out := runSh(t, shim, core.DiagContainerScriptForTest("wg0", filepath.ToSlash(sbin)))
		c := core.ParseProbeForTest(out)
		if got := core.ClassifyIPTablesForTest(c); got.State != core.DiagNo {
			t.Errorf("iptables: %v %s\n%s", got.State, got.Reason, out)
		}
		if core.ProbeGetForTest(c, "IFACE") != "yes" || core.ProbeGetForTest(c, "NFT") != "no" {
			t.Errorf("вывод:\n%s", out)
		}
	})
	t.Run("хост: профили и отказы", func(t *testing.T) {
		shim, mod := t.TempDir(), t.TempDir()
		prof := filepath.Join(t.TempDir(), "profiles")
		if err := os.WriteFile(prof, []byte("wg-quick (enforce)\nwg (enforce)\nwgx (enforce)\nfoo (complain)\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		writeExe(t, shim, "dmesg", `echo '[ 12.1] audit: type=1400 apparmor="DENIED" operation="exec" class="file" profile="wg-quick" name="/usr/bin/readlink"'
echo '[ 12.2] audit: type=1400 apparmor="DENIED" operation="connect" profile="wg" name="/run/wireguard/wg0.sock"'
echo '[ 12.3] audit: type=1400 apparmor="ALLOWED" profile="wg-other"'
`)
		out := runSh(t, shim, core.DiagHostScriptForTest(filepath.ToSlash(mod), filepath.ToSlash(prof)))
		h := core.ParseProbeForTest(out)
		if got := core.ProbeAllForTest(h, "DENIED"); !reflect.DeepEqual(got, []string{"wg", "wg-quick"}) {
			t.Errorf("DENIED %q\n%s", got, out)
		}
		if got := core.ProbeAllForTest(h, "LOADED"); !reflect.DeepEqual(got, []string{"wg-quick", "wg"}) {
			t.Errorf("LOADED %q\n%s", got, out)
		}
	})
	t.Run("хост: журнал не читается", func(t *testing.T) {
		shim := t.TempDir()
		writeExe(t, shim, "dmesg", "echo 'dmesg: read kernel buffer failed: Operation not permitted' >&2; exit 1\n")
		writeExe(t, shim, "journalctl", "exit 1\n")
		out := runSh(t, shim, core.DiagHostScriptForTest("/nonexistent-aa", "/nonexistent"))
		h := core.ParseProbeForTest(out)
		if core.ProbeGetForTest(h, "LOG") != "unreadable" || core.ProbeGetForTest(h, "AA") != "none" {
			t.Errorf("вывод:\n%s", out)
		}
	})
}
