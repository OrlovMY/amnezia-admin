package canary

// PR-W3: К8 на amnezia-awg2 против fakesrv — через собранную программу и SSH.

import (
	"strings"
	"testing"

	"amnezia-admin/core"
	"amnezia-admin/internal/fakesrv"
)

func awg2Ctr() *core.Container {
	return &core.Container{Name: "amnezia-awg2", Dir: "/opt/amnezia/awg", Proto: "AmneziaWG 2", Managed: true}
}

// awg2Server — fakesrv amnezia-awg2 с [Interface] после ListenPort = extra.
func awg2Server(extra string) *fakesrv.Server {
	fs := fakesrv.NewAWG2()
	b, _ := fs.File("/opt/amnezia/awg/awg0.conf")
	s := string(b)
	i := strings.Index(s, "ListenPort = 51820\n") + len("ListenPort = 51820\n")
	j := strings.Index(s, "[Peer]")
	fs.SetFile("/opt/amnezia/awg/awg0.conf", []byte(s[:i]+extra+"\n"+s[j:]))
	return fs
}

const k8AWG3 = "Jc = 4\nS3 = 15\nH1 = 100-200\nHeaderProtectionKey = hpk\nRandomTrailers = on\n# I1 = <b 0x01>\n"

// TestK8OnFakesrv — шаги по серверу (К8.1, К8.2, К8.6, К8.8) ПРОЙДЕН;
// шаги на устройствах — по ответу человека: да → ПРОЙДЕН, нет → НЕ ПРОЙДЕН,
// пропуск → НЕ ПРОВЕРЕНО. Вариант AWG назван.
func TestK8OnFakesrv(t *testing.T) {
	for _, c := range []struct {
		ans  Answer
		want Status
	}{{AnswerYes, Pass}, {AnswerNo, Fail}, {AnswerSkip, NotChecked}} {
		t.Run(c.ans.String(), func(t *testing.T) {
			f := emptyFakeOn(t, awg2Server(k8AWG3), awg2Ctr(), false)
			f.env.NewBin = newCLI(t)
			f.env.Ask = func(string) Answer { return c.ans }
			rs := f.env.k8()
			if len(rs) != 8 {
				t.Fatalf("шагов К8 %d, ждали ровно 8", len(rs))
			}
			for i, r := range rs {
				want := c.want
				if i == 0 || i == 1 || i == 5 || i == 7 {
					want = Pass
				}
				if r.Status != want {
					t.Errorf("%s %s: %s (%s), ждали %s", r.ID, r.Name, r.Status, r.Detail, want)
				}
			}
			if !strings.Contains(rs[0].Detail, "AmneziaWG (версия 3.1)") || !strings.Contains(rs[0].Detail, "проверено на AWG3; AWG2 — только на тестовом стенде") {
				t.Errorf("К8.1 не называет вариант: %s", rs[0].Detail)
			}
			if strings.Contains(rs[0].Detail, "hpk") || strings.Contains(rs[0].Detail, "PrivateKey =") {
				t.Errorf("К8.1 напечатал значения параметров: %s", rs[0].Detail)
			}
		})
	}
}

// TestK8StopsOnUnknownKey — К8.1: незнакомый параметр — НЕ ПРОЙДЕН и СТОП:
// остальные шаги НЕ ПРОВЕРЕНО, ни одной записи на сервер.
func TestK8StopsOnUnknownKey(t *testing.T) {
	f := emptyFakeOn(t, awg2Server("S3 = 15\nPostUp = echo x\n"), awg2Ctr(), false)
	f.env.NewBin = newCLI(t)
	f.env.Ask = func(string) Answer { return AnswerYes }
	rs := f.env.k8()
	if rs[0].Status != Fail || !strings.Contains(rs[0].Detail, "PostUp") {
		t.Fatalf("К8.1: %s — %s", rs[0].Status, rs[0].Detail)
	}
	for _, r := range rs[1:] {
		if r.Status != NotChecked {
			t.Errorf("%s после СТОП: %s", r.ID, r.Status)
		}
	}
	for _, cmd := range f.exec.Commands() {
		if strings.Contains(cmd, "flock -w") {
			t.Fatalf("запись после СТОП К8.1: %.80s", cmd)
		}
	}
}

// TestK8StopsOnMissingFile — awg0.conf нет — К8.1 НЕ ПРОВЕРЕНО (не «нет
// параметров»), остальные НЕ ПРОВЕРЕНО.
func TestK8StopsOnMissingFile(t *testing.T) {
	f := emptyFakeOn(t, awg2Server(""), awg2Ctr(), false)
	f.exec.DeleteFile("/opt/amnezia/awg/awg0.conf")
	f.env.NewBin = newCLI(t)
	rs := f.env.k8()
	for _, r := range rs {
		if r.Status != NotChecked {
			t.Errorf("%s: %s (%s), ждали НЕ ПРОВЕРЕНО", r.ID, r.Status, r.Detail)
		}
	}
}

// TestK8Rows — К8 в Run: не amnezia-awg2 — одна строка НЕ ПРИМЕНИМО;
// предусловия не подтверждены — восемь НЕ ПРОВЕРЕНО.
func TestK8Rows(t *testing.T) {
	awg := &core.Container{Name: "amnezia-awg", Dir: "/opt/amnezia/awg"}
	fam, _ := core.WGFamilyOf(awg)
	e := &Env{Ctr: awg, fam: fam}
	if rs := e.k8Rows(true); len(rs) != 1 || rs[0].Status != NotApplicable {
		t.Errorf("К8 на amnezia-awg: %+v", rs)
	}
	c2 := awg2Ctr()
	fam2, _ := core.WGFamilyOf(c2)
	e2 := &Env{Ctr: c2, fam: fam2}
	rs := e2.k8Rows(false)
	if len(rs) != 8 {
		t.Fatalf("строк К8 без предусловий %d, ждали ровно 8", len(rs))
	}
	for _, r := range rs {
		if r.Status != NotChecked {
			t.Errorf("%s без предусловий: %s", r.ID, r.Status)
		}
	}
}

// TestAWGVariantLine — итог называет проверенный вживую вариант.
func TestAWGVariantLine(t *testing.T) {
	for v, want := range map[string]string{
		"3.1": "проверено на AWG3; AWG2 — только на тестовом стенде",
		"2":   "проверено на AWG2; AWG3 — только на тестовом стенде",
		"":    "версия не определена",
	} {
		if got := AWGVariantLine(v, true); !strings.Contains(got, want) {
			t.Errorf("%q: %q", v, got)
		}
	}
	if AWGVariantLine("3.1", false) != "" {
		t.Error("формат не определён — вариант не называется")
	}
}
