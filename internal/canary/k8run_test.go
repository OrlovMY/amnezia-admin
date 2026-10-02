package canary

import (
	"strings"
	"testing"
)

// TestK8DeleteLeftKey — К8.6: ключ после удаления остался в awg show —
// НЕ ПРОЙДЕН. Работающий сервер подменён: во втором ответе dump (К8.6)
// дописаны peer'ы, которые работали во время вопросов К8.5 (после
// перевыпуска, до удаления).
func TestK8DeleteLeftKey(t *testing.T) {
	f := emptyFakeOn(t, awg2Server(k8AWG3), awg2Ctr(), false)
	f.env.NewBin = newCLI(t)
	var live []string
	f.env.AskIP = func(q string) string {
		if strings.HasPrefix(q, "К8.5") {
			live = f.exec.RuntimePeers()
		}
		return f.env.Sess.Creds.Host
	}
	orig := f.env.Remote
	n := 0
	f.env.Remote = func(cmd string) (string, error) {
		out, err := orig(cmd)
		if strings.HasSuffix(cmd, " awg show awg0 dump") {
			n++
			if n == 2 {
				for _, k := range live {
					if !strings.Contains(out, k) {
						out = strings.TrimRight(out, "\n") + "\n" + k + "\tpsk\t(none)\t10.8.1.2/32\t0\t0\t0\toff\n"
					}
				}
			}
		}
		return out, err
	}
	rs := f.env.k8()
	if rs[5].Status != Fail || !strings.Contains(rs[5].Detail, "остался") {
		t.Errorf("К8.6 при оставшемся ключе: %s — %s", rs[5].Status, rs[5].Detail)
	}
}

// TestRunIncludesK8 — К8 входит в Run: на amnezia-awg — одна строка
// «НЕ ПРИМЕНИМО», на amnezia-awg2 — восемь шагов (на fakesrv предусловия
// К2 не подтверждаются — НЕ ПРОВЕРЕНО).
func TestRunIncludesK8(t *testing.T) {
	ids := func(rs []Result) map[string]Status {
		m := map[string]Status{}
		for _, r := range rs {
			m[r.ID] = r.Status
		}
		return m
	}
	f := emptyFake(t, false)
	f.env.NewBin = newCLI(t)
	f.env.RaceRounds = 2
	rs, err := Run(f.env)
	if err != nil {
		t.Fatal(err)
	}
	if st, ok := ids(rs)["К8"]; !ok || st != NotApplicable {
		t.Errorf("К8 на amnezia-awg: %v (есть %v)", st, ok)
	}
	f2 := emptyFakeOn(t, awg2Server(k8AWG3), awg2Ctr(), false)
	f2.env.NewBin = newCLI(t)
	f2.env.RaceRounds = 2
	rs2, err := Run(f2.env)
	if err != nil {
		t.Fatal(err)
	}
	m := ids(rs2)
	for _, s := range k8IDs {
		if st, ok := m[s.id]; !ok || st != NotChecked {
			t.Errorf("%s на amnezia-awg2: %v (есть %v)", s.id, st, ok)
		}
	}
}
