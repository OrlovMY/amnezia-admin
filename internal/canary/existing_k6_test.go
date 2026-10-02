package canary

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// П0-К6 (живой прогон 03.10): приложение Amnezia в окне К6 переписывает
// clientsTable целиком и дописывает записи администратора allowed_ips.

// appRewrite — как приложение Amnezia: добавляет своего пользователя и
// дописывает записи id поле allowed_ips.
func appRewrite(t *testing.T, f *fakeServer, id string) {
	t.Helper()
	addAppUser(t, f)
	allowedIPs(t, f, id)
}

// allowedIPs — только дописать записи id поле allowed_ips.
func allowedIPs(t *testing.T, f *fakeServer, id string) {
	t.Helper()
	p := f.env.Ctr.Dir + "/clientsTable"
	raw, ok := f.exec.File(p)
	if !ok {
		t.Fatal("clientsTable нет")
	}
	var tbl []map[string]any
	if err := json.Unmarshal(raw, &tbl); err != nil {
		t.Fatal(err)
	}
	hit := false
	for _, r := range tbl {
		if r["clientId"] == id {
			r["userData"].(map[string]any)["allowed_ips"] = "10.8.1.1/32"
			hit = true
		}
	}
	if !hit {
		t.Fatal("записи администратора нет")
	}
	b, _ := json.Marshal(tbl)
	f.exec.SetFile(p, b)
}

func addAppUser(t *testing.T, f *fakeServer) {
	t.Helper()
	if _, err := f.env.Sess.AddUser(f.env.Ctr, "app-user"); err != nil {
		t.Fatal(err)
	}
}

// peerTouch — правка первого блока [Peer] (администратора) в файле
// конфигурации.
func peerTouch(t *testing.T, f *fakeServer) {
	t.Helper()
	p := f.env.Ctr.Dir + "/" + f.env.fam.File
	raw, _ := f.exec.File(p)
	s := strings.Replace(string(raw), "[Peer]\n", "[Peer]\n# тронуто\n", 1)
	if s == string(raw) {
		t.Fatal("[Peer] не найден")
	}
	f.exec.SetFile(p, []byte(s))
}

// TestP0K6Window — правка записи администратора приложением в окне К6 —
// сведение, итог ПРОЙДЕН; та же правка вне окна — НЕ ПРОЙДЕН; [Peer] в
// окне — НЕ ПРОЙДЕН; снимок после К6 не снят — НЕ ПРОВЕРЕНО. Правки и
// обрыв — боевым путём через fakesrv, не присваиванием полей Env.
func TestP0K6Window(t *testing.T) {
	for _, c := range []struct {
		name         string
		inK6, atLock func(t *testing.T, f *fakeServer, id string)
		failAfter    bool
		status       Status
		want         []string
	}{
		{name: "в окне К6 — сведение", inK6: appRewrite, status: Pass,
			want: []string{"сведение", "приложение Amnezia (окно К6)", `allowed_ips: было нет, стало "10.8.1.1/32"`}},
		{name: "вне окна — НЕ ПРОЙДЕН",
			inK6:   func(t *testing.T, f *fakeServer, _ string) { addAppUser(t, f) },
			atLock: allowedIPs, status: Fail,
			want: []string{"изменилась (поля: allowed_ips: было нет"}},
		{name: "[Peer] в окне К6 — НЕ ПРОЙДЕН",
			inK6:   func(t *testing.T, f *fakeServer, id string) { appRewrite(t, f, id); peerTouch(t, f) },
			status: Fail, want: []string{"изменился"}},
		{name: "снимок после К6 не снят — НЕ ПРОВЕРЕНО", inK6: appRewrite, failAfter: true,
			status: NotChecked, want: []string{"снимок после К6 не снят"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			f, id := withAdmin(t, true)
			preflight(t, f)
			real := f.env.Remote
			locked, broke := false, false
			f.env.Remote = func(cmd string) (string, error) {
				if c.atLock != nil && !locked && strings.Contains(cmd, "lslocks") {
					locked = true
					c.atLock(t, f, id)
				}
				if broke {
					broke = false
					return "", errors.New("обрыв связи")
				}
				return real(cmd)
			}
			asked := false
			f.env.Ask = func(q string) Answer {
				if strings.HasPrefix(q, "К6:") {
					asked = true
					c.inK6(t, f, id)
					broke = c.failAfter
				}
				return AnswerYes
			}
			rs, err := Run(f.env)
			if err != nil {
				t.Fatal(err)
			}
			m := byID(rs)
			if !asked || m["К6"].Status != Pass {
				t.Fatalf("К6 не прошёл — проверка ничего не значит: %+v", m["К6"])
			}
			if c.atLock != nil && !locked {
				t.Fatal("правка вне окна не выполнялась")
			}
			r := m["П0-итог"]
			if r.Status != c.status {
				t.Fatalf("П0-итог: %v, ждали %v: %s", r.Status, c.status, r.Detail)
			}
			for _, w := range c.want {
				if !strings.Contains(r.Detail, w) {
					t.Errorf("П0-итог без %q: %s", w, r.Detail)
				}
			}
		})
	}
}

// TestFieldDiff — перечень полей: не-секретные с было/стало, прочие —
// только имя; неразобранная запись — так и сказано.
func TestFieldDiff(t *testing.T) {
	a := `{"clientId":"k","userData":{"clientName":"A","token":"s1"}}`
	b := `{"clientId":"k","userData":{"clientName":"B","token":"s2","allowed_ips":"10.8.1.1/32"}}`
	got := fieldDiff(a, b)
	for _, w := range []string{`allowed_ips: было нет, стало "10.8.1.1/32"`, `clientName: было "A", стало "B"`, "token (значение не печатается)"} {
		if !strings.Contains(got, w) {
			t.Errorf("нет %q: %s", w, got)
		}
	}
	if strings.Contains(got, "s1") || strings.Contains(got, "s2") {
		t.Errorf("значение не-открытого поля напечатано: %s", got)
	}
	if fieldDiff("{", b) != "поля не разобраны" {
		t.Error("неразобранная запись")
	}
}
