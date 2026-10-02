package canary

import (
	"errors"
	"strings"
	"testing"
)

// Правка П0: существующий клиент администратора приложения Amnezia.
const adminName = "Admin [Android (16.0)]"

// withAdmin — пустой fakesrv плюс один клиент, созданный «до канарейки»
// (как приложение Amnezia при установке протокола); полная прогонка Run
// с пройденными предусловиями К2. ServerIP — адрес стенда.
func withAdmin(t *testing.T, admin bool) (*fakeServer, string) {
	t.Helper()
	f := emptyFake(t, false)
	id := ""
	if admin {
		u, err := f.env.Sess.AddUser(f.env.Ctr, adminName)
		if err != nil {
			t.Fatal(err)
		}
		m, err := f.env.names()
		if err != nil || m[u.Name].ClientID == "" {
			t.Fatalf("клиент администратора не создан: %v", err)
		}
		id = m[u.Name].ClientID
	}
	f.env.Remote = scriptedPre(f.env.Remote, "")
	f.env.NewBin = newCLI(t)
	f.env.RaceRounds = 1
	f.env.MakeSudoKey = noopSudoKey
	f.env.Ask = func(string) Answer { return AnswerYes }
	f.env.ServerIP = f.env.Sess.Creds.Host
	return f, id
}

func byID(rs []Result) map[string]Result {
	m := map[string]Result{}
	for _, r := range rs {
		m[r.ID] = r
	}
	return m
}

// TestExistingClientKept — один существующий клиент: канарейка проходит
// так же, как на пустом сервере (те же исходы каждого шага), П0-итог
// ПРОЙДЕН, клиент на месте.
func TestExistingClientKept(t *testing.T) {
	fe, _ := withAdmin(t, false)
	fe.env.ServerIP = "" // эталон: пустой сервер, прежний П0
	empty, err := Run(fe.env)
	if err != nil {
		t.Fatal(err)
	}
	f, id := withAdmin(t, true)
	rs, err := Run(f.env)
	if err != nil {
		t.Fatal(err)
	}
	got, want := byID(rs), byID(empty)
	if got["П0"].Status != Pass || !strings.Contains(got["П0"].Detail, "клиентов до проверки 1") {
		t.Fatalf("П0: %+v", got["П0"])
	}
	if got["П0-итог"].Status != Pass {
		t.Fatalf("П0-итог: %+v", got["П0-итог"])
	}
	if _, ok := want["П0-итог"]; ok {
		t.Errorf("без -server-ip шага П0-итог быть не должно")
	}
	// проверка ничего не значит, если записи не выполнялись: шаги записи,
	// касающиеся существующих клиентов (К3, откат, гонка с возвратом файлов
	// прежней записью), обязаны ПРОЙТИ на обоих стендах
	for _, k := range []string{"К3", "К4", "У"} {
		if got[k].Status != Pass || want[k].Status != Pass {
			t.Errorf("проверка ничего не значит: %s — с клиентом %s (%s), на пустом %s (%s)", k, got[k].Status, got[k].Detail, want[k].Status, want[k].Detail)
		}
	}
	for k, w := range want {
		if k == "П0" {
			continue
		}
		if got[k].Status != w.Status {
			t.Errorf("%s: с существующим клиентом %s (%s), на пустом %s (%s)", k, got[k].Status, got[k].Detail, w.Status, w.Detail)
		}
	}
	m, err := f.env.names()
	if err != nil || m[adminName].ClientID != id {
		t.Errorf("клиент администратора после канарейки: %+v, %v", m[adminName], err)
	}
}

// TestExistingClientErasedFails — подмена «шаг стирает чужого клиента»:
// посреди прогона клиента администратора удаляют — П0-итог НЕ ПРОЙДЕН.
// Вторая подмена — меняют его запись в таблице (имя) — тоже НЕ ПРОЙДЕН.
func TestExistingClientErasedFails(t *testing.T) {
	for _, c := range []struct {
		name string
		hit  func(f *fakeServer, id string) error
		want string
	}{
		{"удалён", func(f *fakeServer, id string) error { return f.env.Sess.DeleteByID(f.env.Ctr, id) }, "пропал"},
		{"переименован", func(f *fakeServer, id string) error {
			return f.env.Sess.RenameUser(f.env.Ctr, id, "кто-то другой")
		}, "изменилась"},
	} {
		t.Run(c.name, func(t *testing.T) {
			f, id := withAdmin(t, true)
			real := f.env.Remote
			done := false
			f.env.Remote = func(cmd string) (string, error) {
				if !done && strings.Contains(cmd, "lslocks") {
					done = true
					if err := c.hit(f, id); err != nil {
						t.Fatal(err)
					}
				}
				return real(cmd)
			}
			rs, err := Run(f.env)
			if err != nil {
				t.Fatal(err)
			}
			r := byID(rs)["П0-итог"]
			if r.Status != Fail || !strings.Contains(r.Detail, c.want) {
				t.Fatalf("П0-итог при чужом клиенте «%s»: %+v", c.name, r)
			}
		})
	}
}

// TestExistingOverLimitStops — клиентов больше MaxExisting — СТОП на П0,
// ни одной записи; ровно MaxExisting — допускается.
func TestExistingOverLimitStops(t *testing.T) {
	for _, n := range []int{MaxExisting, MaxExisting + 1} {
		f, _ := withAdmin(t, false)
		for i := 0; i < n; i++ {
			if _, err := f.env.Sess.AddUser(f.env.Ctr, "Admin "+string(rune('A'+i))); err != nil {
				t.Fatal(err)
			}
		}
		before := len(f.exec.Commands())
		r := f.env.existingAllowed()
		if n <= MaxExisting {
			if r.Status != Pass {
				t.Errorf("%d клиентов: %+v", n, r)
			}
			continue
		}
		if r.Status != Fail || !strings.Contains(r.Detail, "СТОП") {
			t.Errorf("%d клиентов: %+v", n, r)
		}
		for _, cmd := range f.exec.Commands()[before:] {
			if strings.Contains(cmd, "flock -w") {
				t.Fatalf("запись при превышении порога: %.80s", cmd)
			}
		}
		f.env.ServerIP = f.env.Sess.Creds.Host
		rs, err := Run(f.env)
		if !errors.Is(err, ErrStop) || byID(rs)["П0"].Status == Pass {
			t.Errorf("Run при %d клиентах: err=%v, П0=%+v", n, err, byID(rs)["П0"])
		}
	}
}

// TestExistingCanaryLeftStops — среди существующих canary-* (след прошлого
// прогона) — СТОП.
func TestExistingCanaryLeftStops(t *testing.T) {
	f, _ := withAdmin(t, false)
	if _, err := f.env.Sess.AddUser(f.env.Ctr, "canary-old"); err != nil {
		t.Fatal(err)
	}
	if r := f.env.existingAllowed(); r.Status != Fail || !strings.Contains(r.Detail, "canary-old") {
		t.Errorf("%+v", r)
	}
}

// TestWithoutServerIPStrict — без -server-ip прежнее поведение: клиент
// есть — СТОП.
func TestWithoutServerIPStrict(t *testing.T) {
	f, _ := withAdmin(t, true)
	f.env.ServerIP = ""
	rs, err := Run(f.env)
	if !errors.Is(err, ErrStop) || byID(rs)["П0"].Status == Pass {
		t.Fatalf("без -server-ip сервер с клиентом: err=%v, %+v", err, byID(rs)["П0"])
	}
}

// TestCheckServerIP — -server-ip против адреса из ключа.
func TestCheckServerIP(t *testing.T) {
	for _, c := range []struct {
		flag, host string
		ok         bool
	}{
		{"89.22.229.78", "89.22.229.78", true},
		{" 89.22.229.78 ", "89.22.229.78", true},
		{"89.22.229.78", "89.22.229.79", false},
		{"не-ip", "89.22.229.78", false},
		{"", "89.22.229.78", false},
		{"127.0.0.1", "localhost", true},
		{"10.0.0.1", "localhost", false},
		{"10.0.0.1", "нет-такого-имени.invalid", false},
	} {
		if err := CheckServerIP(c.flag, c.host); (err == nil) != c.ok {
			t.Errorf("-server-ip %q, ключ %q: %v, ждали ok=%v", c.flag, c.host, err, c.ok)
		}
	}
}

// TestPeerBlocks — разбор [Peer] по ключу.
func TestPeerBlocks(t *testing.T) {
	m := peerBlocks("[Interface]\nPrivateKey = x\n\n[Peer]\nPublicKey = A\nAllowedIPs = 10.8.1.2/32\n\n[Peer]\nPublicKey = B\nAllowedIPs = 10.8.1.3/32\n")
	if len(m) != 2 || m["A"] != "[Peer]\nPublicKey = A\nAllowedIPs = 10.8.1.2/32" || !strings.Contains(m["B"], "10.8.1.3") {
		t.Errorf("%q", m)
	}
}
