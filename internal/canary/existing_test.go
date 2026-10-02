package canary

import (
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"amnezia-admin/core"
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

// withInspect — ответ на docker inspect .Created: каждому контейнеру из
// команды — время created (fakesrv inspect не умеет).
func withInspect(real func(string) (string, error), created time.Time) func(string) (string, error) {
	return func(cmd string) (string, error) {
		if i := strings.Index(cmd, "{{.Created}}' "); i >= 0 && strings.Contains(cmd, " inspect --format") {
			var b strings.Builder
			for _, n := range strings.Fields(cmd[i+len("{{.Created}}' "):]) {
				fmt.Fprintf(&b, "/%s %s\n", n, created.UTC().Format(time.RFC3339Nano))
			}
			return b.String(), nil
		}
		return real(cmd)
	}
}

// preflight — Preflight по одному контейнеру, контейнер поставлен час назад.
func preflight(t *testing.T, f *fakeServer) []Result {
	t.Helper()
	now := time.Now()
	f.env.Remote = withInspect(f.env.Remote, now.Add(-time.Hour))
	return Preflight(f.env.Remote, []*Env{f.env}, []string{f.env.Ctr.Name}, now)
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
	pre := preflight(t, f)
	if byID(pre)["П0-сервер"].Status != Pass || byID(pre)["П0-свежесть"].Status != Pass {
		t.Fatalf("свежий сервер с 1 клиентом не прошёл предпроверку: %+v", pre)
	}
	rs, err := Run(f.env)
	if err != nil {
		t.Fatal(err)
	}
	got, want := byID(rs), byID(empty)
	if got["П0"].Status != Pass || !strings.Contains(got["П0"].Detail, "клиентов в контейнере до проверки 1") {
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
			preflight(t, f)
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

// TestPreflightServerTotal — SEC П-2: порог — на СЕРВЕР в сумме по всем
// контейнерам WG. 2+2 в двух контейнерах — СТОП (на контейнер каждый в
// пороге); 2+1 — проходит; 1 — проходит. Без предпроверки П0 с -server-ip —
// СТОП, ни одной записи.
func TestPreflightServerTotal(t *testing.T) {
	mk := func(n int) *fakeServer {
		f, _ := withAdmin(t, false)
		for i := 0; i < n; i++ {
			if _, err := f.env.Sess.AddUser(f.env.Ctr, "Admin "+string(rune('A'+i))); err != nil {
				t.Fatal(err)
			}
		}
		return f
	}
	now := time.Now()
	fresh := func(string) (string, error) {
		return "/amnezia-awg " + now.Add(-time.Hour).UTC().Format(time.RFC3339Nano) + "\n/amnezia-wireguard " + now.Add(-2*time.Hour).UTC().Format(time.RFC3339Nano) + "\n", nil
	}
	names := []string{"amnezia-awg", "amnezia-wireguard"}
	for _, c := range []struct {
		counts []int
		want   Status
	}{
		{[]int{2, 2}, Fail},
		{[]int{2, 1}, Pass},
		{[]int{1}, Pass},
		{[]int{4}, Fail},
		{[]int{0, 0}, Pass},
	} {
		var envs []*Env
		for _, n := range c.counts {
			envs = append(envs, mk(n).env)
		}
		r := byID(Preflight(fresh, envs, names, now))["П0-сервер"]
		if r.Status != c.want {
			t.Errorf("клиенты %v: %s (%s), ждали %s", c.counts, r.Status, r.Detail, c.want)
		}
		for _, e := range envs {
			if e.preflightOK != (c.want == Pass) {
				t.Errorf("клиенты %v: предпроверка отмечена %v", c.counts, e.preflightOK)
			}
		}
	}
	// без предпроверки: Run с -server-ip — СТОП на П0, без записей
	f := mk(1)
	f.env.ServerIP = f.env.Sess.Creds.Host
	before := len(f.exec.Commands())
	rs, err := Run(f.env)
	if !errors.Is(err, ErrStop) || byID(rs)["П0"].Status == Pass {
		t.Errorf("Run без предпроверки: err=%v, П0=%+v", err, byID(rs)["П0"])
	}
	for _, cmd := range f.exec.Commands()[before:] {
		if strings.Contains(cmd, "flock -w") {
			t.Fatalf("запись без предпроверки: %.80s", cmd)
		}
	}
}

// TestAgeCheck — SEC П-2: контейнер старше 72 ч — СТОП; сбой inspect,
// неразобранный ответ, нет контейнера в ответе — СТОП (НЕ ПРОВЕРЕНО).
func TestAgeCheck(t *testing.T) {
	now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	at := func(h float64) string {
		return now.Add(-time.Duration(h * float64(time.Hour))).Format(time.RFC3339Nano)
	}
	names := []string{"amnezia-awg2", "amnezia-wireguard"}
	for _, c := range []struct {
		name string
		out  string
		err  error
		want Status
	}{
		{"оба свежие", "/amnezia-awg2 " + at(1) + "\n/amnezia-wireguard " + at(71.9) + "\n", nil, Pass},
		{"один старше 72 ч", "/amnezia-awg2 " + at(1) + "\n/amnezia-wireguard " + at(72.1) + "\n", nil, Fail},
		{"боевой — месяц", "/amnezia-awg2 " + at(24*30) + "\n/amnezia-wireguard " + at(24*30) + "\n", nil, Fail},
		{"inspect упал", "Error: No such object", errors.New("exit status 1"), NotChecked},
		{"время не разобрано", "/amnezia-awg2 вчера\n/amnezia-wireguard " + at(1) + "\n", nil, NotChecked},
		{"строка не разобрана", "мусор\n", nil, NotChecked},
		{"одного нет в ответе", "/amnezia-awg2 " + at(1) + "\n", nil, NotChecked},
		{"пустой ответ", "", nil, NotChecked},
	} {
		r := AgeCheck(func(string) (string, error) { return c.out, c.err }, names, now)
		if r.Status != c.want {
			t.Errorf("%s: %s (%s), ждали %s", c.name, r.Status, r.Detail, c.want)
		}
	}
	if r := AgeCheck(func(string) (string, error) { return "", nil }, nil, now); r.Status == Pass {
		t.Errorf("без контейнеров: %+v", r)
	}
	// Preflight: старый контейнер — СТОП, даже если клиентов ноль
	f, _ := withAdmin(t, false)
	old := func(string) (string, error) { return "/amnezia-awg " + at(100) + "\n", nil }
	pre := byID(Preflight(old, []*Env{f.env}, []string{"amnezia-awg"}, now))
	if pre["П0-свежесть"].Status != Fail || f.env.preflightOK {
		t.Errorf("старый контейнер: %+v, отмечено %v", pre["П0-свежесть"], f.env.preflightOK)
	}
	failInspect := func(string) (string, error) { return "", errors.New("exit status 1") }
	pre = byID(Preflight(failInspect, []*Env{f.env}, []string{"amnezia-awg"}, now))
	if pre["П0-свежесть"].Status == Pass || f.env.preflightOK {
		t.Errorf("inspect упал: %+v, отмечено %v", pre["П0-свежесть"], f.env.preflightOK)
	}
}

// TestExistingCanaryLeftStops — среди существующих canary-* (след прошлого
// прогона) — СТОП.
func TestExistingCanaryLeftStops(t *testing.T) {
	f, _ := withAdmin(t, false)
	if _, err := f.env.Sess.AddUser(f.env.Ctr, "canary-old"); err != nil {
		t.Fatal(err)
	}
	preflight(t, f)
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

// TestPinServer — SEC П-1: имя разрешается в {A, B}, флаг A — подключение
// ровно к A (hostName закреплённого ключа = A, и для дочерних программ);
// флаг вне набора — отказ; IP в ключе обязан совпасть.
func TestPinServer(t *testing.T) {
	const a, b = "198.51.100.1", "203.0.113.2"
	lookup := func(h string) ([]net.IP, error) {
		if h == "test.example" {
			return []net.IP{net.ParseIP(a), net.ParseIP(b)}, nil
		}
		return nil, errors.New("нет такого имени")
	}
	cfg := map[string]any{"hostName": "test.example", "userName": "root", "password": "pw", "port": "22"}
	p, err := PinServer(cfg, a, lookup)
	if err != nil {
		t.Fatal(err)
	}
	creds, err := core.CredsFromConfig(p)
	if err != nil || creds.Host != a {
		t.Fatalf("SSH-адрес %q (%v), ждали ровно %s", creds.Host, err, a)
	}
	if cfg["hostName"] != "test.example" {
		t.Errorf("исходный ключ изменён: %v", cfg["hostName"])
	}
	ck, err := ChildKey(p)
	if err != nil {
		t.Fatal(err)
	}
	dec, err := core.DecodeVpnKey(ck)
	if err != nil || dec["hostName"] != a || dec["password"] != "pw" || dec["userName"] != "root" {
		t.Errorf("ключ дочерних программ: %v %v", dec["hostName"], err)
	}
	for _, c := range []struct{ host, flag string }{
		{"test.example", "192.0.2.9"}, {"нет.example", a}, {b, a}, {"test.example", "не-ip"},
	} {
		if _, err := PinServer(map[string]any{"hostName": c.host}, c.flag, lookup); err == nil {
			t.Errorf("ключ %q, флаг %q: ждали отказ", c.host, c.flag)
		}
	}
}

// TestPinServerConnectsByIP — доезд П-1: имя в ключе не разрешается вовсе
// (кроме подставного резолвера), а подключение к fakesrv проходит — значит,
// SSH идёт по закреплённому IP, без второго разрешения имени.
func TestPinServerConnectsByIP(t *testing.T) {
	f := emptyFake(t, false)
	host, port := f.env.Sess.Creds.Host, f.env.Sess.Creds.Port
	cfg := map[string]any{"hostName": "canary-pin.invalid", "userName": "root", "password": "canary-test-pw", "port": port}
	lookup := func(string) ([]net.IP, error) { return []net.IP{net.ParseIP("192.0.2.77"), net.ParseIP(host)}, nil }
	p, err := PinServer(cfg, host, lookup)
	if err != nil {
		t.Fatal(err)
	}
	creds, err := core.CredsFromConfig(p)
	if err != nil {
		t.Fatal(err)
	}
	sess, err := core.ConnectWithHostKey(creds, core.HostKeyPolicy{
		KnownHostsPath: filepath.Join(t.TempDir(), "kh"), ExpectedFingerprint: f.env.HostKey})
	if err != nil {
		t.Fatalf("подключение по закреплённому IP: %v", err)
	}
	defer sess.Close()
	if sess.Creds.Host != host {
		t.Errorf("SSH-адрес %q, ждали %s", sess.Creds.Host, host)
	}
}
