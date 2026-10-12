package core_test

import (
	"errors"
	"net"
	"strings"
	"testing"

	"amnezia-admin/core"
	"amnezia-admin/internal/fakesrv"
)

func stubResolver(m map[string][]string, err error) core.Resolver {
	return func(h string) ([]net.IP, error) {
		if err != nil {
			return nil, err
		}
		var out []net.IP
		for _, s := range m[h] {
			out = append(out, net.ParseIP(s))
		}
		return out, nil
	}
}

// TestCheckClientHostTable — три исхода сверки имени, несколько записей,
// семейства адресов. «Не удалось» обязано отличаться от «совпадает» и от
// «не совпадает».
func TestCheckClientHostTable(t *testing.T) {
	recs := map[string][]string{
		"vpn.example.com":    {"203.0.113.5"},
		"other.example.com":  {"198.51.100.7"},
		"rr.example.com":     {"203.0.113.5", "198.51.100.7"},
		"both.example.com":   {"203.0.113.5", "2001:db8::1"},
		"v6only.example.com": {"2001:db8::1"},
		"empty.example.com":  {},
	}
	res := stubResolver(recs, nil)
	cases := []struct {
		name, host, srv string
		resolve         core.Resolver
		want            core.ClientHostStatus
		text            string
	}{
		{"совпало", "vpn.example.com", "203.0.113.5", res, core.ClientHostMatch, "указывает на этот сервер"},
		{"другой IP", "other.example.com", "203.0.113.5", res, core.ClientHostMismatch, "НЕ на этот сервер"},
		{"часть записей чужая", "rr.example.com", "203.0.113.5", res, core.ClientHostMismatch, "198.51.100.7"},
		{"A совпала, AAAA не проверена", "both.example.com", "203.0.113.5", res, core.ClientHostMatch, "не проверены"},
		{"только AAAA при IPv4", "v6only.example.com", "203.0.113.5", res, core.ClientHostUnknown, "нет записей A"},
		{"нет записей", "empty.example.com", "203.0.113.5", res, core.ClientHostUnknown, "не удалось"},
		{"не резолвится", "vpn.example.com", "203.0.113.5", stubResolver(nil, errors.New("no such host")), core.ClientHostUnknown, "no such host"},
		{"DNS недоступен (нет резолвера)", "vpn.example.com", "203.0.113.5", nil, core.ClientHostUnknown, "не удалось"},
		{"адрес сервера неизвестен", "vpn.example.com", "", res, core.ClientHostUnknown, "неизвестен адрес"},
		{"публичный IPv6 совпал", "v6only.example.com", "2001:db8::1", res, core.ClientHostMatch, "указывает на этот сервер"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := core.CheckClientHost(tc.host, tc.srv, tc.resolve)
			if c.Status != tc.want {
				t.Errorf("статус %d, ждали %d (%s)", c.Status, tc.want, c.Text())
			}
			if !strings.Contains(c.Text(), tc.text) {
				t.Errorf("текст %q без %q", c.Text(), tc.text)
			}
			if !strings.Contains(c.Text(), "подсказка, а не гарантия") {
				t.Errorf("нет оговорки о DNS этого компьютера: %q", c.Text())
			}
			if tc.want == core.ClientHostUnknown && (strings.Contains(c.Text(), "указывает на этот") || strings.Contains(c.Text(), "НЕ на этот")) {
				t.Errorf("«не удалось» выдано за ответ: %q", c.Text())
			}
		})
	}
}

// TestDecideClientHostTable — IP в ключе и отказ / имя в ключе / выбранное имя.
func TestDecideClientHostTable(t *testing.T) {
	cases := []struct {
		name, key string
		set       core.ClientHostSetting
		host      string
		ask       bool
	}{
		{"имя в ключе — не спрашивать", "vpn.example.com", core.ClientHostSetting{}, "vpn.example.com", false},
		{"IP в ключе, выбора нет — спросить", "203.0.113.5", core.ClientHostSetting{}, "203.0.113.5", true},
		{"IPv6 в ключе — спросить", "2001:db8::1", core.ClientHostSetting{}, "2001:db8::1", true},
		{"IP в ключе и отказ — IP, не спрашивать", "203.0.113.5", core.ClientHostSetting{KeepIP: true}, "203.0.113.5", false},
		{"IP в ключе, имя выбрано", "203.0.113.5", core.ClientHostSetting{Host: "vpn.example.com"}, "vpn.example.com", false},
		{"имя в ключе, выбрано другое имя", "a.example.com", core.ClientHostSetting{Host: "b.example.com"}, "b.example.com", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h, ask := core.DecideClientHost(tc.key, tc.set)
			if h != tc.host || ask != tc.ask {
				t.Errorf("(%q, %v), ждали (%q, %v)", h, ask, tc.host, tc.ask)
			}
		})
	}
}

func TestNormalizeClientHost(t *testing.T) {
	for in, want := range map[string]string{" VPN.Example.com. ": "vpn.example.com", "a-b.c": "a-b.c"} {
		if got, err := core.NormalizeClientHost(in); err != nil || got != want {
			t.Errorf("%q → %q, %v", in, got, err)
		}
	}
	for _, bad := range []string{"", "1.2.3.4", "::1", "a..b", "-a.b", "впн.рф", "a b.c", "a:22"} {
		if _, err := core.NormalizeClientHost(bad); err == nil {
			t.Errorf("%q принято", bad)
		}
	}
}

// TestClientHostReachesConfigs — тест доезда: выбранное имя попадает в
// Endpoint конфига добавленного и перевыпущенного клиента (fakesrv), а без
// выбора — как прежде hostName ключа. На 2f84e37 конфиг содержал IP.
func TestClientHostReachesConfigs(t *testing.T) {
	for _, tc := range []struct{ name, set, want string }{
		{"имя выбрано", "vpn.example.com", "Endpoint = vpn.example.com:"},
		{"выбора нет — hostName ключа", "", "Endpoint = 1.2.3.4:"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := fakesrv.New()
			sess := core.NewSessionWithRunner(srv, raceCreds())
			sess.ClientHost = tc.set
			c := raceContainer()
			nu, err := sess.AddUser(c, "Carol")
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(nu.Config, tc.want) {
				t.Errorf("add: конфиг без %q:\n%s", tc.want, nu.Config)
			}
			if tc.set != "" && strings.Contains(nu.Config, "1.2.3.4") {
				t.Errorf("add: в конфиге остался IP")
			}
			cls, err := sess.LoadClients(c)
			if err != nil {
				t.Fatal(err)
			}
			var id string
			for _, cl := range cls {
				if cl.Name() == "Carol" {
					id = cl.ClientID
				}
			}
			ru, err := sess.RegenerateUser(c, id)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(ru.Config, tc.want) {
				t.Errorf("rekey: конфиг без %q:\n%s", tc.want, ru.Config)
			}
		})
	}
}

// TestClientHostReachesXRayLink — то же для ссылки vless:// XRay.
func TestClientHostReachesXRayLink(t *testing.T) {
	srv := fakesrv.NewXRay("master")
	sess, x := xraySession(t, srv)
	sess.ClientHost = "vpn.example.com"
	nu, err := xrayApply(sess.PlanAddUser(x, "Carol"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(nu.Link, "@vpn.example.com:") || strings.Contains(nu.Link, "1.2.3.4") {
		t.Errorf("ссылка %q", nu.Link)
	}
}

// TestSessionServerIP — адрес подключения: без SSH — IP из ключа, имя в
// ключе без SSH — неизвестен ("" → проверка «не удалось»).
func TestSessionServerIP(t *testing.T) {
	if ip := core.NewSessionWithRunner(nil, &core.ServerCreds{Host: "203.0.113.5"}).ServerIP(); ip != "203.0.113.5" {
		t.Errorf("%q", ip)
	}
	if ip := core.NewSessionWithRunner(nil, &core.ServerCreds{Host: "vpn.example.com"}).ServerIP(); ip != "" {
		t.Errorf("%q", ip)
	}
}

// TestCheckClientHostPrivateServerIP — З1 AU-LOGIC: адрес подключения не
// публичный (туннель, проброс, частная сеть) — сравнивать не с чем:
// «не удалось», а не «указывает на другие адреса».
func TestCheckClientHostPrivateServerIP(t *testing.T) {
	res := stubResolver(map[string][]string{"vpn.example.com": {"203.0.113.5", "2001:db8::5"}}, nil)
	for _, srv := range []string{"127.0.0.1", "10.8.1.1", "172.16.5.5", "172.31.255.1", "192.168.1.1", "100.64.1.1", "100.127.0.1", "169.254.1.1", "::1", "fd00::1", "fc00::2", "fe80::1"} {
		t.Run(srv, func(t *testing.T) {
			c := core.CheckClientHost("vpn.example.com", srv, res)
			if c.Status != core.ClientHostUnknown {
				t.Errorf("статус %d: %s", c.Status, c.Text())
			}
			if !strings.Contains(c.Text(), "частный/туннельный адрес "+srv) || strings.Contains(c.Text(), "НЕ на этот") {
				t.Errorf("текст %q", c.Text())
			}
		})
	}
	// граница: соседние публичные адреса сравниваются как обычно
	for _, srv := range []string{"100.63.255.1", "100.128.0.1", "172.32.0.1"} {
		if c := core.CheckClientHost("vpn.example.com", srv, res); c.Status != core.ClientHostMismatch {
			t.Errorf("%s: статус %d (%s)", srv, c.Status, c.Text())
		}
	}
}
