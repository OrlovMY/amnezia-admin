package main

import (
	"bytes"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"amnezia-admin/core"
)

// stubClientHost — адрес подключения стенда 127.0.0.1 непубличный (З1),
// поэтому для сверки подставляется публичный 203.0.113.5.
func stubClientHost(t *testing.T) {
	r, ip := clientHostResolver, clientHostServerIP
	t.Cleanup(func() { clientHostResolver, clientHostServerIP = r, ip })
	clientHostServerIP = func(*core.Session) string { return "203.0.113.5" }
	clientHostResolver = func(h string) ([]net.IP, error) {
		if h == "vpn.example.com" {
			return []net.IP{net.ParseIP("203.0.113.5")}, nil
		}
		return nil, errors.New("no such host")
	}
}

// TestCLIClientHostDoezd — тест доезда: add/rekey через настоящий SSH к
// fakesrv (адрес в ключе — IP 127.0.0.1) с -client-host; конфиг в файле
// содержит имя. На 2f84e37 флага не было, Endpoint был 127.0.0.1.
func TestCLIClientHostDoezd(t *testing.T) {
	stubClientHost(t)
	recs := map[string][]string{
		"vpn.example.com":   {"203.0.113.5"},
		"other.example.com": {"192.0.2.9"},
	}
	clientHostResolver = func(h string) ([]net.IP, error) {
		ss, ok := recs[h]
		if !ok {
			return nil, errors.New("no such host")
		}
		var out []net.IP
		for _, s := range ss {
			out = append(out, net.ParseIP(s))
		}
		return out, nil
	}
	cases := []struct {
		name     string
		args     []string
		code     int
		endpoint string // "" — файл не должен появиться
		errHas   string
	}{
		{"имя совпало", []string{"-client-host", "VPN.example.com"}, 0, "Endpoint = vpn.example.com:", ""},
		{"другой IP без подтверждения — отказ", []string{"-client-host", "other.example.com"}, 2, "", "НЕ на этот сервер"},
		{"другой IP с подтверждением", []string{"-client-host", "other.example.com", "-client-host-confirm"}, 0, "Endpoint = other.example.com:", "НЕ на этот сервер"},
		{"не резолвится — не «совпало» и не «не совпало»", []string{"-client-host", "nx.example.com"}, 2, "", "не удалось"},
		{"IP вместо имени — ошибка", []string{"-client-host", "10.0.0.1"}, 1, "", "IP-адрес"},
		{"без имени, IP в ключе — IP и громкое предупреждение", nil, 0, "Endpoint = 127.0.0.1:", "придётся перевыпускать"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("AMNEZIA_CLIENT_HOST", "")
			dir := cliConfigsEnv(t)
			key, kh, _ := setupFakeSSHForRunWithExec(t)
			var o, e bytes.Buffer
			args := append([]string{"add", "-name", "Carol", "-key", key}, tc.args...)
			code := run(args, strings.NewReader(""), &o, &e, kh)
			if code != tc.code {
				t.Fatalf("код %d, ждали %d\n%s\n%s", code, tc.code, o.String(), e.String())
			}
			if !strings.Contains(e.String(), tc.errHas) {
				t.Errorf("stderr без %q:\n%s", tc.errHas, e.String())
			}
			data, err := os.ReadFile(filepath.Join(dir, "Carol.conf"))
			if tc.endpoint == "" {
				if err == nil {
					t.Errorf("конфиг выдан вопреки отказу:\n%s", data)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(data), tc.endpoint) {
				t.Errorf("конфиг без %q:\n%s", tc.endpoint, data)
			}
			if tc.args != nil && strings.Contains(string(data), "127.0.0.1") {
				t.Errorf("в конфиге остался IP:\n%s", data)
			}
		})
	}
	// rekey тоже получает имя
	t.Run("rekey", func(t *testing.T) {
		t.Setenv("AMNEZIA_CLIENT_HOST", "")
		dir := cliConfigsEnv(t)
		key, kh, _ := setupFakeSSHForRunWithExec(t)
		var o, e bytes.Buffer
		if code := run([]string{"add", "-name", "Carol", "-key", key}, strings.NewReader(""), &o, &e, kh); code != 0 {
			t.Fatal(e.String())
		}
		if code := run([]string{"rekey", "-name", "Carol", "-yes", "-key", key, "-client-host", "vpn.example.com"}, strings.NewReader(""), &o, &e, kh); code != 0 {
			t.Fatal(e.String())
		}
		data, _ := os.ReadFile(filepath.Join(dir, "Carol.conf"))
		if !strings.Contains(string(data), "Endpoint = vpn.example.com:") {
			t.Errorf("%s", data)
		}
	})
}

// TestCLIClientHostPrivateConn — З1 доездом: настоящее SSH-подключение к
// 127.0.0.1 (без подмены адреса) — «проверить не удалось», не «другие
// адреса»; без подтверждения конфиг не выдаётся.
func TestCLIClientHostPrivateConn(t *testing.T) {
	r := clientHostResolver
	t.Cleanup(func() { clientHostResolver = r })
	clientHostResolver = func(string) ([]net.IP, error) { return []net.IP{net.ParseIP("203.0.113.5")}, nil }
	t.Setenv("AMNEZIA_CLIENT_HOST", "")
	cliConfigsEnv(t)
	key, kh, _ := setupFakeSSHForRunWithExec(t)
	var o, e bytes.Buffer
	code := run([]string{"add", "-name", "Carol", "-key", key, "-client-host", "vpn.example.com"}, strings.NewReader(""), &o, &e, kh)
	if code != 2 || !strings.Contains(e.String(), "частный/туннельный адрес 127.0.0.1") || strings.Contains(e.String(), "НЕ на этот") {
		t.Errorf("%d\n%s", code, e.String())
	}
}

// TestCLIClientHostSurfaces — З3/З4: строка об адресе после выдачи;
// -dry-run говорит, какой адрес будет; show-config XRay учитывает
// -client-host; show-config WG прямо говорит, что флаг не действует; без
// имени show-config XRay предупреждает об IP.
func TestCLIClientHostSurfaces(t *testing.T) {
	stubClientHost(t)
	t.Setenv("AMNEZIA_CLIENT_HOST", "")
	cliConfigsEnv(t)
	key, kh, _ := setupFakeSSHForRunWithExec(t)
	runIt := func(k string, args ...string) (int, string, string) {
		var o, e bytes.Buffer
		c := run(append(args, "-key", k), strings.NewReader(""), &o, &e, kh)
		return c, o.String(), e.String()
	}
	if c, o, e := runIt(key, "add", "-name", "Carol", "-client-host", "vpn.example.com"); c != 0 || !strings.Contains(o, "Адрес сервера в конфиге: vpn.example.com") {
		t.Errorf("add: %d\n%s\n%s", c, o, e)
	}
	if c, o, e := runIt(key, "add", "-dry-run", "-name", "Dave", "-client-host", "vpn.example.com"); c != 0 || !strings.Contains(o, "будет: vpn.example.com") {
		t.Errorf("dry-run: %d\n%s\n%s", c, o, e)
	}
	if c, o, e := runIt(key, "add", "-dry-run", "-name", "Dave"); c != 0 || !strings.Contains(o, "будет: 127.0.0.1") || !strings.Contains(e, "придётся перевыпускать") {
		t.Errorf("dry-run без имени: %d\n%s\n%s", c, o, e)
	}
	if c, o, e := runIt(key, "show-config", "-name", "Carol", "-client-host", "vpn.example.com"); c != 0 || !strings.Contains(e, "здесь не действует") {
		t.Errorf("show-config WG: %d\n%s\n%s", c, o, e)
	}
	xkey, xkh, _ := setupXRayRun(t)
	var o, e bytes.Buffer
	if c := run([]string{"show-config", "-key", xkey, "-name", "Bob", "-print", "-client-host", "vpn.example.com"}, strings.NewReader(""), &o, &e, xkh); c != 0 || !strings.Contains(o.String(), "@vpn.example.com:") {
		t.Errorf("show-config XRay: %d\n%s\n%s", c, o.String(), e.String())
	}
	o.Reset()
	e.Reset()
	if c := run([]string{"show-config", "-key", xkey, "-name", "Bob", "-print"}, strings.NewReader(""), &o, &e, xkh); c != 0 || !strings.Contains(e.String(), "придётся перевыпускать") {
		t.Errorf("show-config XRay без имени: %d\n%s", c, e.String())
	}
}
