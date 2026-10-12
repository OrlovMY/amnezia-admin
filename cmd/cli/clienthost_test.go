package main

import (
	"bytes"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestCLIClientHostDoezd — тест доезда: add/rekey через настоящий SSH к
// fakesrv (адрес в ключе — IP 127.0.0.1) с -client-host; конфиг в файле
// содержит имя. На 2f84e37 флага не было, Endpoint был 127.0.0.1.
func TestCLIClientHostDoezd(t *testing.T) {
	saved := clientHostResolver
	t.Cleanup(func() { clientHostResolver = saved })
	recs := map[string][]string{
		"vpn.example.com":   {"127.0.0.1"},
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
