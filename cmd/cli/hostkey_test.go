package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net"
	"path/filepath"
	"strings"
	"testing"

	"amnezia-admin/internal/fakesrv"
)

// buildTestVpnKey — тот же формат "bare JSON base64", что понимает
// core.DecodeVpnKey (core/core_test.go:47-57) и печатает cmd/fakeserver —
// hostName/userName/password/port из addr фейкового SSH-сервера.
func buildTestVpnKey(t *testing.T, addr, user, password string) string {
	t.Helper()
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("SplitHostPort(%q): %v", addr, err)
	}
	m := map[string]any{
		"hostName": host,
		"userName": user,
		"password": password,
		"port":     port,
	}
	data, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	return "vpn://" + base64.RawURLEncoding.EncodeToString(data)
}

// TestNonTTYUnknownHostNeedsHostkey — Е3 задания PR-4: без -hostkey CLI без
// терминала обязан отказать неизвестному серверу с кодом 2 и напечатать
// отпечаток на stderr (подсказка "-hostkey SHA256:…"); с верным -hostkey —
// подключиться и выполнить list. Доказывает на 3ea9806 (база части Б без
// изменений run()): main.go тогда не имел func run(...) и флага -hostkey
// вовсе — не компилируется (слабейшая форма регресса, но других на этой базе
// для НОВОГО кода тут и не бывает: сама функция появляется только в части Б).
func TestNonTTYUnknownHostNeedsHostkey(t *testing.T) {
	const user, password = "root", "fakepw-hostkey-test"
	hostKey, err := fakesrv.NewHostKey()
	if err != nil {
		t.Fatalf("NewHostKey: %v", err)
	}
	srv, err := fakesrv.ListenSSH("127.0.0.1:0", user, password, hostKey, fakesrv.New())
	if err != nil {
		t.Fatalf("ListenSSH: %v", err)
	}
	t.Cleanup(func() { srv.Close() })

	key := buildTestVpnKey(t, srv.Addr(), user, password)
	knownHostsPath := filepath.Join(t.TempDir(), "known_hosts")

	t.Run("без -hostkey — код 2, отпечаток на stderr", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		code := run([]string{"list", "-key", key}, strings.NewReader(""), &stdout, &stderr, knownHostsPath)
		if code != 2 {
			t.Errorf("code = %d, хочу 2; stderr:\n%s", code, stderr.String())
		}
		if !strings.Contains(stderr.String(), srv.Fingerprint()) {
			t.Errorf("stderr не содержит отпечаток %q: %q", srv.Fingerprint(), stderr.String())
		}
		if !strings.Contains(stderr.String(), "-hostkey") {
			t.Errorf("stderr не содержит подсказку про -hostkey: %q", stderr.String())
		}
		if stdout.Len() != 0 {
			t.Errorf("stdout должен быть пуст при отказе, получено: %q", stdout.String())
		}
	})

	t.Run("с верным -hostkey — list печатает таблицу", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		code := run([]string{"list", "-key", key, "-hostkey", srv.Fingerprint()}, strings.NewReader(""), &stdout, &stderr, knownHostsPath)
		if code != 0 {
			t.Fatalf("code = %d, хочу 0; stderr:\n%s", code, stderr.String())
		}
		out := stdout.String()
		for _, want := range []string{"Alice", "Bob", "Публичный ключ"} {
			if !strings.Contains(out, want) {
				t.Errorf("вывод list не содержит %q; out:\n%s", want, out)
			}
		}
	})

	t.Run("повторное подключение тем же -key — без -hostkey тоже проходит (known_hosts уже содержит ключ)", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		code := run([]string{"list", "-key", key}, strings.NewReader(""), &stdout, &stderr, knownHostsPath)
		if code != 0 {
			t.Fatalf("code = %d, хочу 0 (сервер уже известен из known_hosts); stderr:\n%s", code, stderr.String())
		}
		if !strings.Contains(stdout.String(), "Alice") {
			t.Errorf("повторный list не напечатал таблицу: %q", stdout.String())
		}
	})
}
