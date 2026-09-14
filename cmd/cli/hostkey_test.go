package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"amnezia-admin/internal/fakesrv"
)

// restartFakeSSHServerSameAddr закрывает srv и поднимает НОВЫЙ сервер (с
// НОВЫМ, отличным от исходного, ключом хоста) на ТОМ ЖЕ АДРЕСЕ — имитирует
// «сервер переустановили» (тот же приём, что и core/hostkey_test.go:
// restartFakeSSHServerSameAddr, здесь своя копия — пакеты разные, экспорта
// между core и cmd/cli для тестового кода нет и не нужно). Небольшой ретрай
// на bind — сразу после Close порт иногда на мгновение занят.
func restartFakeSSHServerSameAddr(t *testing.T, srv *fakesrv.SSHServer, user, password string) *fakesrv.SSHServer {
	t.Helper()
	addr := srv.Addr()
	if err := srv.Close(); err != nil {
		t.Fatalf("Close исходного сервера: %v", err)
	}
	hostKey, err := fakesrv.NewHostKey()
	if err != nil {
		t.Fatalf("fakesrv.NewHostKey: %v", err)
	}
	var next *fakesrv.SSHServer
	var lastErr error
	for i := 0; i < 20; i++ {
		next, lastErr = fakesrv.ListenSSH(addr, user, password, hostKey, fakesrv.New())
		if lastErr == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if lastErr != nil {
		t.Fatalf("не удалось перезапустить сервер на прежнем адресе %s: %v", addr, lastErr)
	}
	t.Cleanup(func() { next.Close() })
	return next
}

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

	// (d) — ревью PR-4-Б, круг 1, Low: сервер сменил ключ хоста (та же
	// имитация переустановки, что и в core/hostkey_test.go) — код 1,
	// known_hosts байт в байт прежний, ни -hostkey (со СТАРЫМ, теперь уже
	// неверным отпечатком), ни -yes смену не обходят. Последний подтест —
	// после него исходный srv закрыт и заменён.
	t.Run("сервер сменил ключ — код 1, known_hosts не тронут, -hostkey/-yes не обходят", func(t *testing.T) {
		oldFp := srv.Fingerprint()
		khBefore, err := os.ReadFile(knownHostsPath)
		if err != nil {
			t.Fatalf("known_hosts перед сменой ключа: %v", err)
		}

		newSrv := restartFakeSSHServerSameAddr(t, srv, user, password)
		if newSrv.Fingerprint() == oldFp {
			t.Fatal("тестовая настройка сломана: отпечаток не изменился")
		}

		var stdout, stderr bytes.Buffer
		code := run([]string{"list", "-key", key}, strings.NewReader(""), &stdout, &stderr, knownHostsPath)
		if code != 1 {
			t.Errorf("без -hostkey: code = %d, хочу 1; stderr:\n%s", code, stderr.String())
		}
		if !strings.Contains(stderr.String(), oldFp) || !strings.Contains(stderr.String(), newSrv.Fingerprint()) {
			t.Errorf("stderr не содержит оба отпечатка (был/стал): %q", stderr.String())
		}

		stdout.Reset()
		stderr.Reset()
		code = run([]string{"list", "-key", key, "-hostkey", oldFp}, strings.NewReader(""), &stdout, &stderr, knownHostsPath)
		if code != 1 {
			t.Errorf("со СТАРЫМ -hostkey: code = %d, хочу 1 (не обходит смену)", code)
		}

		stdout.Reset()
		stderr.Reset()
		code = run([]string{"del", "-key", key, "-hostkey", newSrv.Fingerprint(), "-name", "Alice", "-yes"}, strings.NewReader(""), &stdout, &stderr, knownHostsPath)
		if code != 1 {
			t.Errorf("del -yes -hostkey=НОВЫЙ отпечаток: code = %d, хочу 1 (смена ключа отклоняется до -yes/-hostkey, потому что known_hosts хранит СТАРЫЙ ключ)", code)
		}

		khAfter, err := os.ReadFile(knownHostsPath)
		if err != nil {
			t.Fatalf("known_hosts после попыток смены ключа: %v", err)
		}
		if !bytes.Equal(khBefore, khAfter) {
			t.Fatalf("known_hosts изменился при отказах смены ключа:\nбыло:  %q\nстало: %q", khBefore, khAfter)
		}
	})
}
