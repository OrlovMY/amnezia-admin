package main

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"amnezia-admin/core"
	"amnezia-admin/internal/fakesrv"
)

// TestCLIMigrateCloneHostKeyUnknown — тест доезда третьего состояния: два
// настоящих SSH-сервера с ОДНИМ ключом хоста (клон), у цели другой адрес.
// Отпечатки равны по настоящему рукопожатию; ядро говорит «не знаем» (не «один
// сервер»), отказ код 4 с советом про ключи хоста, на серверы ничего. Подмена
// «отказ только при SameYes» пропустила бы переезд — тест падает.
func TestCLIMigrateCloneHostKeyUnknown(t *testing.T) {
	const user, pw = "root", "fakepw-run-e2e-test"
	hk, err := fakesrv.NewHostKey()
	if err != nil {
		t.Fatal(err)
	}
	mk := func() (*fakesrv.Server, string) {
		ex := fakesrv.New()
		srv, err := fakesrv.ListenSSH("127.0.0.1:0", user, pw, hk, ex)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { srv.Close() })
		return ex, buildTestVpnKey(t, srv.Addr(), user, pw)
	}
	src, keyA := mk()
	dst, keyB := mk()
	kh := filepath.Join(t.TempDir(), "known_hosts")
	for _, k := range []string{keyA, keyB} {
		cfg, _ := core.DecodeVpnKey(k)
		creds, _ := core.CredsFromConfig(cfg)
		s, err := core.ConnectWithHostKey(creds, core.HostKeyPolicy{KnownHostsPath: kh, Prompt: func(string, string) bool { return true }})
		if err != nil {
			t.Fatal(err)
		}
		s.Close()
	}
	s1, s2 := cliSession(t, keyA, kh), cliSession(t, keyB, kh)
	if s1.HostKeyFingerprint == "" || s1.HostKeyFingerprint != s2.HostKeyFingerprint {
		t.Fatalf("ключ хоста не общий: %q %q", s1.HostKeyFingerprint, s2.HostKeyFingerprint)
	}
	s1.ClientHostDecided = true
	s2.Creds.Host = "127.0.0.2" // у клона другой адрес
	var o, er bytes.Buffer
	code := runMigrate(context.Background(), strings.NewReader(""), &o, &er, false, s1, s2,
		migrateFlags{apply: true, yes: true, noPw: true, addrOK: true, replaceUsers: true}, time.Now())
	if code != 4 || !strings.Contains(er.String(), "клон") || !strings.Contains(er.String(), "dpkg-reconfigure") || flocks(dst) != 0 || flocks(src) != 0 {
		t.Fatalf("код %d записей %d\n%s\n%s", code, flocks(dst), o.String(), er.String())
	}
}
