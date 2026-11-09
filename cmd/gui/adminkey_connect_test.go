package main

import (
	"encoding/base64"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"fyne.io/fyne/v2/widget"

	"amnezia-admin/core"
	"amnezia-admin/internal/fakesrv"
)

// Доезд M1 (ревью-2 PR #75): поля ключа попадают в keyMeta БОЕВЫМ путём —
// attemptConnect по настоящему SSH (fakesrv), а не присваиванием в тесте;
// выданный ключ несёт description/dns1/dns2/defaultContainer прежнего.
func TestGUIAdminKeyMetaFromRealConnect(t *testing.T) {
	serialUI(t) // fyne.Do тестового драйвера не сериализует — как в тестах переноса
	// known_hosts пишется в каталог хранилищ бинарника: свой, пустой, убирается
	// после теста — иначе соседние тесты находят чужой «Настройки»
	vd := vaultDirForTest(t)
	t.Cleanup(func() { os.RemoveAll(vd) })
	f := newGUIAKFixture(t, nil)
	f.u.keyMeta = adminKeyMeta{} // заполнить должен только attemptConnect
	hk, err := fakesrv.NewHostKey()
	if err != nil {
		t.Fatal(err)
	}
	srv, err := fakesrv.ListenSSH("127.0.0.1:0", "root", guiAKPw, hk, f.srv)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { srv.Close() })
	host, port, _ := net.SplitHostPort(srv.Addr())
	j, _ := json.Marshal(map[string]any{"hostName": host, "userName": "root", "password": guiAKPw, "port": port,
		"description": "Боевой", "dns1": "9.9.9.9", "dns2": "1.0.0.1", "defaultContainer": "amnezia-awg2"})
	key := "vpn://" + base64.RawURLEncoding.EncodeToString(j)
	kh := filepath.Join(core.DefaultVaultDir(), "known_hosts")
	creds, _ := core.CredsFromConfig(map[string]any{"hostName": host, "userName": "root", "password": guiAKPw, "port": port})
	warm, err := core.ConnectWithHostKey(creds, core.HostKeyPolicy{KnownHostsPath: kh, Prompt: func(string, string) bool { return true }})
	if err != nil {
		t.Fatal(err)
	}
	warm.Close()
	f.u.showConnectScreen("")
	btn, info := widget.NewButton("", nil), msgLabel("")
	f.u.attemptConnect(key, nil, btn, info)
	waitGUIGoroutines(t)
	if f.u.sess == nil || f.u.sess.Creds.Host != host {
		t.Fatalf("не подключились: %s", info.Text)
	}
	f.run(t, adminKeyOKFull)
	if f.written == "" {
		t.Fatal("ключ не выдан")
	}
	cfg, err := core.DecodeVpnKey(f.written)
	if err != nil {
		t.Fatal("ключ не разбирается")
	}
	got := strings.Join([]string{core.Str(cfg, "description"), core.Str(cfg, "dns1"), core.Str(cfg, "dns2"), core.Str(cfg, "defaultContainer")}, "|")
	if got != "Боевой|9.9.9.9|1.0.0.1|amnezia-awg2" {
		t.Fatalf("поля прежнего ключа не перенесены: %s", got)
	}
}

// nil Creds — отказ словами, без паники (ревью-2 PR #75, п. 1).
func TestGUIAdminKeyIssueNilCreds(t *testing.T) {
	s := core.NewSessionWithRunner(fakesrv.NewAWG2(), nil)
	k, lines := adminKeyIssue(s, core.AdminKeyReissue{}, adminKeyMeta{})
	if k.Len() != 0 || len(lines) == 0 || !strings.Contains(lines[0], "не выдан") {
		t.Fatalf("len=%d lines=%v", k.Len(), lines)
	}
}
