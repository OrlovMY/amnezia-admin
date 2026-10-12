package main

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"

	"amnezia-admin/core"
)

// TestCLIBackupIssuedAddress — QA-01 Major доездом: копия, снятая CLI,
// записывает адрес выдачи по выбору: без выбора при IP в ключе —
// «неизвестен», с -client-host — имя, с keep-ip — IP.
func TestCLIBackupIssuedAddress(t *testing.T) {
	stubClientHost(t)
	t.Setenv("AMNEZIA_CLIENT_HOST", "")
	cliConfigsEnv(t)
	key, kh, _ := setupFakeSSHForRunWithExec(t)
	for _, tc := range []struct {
		name  string
		args  []string
		kind  string
		value string
	}{
		{"без выбора", nil, core.AddressKindUnknown, ""},
		{"имя", []string{"-client-host", "vpn.example.com"}, core.AddressKindName, "vpn.example.com"},
		{"keep-ip", []string{"-client-host", "keep-ip"}, core.AddressKindIP, "127.0.0.1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "c.aabk")
			var o, e bytes.Buffer
			args := append([]string{"backup", "-key", key, "-o", p, "-no-password"}, tc.args...)
			if code := run(args, strings.NewReader(""), &o, &e, kh); code != 0 {
				t.Fatalf("%d %s", code, e.String())
			}
			b, err := core.ReadBackupFile(p, core.PlainLayer{})
			if err != nil {
				t.Fatal(err)
			}
			if b.IssuedAddress.Kind != tc.kind || b.IssuedAddress.Value != tc.value {
				t.Errorf("%+v", b.IssuedAddress)
			}
		})
	}
}
