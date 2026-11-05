package main

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"amnezia-admin/core"
)

type provCLIFake map[string]string // метка → stdout; нет метки — ошибка

func (f provCLIFake) Run(cmd string, _ []byte) (string, error) {
	for tag, o := range f {
		if strings.Contains(cmd, tag) {
			return o, nil
		}
	}
	return "", errors.New("обрыв связи")
}

func healthyProvCLI() provCLIFake {
	return provCLIFake{
		core.ProvOSTag:     "ID=debian\nVERSION_ID=12\nPRETTY=Debian 12\nEND\n",
		core.ProvKernelTag: "KERNEL=6.1.0-18-amd64\nARCH=x86_64\nEND\n",
		core.DiagHostTag:   "AA=none\nLOG=readable\nEND\n",
		core.ProvSudoTag:   "UID=0\nEND\n",
		core.ProvDockerTag: "DOCKER=no\nEND\n",
		core.ProvPortsTag:  "SSRC=0\nL=tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\nEND\n",
		core.ProvDiskTag:   "DFPATH=/\nDFRC=0\nDF=/dev/vda1 41152736 3000000 36000000 8% /\nEND\n",
	}
}

// Коды выхода доезжают из ядра: можно — 0, нельзя — 1, неизвестно — 4.
// «Неизвестно» отличается от «нельзя» и по коду, и по тексту.
func TestProvisionCheckExitCodes(t *testing.T) {
	cases := []struct {
		name string
		mod  func(provCLIFake)
		code int
		want string
	}{
		{"можно", func(provCLIFake) {}, 0, "Итог: можно ставить"},
		{"нельзя", func(f provCLIFake) { f[core.ProvPortsTag] = "SSRC=0\nL=tcp LISTEN 0 511 0.0.0.0:443 0.0.0.0:*\nEND\n" }, 1, "Итог: НЕЛЬЗЯ"},
		{"неизвестно: ss упал", func(f provCLIFake) { delete(f, core.ProvPortsTag) }, 4, "Итог: неизвестно"},
		{"неизвестно: os пусто", func(f provCLIFake) { f[core.ProvOSTag] = "" }, 4, "узнать не удалось"},
	}
	for _, c := range cases {
		f := healthyProvCLI()
		c.mod(f)
		var out bytes.Buffer
		code := runProvisionCheck(&out, core.NewSessionWithRunner(f, &core.ServerCreds{User: "root", Host: "203.0.113.5", Port: "22"}))
		if code != c.code || !strings.Contains(out.String(), c.want) {
			t.Errorf("%s: код %d (ждали %d), вывод:\n%s", c.name, code, c.code, out.String())
		}
	}
}

func TestProvisionCheckUsage(t *testing.T) {
	t.Setenv("AMNEZIA_KEY", "")
	t.Setenv("AMNEZIA_TO_KEY", "")
	var o, e bytes.Buffer
	if code := run([]string{"provision-check"}, strings.NewReader(""), &o, &e, t.TempDir()+"/kh"); code != 2 {
		t.Fatalf("без ключа: код %d, %s", code, e.String())
	}
	e.Reset()
	if code := run([]string{"provision-check", "-key", "vpn://a", "-to-key", "vpn://b"}, strings.NewReader(""), &o, &e, t.TempDir()+"/kh"); code != 2 {
		t.Fatalf("два разных ключа: код %d", code)
	}
	e.Reset()
	if code := run([]string{"provision-check", "-to-key", "vpn://мусор"}, strings.NewReader(""), &o, &e, t.TempDir()+"/kh"); code != 2 {
		t.Fatalf("ключ не разобран: код %d, %s", code, e.String())
	}
	if strings.Contains(e.String(), "мусор") {
		t.Fatalf("ключ попал в текст ошибки: %s", e.String())
	}
}
