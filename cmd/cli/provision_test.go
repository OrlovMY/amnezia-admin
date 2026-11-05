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

// H1: ошибка флагов у provision-check — код 2, не 1 («нельзя»).
func TestProvisionCheckBadFlagExit2(t *testing.T) {
	var o, e bytes.Buffer
	for _, args := range [][]string{
		{"provision-check", "-to-key", "vpn://x", "-tohostkey", "SHA256:x"},
		{"provision-check", "-no-such-flag"},
	} {
		if code := run(args, strings.NewReader(""), &o, &e, t.TempDir()+"/kh"); code != 2 {
			t.Errorf("%v: код %d, ждали 2", args, code)
		}
	}
}

// L1: выбор ключа — явный флаг главнее окружения.
func TestProvKeysPick(t *testing.T) {
	cases := []struct {
		k        provKeys
		key      string
		from     string
		conflict bool
	}{
		{provKeys{flagToKey: "T", envKey: "A", envToKey: "B"}, "T", "-to-key", false},
		{provKeys{flagKey: "K", envKey: "A", envToKey: "B"}, "K", "-key", false},
		{provKeys{envKey: "A", envToKey: "B"}, "B", "AMNEZIA_TO_KEY", false},
		{provKeys{envKey: "A"}, "A", "AMNEZIA_KEY", false},
		{provKeys{flagKey: "K", flagToKey: "T"}, "", "", true},
		{provKeys{flagKey: "K", flagToKey: "K"}, "K", "-to-key", false},
		{provKeys{}, "", "", false},
	}
	for i, c := range cases {
		k, from, conf := c.k.pick()
		if k != c.key || from != c.from || conf != c.conflict {
			t.Errorf("%d: %q %q %v, ждали %q %q %v", i, k, from, conf, c.key, c.from, c.conflict)
		}
	}
}

// L1 доезд: разные AMNEZIA_KEY и AMNEZIA_TO_KEY + явный -to-key — не ошибка
// «два ключа», берётся -to-key.
func TestProvisionCheckExplicitToKeyBeatsEnv(t *testing.T) {
	t.Setenv("AMNEZIA_KEY", "vpn://env-a")
	t.Setenv("AMNEZIA_TO_KEY", "vpn://env-b")
	var o, e bytes.Buffer
	run([]string{"provision-check", "-to-key", "vpn://explicit"}, strings.NewReader(""), &o, &e, t.TempDir()+"/kh")
	if strings.Contains(e.String(), "разными ключами") {
		t.Fatalf("переменные окружения выданы за конфликт флагов: %s", e.String())
	}
	if !strings.Contains(o.String(), "взят из -to-key") {
		t.Fatalf("ключ не из -to-key: %s", o.String())
	}
}

// L2: список команд — до ключа и с migrate/provision-check.
func TestCLICommandListBeforeKey(t *testing.T) {
	t.Setenv("AMNEZIA_KEY", "")
	var o, e bytes.Buffer
	if code := run([]string{"frobnicate"}, strings.NewReader(""), &o, &e, t.TempDir()+"/kh"); code != 1 {
		t.Fatalf("неизвестная команда: код %d", code)
	}
	for _, want := range []string{"неизвестная команда", "migrate", "provision-check"} {
		if !strings.Contains(e.String(), want) {
			t.Errorf("нет %q: %s", want, e.String())
		}
	}
	o.Reset()
	if code := run([]string{"help"}, strings.NewReader(""), &o, &e, t.TempDir()+"/kh"); code != 0 || !strings.Contains(o.String(), "provision-check") {
		t.Fatalf("help: код %d, %s", code, o.String())
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
