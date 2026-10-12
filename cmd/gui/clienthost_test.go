package main

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"fyne.io/fyne/v2/test"
	"fyne.io/fyne/v2/widget"

	"amnezia-admin/core"
	"amnezia-admin/internal/fakesrv"
)

func clientHostUI(t *testing.T, host string, res core.Resolver) *ui {
	t.Helper()
	a := test.NewApp()
	t.Cleanup(a.Quit)
	w := test.NewWindow(nil)
	t.Cleanup(w.Close)
	old := guiClientHostResolver
	guiClientHostResolver = res
	t.Cleanup(func() { guiClientHostResolver = old })
	u := &ui{win: w, selectedRow: -1, status: widget.NewLabel(""),
		sess: core.NewSessionWithRunner(fakesrv.New(), &core.ServerCreds{Host: host, User: "root"})}
	u.cur = &core.Container{Name: "amnezia-awg", Dir: "/opt/amnezia/awg", Proto: "AmneziaWG", Support: core.SupportYes}
	u.applyClientHostSetting(u.sess, core.ClientHostSetting{})
	return u
}

func resolverOf(m map[string]string) core.Resolver {
	return func(h string) ([]net.IP, error) {
		ip, ok := m[h]
		if !ok {
			return nil, errors.New("no such host")
		}
		return []net.IP{net.ParseIP(ip)}, nil
	}
}

func waitUntil(t *testing.T, cond func() bool) {
	t.Helper()
	for end := time.Now().Add(5 * time.Second); time.Now().Before(end); time.Sleep(10 * time.Millisecond) {
		if cond() {
			return
		}
	}
	t.Fatal("не дождались")
}

// TestGUIClientHostTable — окно выбора адреса перед созданием клиента:
// имя совпало / другой IP / не резолвится / оставить IP / имя в ключе.
func TestGUIClientHostTable(t *testing.T) {
	res := resolverOf(map[string]string{"vpn.example.com": "203.0.113.5", "other.example.com": "198.51.100.7"})
	t.Run("имя в ключе — окна нет, адрес из ключа", func(t *testing.T) {
		u := clientHostUI(t, "srv.example.com", res)
		u.addDialog()
		if u.clientHostShown != nil || u.clientHostAsk {
			t.Fatal("спросили при имени в ключе")
		}
		if u.sess.EndpointHost() != "srv.example.com" {
			t.Error(u.sess.EndpointHost())
		}
	})
	t.Run("сохранённый выбор из хранилища — окна нет", func(t *testing.T) {
		u := clientHostUI(t, "203.0.113.5", res)
		u.applyClientHostSetting(u.sess, core.ClientHostSetting{Host: "vpn.example.com"})
		u.addDialog()
		if u.clientHostShown != nil || u.sess.EndpointHost() != "vpn.example.com" {
			t.Fatal("сохранённое имя не применено")
		}
	})
	t.Run("имя совпало — конфиг с именем (доезд)", func(t *testing.T) {
		u := clientHostUI(t, "203.0.113.5", res)
		u.addDialog()
		v := u.clientHostShown
		if v == nil {
			t.Fatal("окна выбора нет при IP в ключе")
		}
		v.entry.SetText("vpn.example.com")
		test.Tap(v.checkBt)
		waitUntil(t, func() bool { return !u.clientHostAsk })
		if u.sess.ClientHost != "vpn.example.com" {
			t.Fatalf("ClientHost %q", u.sess.ClientHost)
		}
		nu, err := u.sess.AddUser(u.cur, "Carol")
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(nu.Config, "Endpoint = vpn.example.com:") || strings.Contains(nu.Config, "203.0.113.5") {
			t.Errorf("конфиг:\n%s", nu.Config)
		}
	})
	for _, tc := range []struct{ name, host, text string }{
		{"другой IP — не сохраняется без подтверждения", "other.example.com", "НЕ на этот сервер"},
		{"не резолвится — «не удалось», не ответ", "nx.example.com", "не удалось"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			u := clientHostUI(t, "203.0.113.5", res)
			u.addDialog()
			v := u.clientHostShown
			v.entry.SetText(tc.host)
			test.Tap(v.checkBt)
			waitUntil(t, func() bool { return v.confirm != nil })
			if !strings.Contains(v.text, tc.text) {
				t.Errorf("текст %q без %q", v.text, tc.text)
			}
			if u.sess.ClientHost != "" || !u.clientHostAsk {
				t.Errorf("имя принято без подтверждения: %q", u.sess.ClientHost)
			}
		})
	}
	t.Run("оставить IP — выбор запомнен, предупреждение", func(t *testing.T) {
		u := clientHostUI(t, "203.0.113.5", res)
		u.addDialog()
		test.Tap(u.clientHostShown.keepBt)
		if u.clientHostAsk || !u.clientHostSet.KeepIP || u.sess.EndpointHost() != "203.0.113.5" {
			t.Fatalf("ask=%v set=%+v", u.clientHostAsk, u.clientHostSet)
		}
		if !strings.Contains(u.status.Text, "придётся перевыпускать") {
			t.Errorf("нет предупреждения: %q", u.status.Text)
		}
		u.clientHostShown = nil
		u.addDialog()
		if u.clientHostShown != nil {
			t.Error("спросили повторно после «Оставить IP»")
		}
	})
}

// TestSaveClientHostToVault — выбор пишется внутрь .avlt; неверный пин
// файла не меняет (иначе файл перезапечатался бы чужим пином).
func TestSaveClientHostToVault(t *testing.T) {
	const pin = "Kx7#mQ2v9Lp44"
	data, err := core.SealVault(pin, core.VaultPayload{Label: "s", Key: "k"}, core.ArgonParams{MemoryKiB: 64, Time: 1, Threads: 1}, false)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "a.avlt")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := saveClientHostToVault(path, "wrong-pin-1", core.ClientHostSetting{Host: "vpn.example.com"}); err == nil {
		t.Fatal("неверный пин принят")
	}
	if got, _ := os.ReadFile(path); string(got) != string(data) {
		t.Fatal("файл изменён при неверном пине")
	}
	if err := saveClientHostToVault(path, pin, core.ClientHostSetting{Host: "vpn.example.com"}); err != nil {
		t.Fatal(err)
	}
	p, _, err := vaultDecrypt(path, pin)
	if err != nil || p.ClientHost != "vpn.example.com" || p.Key != "k" {
		t.Errorf("%+v %v", p.ClientHostSetting(), err)
	}
}
