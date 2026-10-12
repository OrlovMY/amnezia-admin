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
	// последним — значит, первым при очистке: ни одна фоновая операция не
	// переживает тест (иначе её fyne.Do гоняется со следующим тестом)
	t.Cleanup(func() { waitGUIGoroutines(t) })
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

// waitUntil — дождаться ВСЕХ фоновых операций goSafe (тестовый драйвер Fyne
// исполняет fyne.Do прямо в фоновой goroutine, см. guiGoroutines), затем
// проверить условие один раз. Опрос по времени давал гонку под -race.
func waitUntil(t *testing.T, cond func() bool) {
	t.Helper()
	waitGUIGoroutines(t)
	if !cond() {
		t.Fatal("после завершения фоновых операций условие не выполнено")
	}
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
		waitGUIGoroutines(t) // перепроверка сохранённого имени идёт в фоне (З3)
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
	path := stubPinThrottle(t, data)
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

// stubPinThrottle — хранилище во временном каталоге pinVaultDir (там же
// throttle.json) и фиксированное онлайн-время.
func stubPinThrottle(t *testing.T, data []byte) string {
	t.Helper()
	dir := t.TempDir()
	oldDir, oldNow := pinVaultDir, clientHostNow
	t.Cleanup(func() { pinVaultDir, clientHostNow = oldDir, oldNow })
	pinVaultDir = func() string { return dir }
	now := time.Date(2026, 10, 12, 12, 0, 0, 0, time.UTC)
	clientHostNow = func() (time.Time, error) { return now, nil }
	path := filepath.Join(dir, "a.avlt")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestSaveClientHostPinThrottled — SEC-01 по PR #50: второй диалог пина
// (запомнить адрес для клиентов) идёт под тем же счётчиком, что основной:
// после 10 неверных пинов ввод закрыт — даже ВЕРНЫЙ пин не расшифровывает
// файл, и расшифровка не вызывается вовсе; счётчик — тот же throttle.json.
func TestSaveClientHostPinThrottled(t *testing.T) {
	const pin = "Kx7#mQ2v9Lp44"
	data, err := core.SealVault(pin, core.VaultPayload{Label: "s", Key: "k"}, core.ArgonParams{MemoryKiB: 64, Time: 1, Threads: 1}, false)
	if err != nil {
		t.Fatal(err)
	}
	path := stubPinThrottle(t, data)
	calls := 0
	old := vaultDecrypt
	t.Cleanup(func() { vaultDecrypt = old })
	vaultDecrypt = func(p, pn string) (core.VaultPayload, core.VaultInfo, error) {
		calls++
		return old(p, pn)
	}
	set := core.ClientHostSetting{Host: "vpn.example.com"}
	for i := 1; i <= 10; i++ {
		if err := saveClientHostToVault(path, "wrong-pin-1", set); err == nil {
			t.Fatal("неверный пин принят")
		} else if i == 9 && !strings.Contains(err.Error(), "Осталось попыток: 1") {
			t.Errorf("попытка 9: %v", err)
		}
	}
	st, err := core.LoadThrottle(pinVaultDir(), "a.avlt")
	if err != nil || st.BlockedUntil.IsZero() {
		t.Fatalf("счётчик основного ввода не увеличен: %+v %v", st, err)
	}
	before := calls
	err = saveClientHostToVault(path, pin, set)
	if err == nil || !strings.Contains(err.Error(), "заблокирован") || calls != before {
		t.Fatalf("после 10 неверных верный пин прошёл: err=%v расшифровок=%d", err, calls-before)
	}
	if got, _ := os.ReadFile(path); string(got) != string(data) {
		t.Fatal("файл изменён")
	}
}
