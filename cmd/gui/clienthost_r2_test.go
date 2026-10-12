package main

import (
	"strings"
	"testing"

	"fyne.io/fyne/v2/test"

	"amnezia-admin/core"
)

// TestGUIClientHostRecheckSaved — З3 AU-LOGIC: имя из хранилища не
// применяется молча — перепроверка перед первой выдачей; совпало —
// строка «сохранено ранее» и дальше; не совпало / не удалось — окно, без
// «Использовать» конфиг не выдаётся.
func TestGUIClientHostRecheckSaved(t *testing.T) {
	res := resolverOf(map[string]string{"vpn.example.com": "203.0.113.5", "other.example.com": "198.51.100.7"})
	for _, tc := range []struct {
		name, host string
		ok         bool
		text       string
	}{
		{"совпало", "vpn.example.com", true, "сохранено ранее"},
		{"другой IP", "other.example.com", false, "НЕ на этот сервер"},
		{"не резолвится", "nx.example.com", false, "не удалось"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			u := clientHostUI(t, "203.0.113.5", res)
			u.applyClientHostSetting(u.sess, core.ClientHostSetting{Host: tc.host})
			opened := false
			u.ensureClientHost(func() { opened = true })
			if tc.ok {
				waitUntil(t, func() bool { return opened })
				if !strings.Contains(u.status.Text, tc.text) || u.clientHostRecheck {
					t.Errorf("статус %q", u.status.Text)
				}
				return
			}
			waitUntil(t, func() bool { return u.clientHostRecheckDl != nil })
			if opened || !strings.Contains(u.clientHostRecheckTx, tc.text) || !u.clientHostRecheck {
				t.Errorf("выдано без подтверждения: opened=%v %q", opened, u.clientHostRecheckTx)
			}
		})
	}
}

// TestGUIIPNoteEveryIssue — QA-01: при «Оставить IP» предупреждение
// дописывается к строке о КАЖДОЙ выдаче; с именем — нет.
func TestGUIIPNoteEveryIssue(t *testing.T) {
	u := clientHostUI(t, "203.0.113.5", nil)
	u.addDialog()
	test.Tap(u.clientHostShown.keepBt)
	for i := 0; i < 2; i++ {
		if st := u.withIPNote("Конфиг создан."); !strings.Contains(st, "придётся перевыпускать") {
			t.Errorf("выдача %d: %q", i, st)
		}
	}
	u.sess.ClientHost = "vpn.example.com"
	if st := u.withIPNote("Конфиг создан."); st != "Конфиг создан." {
		t.Errorf("%q", st)
	}
}

// TestGUIXRayShowConfigGated — З4: показ конфига XRay-клиента (собирается
// заново с текущим адресом) проходит те же ворота, что создание.
func TestGUIXRayShowConfigGated(t *testing.T) {
	u := clientHostUI(t, "203.0.113.5", nil)
	u.showXRayConfig(core.ClientEntry{ClientID: "id-1", UserData: map[string]any{"clientName": "Bob"}})
	if u.clientHostShown == nil {
		t.Fatal("окно выбора адреса не показано перед сборкой конфига XRay")
	}
}
