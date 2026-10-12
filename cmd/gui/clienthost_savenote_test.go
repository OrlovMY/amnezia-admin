package main

import (
	"strings"
	"testing"

	"fyne.io/fyne/v2/test"
	"fyne.io/fyne/v2/widget"

	"amnezia-admin/core"
	"amnezia-admin/internal/fakesrv"
)

// TestGUISaveLineCarriesEndpoint — QA-01 круг 3: итоговая строка сохранения
// конфига (и «сохранён», и «НЕ сохранён») сохраняет прежний текст В НАЧАЛЕ
// и несёт адрес в конфиге: имя или предупреждение об IP.
func TestGUISaveLineCarriesEndpoint(t *testing.T) {
	for _, tc := range []struct {
		name, state, clientHost, prefix, note string
	}{
		{"сохранён, имя", "ok", "vpn.example.com", "Конфиг сохранён: ", "Адрес сервера в конфиге: vpn.example.com"},
		{"сохранён, IP", "ok", "", "Конфиг сохранён: ", "придётся перевыпускать"},
		{"не сохранён, имя", "fail", "vpn.example.com", "Конфиг НЕ сохранён", "Адрес сервера в конфиге: vpn.example.com"},
		{"не сохранён, IP", "fail", "", "Конфиг НЕ сохранён", "придётся перевыпускать"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.state == "ok" {
				configDirEnv(t)
			} else {
				t.Setenv("LOCALAPPDATA", "rel")
				t.Setenv("XDG_CONFIG_HOME", "rel")
				t.Setenv("HOME", "")
			}
			a := test.NewApp()
			t.Cleanup(a.Quit)
			w := test.NewWindow(nil)
			t.Cleanup(w.Close)
			sess := core.NewSessionWithRunner(fakesrv.New(), &core.ServerCreds{Host: "203.0.113.5", User: "root"})
			sess.ClientHost, sess.ClientHostDecided = tc.clientHost, true
			u := &ui{win: w, selectedRow: -1, status: widget.NewLabel(""), sess: sess}
			t.Cleanup(func() { waitGUIGoroutines(t) })
			u.showConfigDialog(&core.NewUser{Name: "Carol", Config: "[Interface]\nPrivateKey = x\n"}, "создан")
			waitGUIGoroutines(t)
			st := u.status.Text
			if !strings.HasPrefix(st, tc.prefix) || !strings.Contains(st, tc.note) {
				t.Errorf("строка %q: ждали начало %q и %q", st, tc.prefix, tc.note)
			}
			if tc.state == "ok" && !strings.Contains(st, "Carol") {
				t.Errorf("путь файла пропал: %q", st)
			}
		})
	}
}
