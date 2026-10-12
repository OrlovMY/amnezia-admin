package main

import (
	"strings"
	"testing"

	"fyne.io/fyne/v2/test"
	"fyne.io/fyne/v2/widget"

	"amnezia-admin/core"
	"amnezia-admin/internal/fakesrv"
)

// TestGUIXRayShowConfigEndpointNote — QA-01: после показа конфига XRay в
// строке состояния — какой адрес в нём: имя или предупреждение об IP.
func TestGUIXRayShowConfigEndpointNote(t *testing.T) {
	for _, tc := range []struct {
		name, clientHost, want string
	}{
		{"имя", "vpn.example.com", "Адрес сервера в конфиге: vpn.example.com"},
		{"оставлен IP", "", "придётся перевыпускать"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := test.NewApp()
			t.Cleanup(a.Quit)
			w := test.NewWindow(nil)
			t.Cleanup(w.Close)
			t.Cleanup(core.SetXRayWaits(0, 0))
			sess := core.NewSessionWithRunner(fakesrv.NewXRay("master"), &core.ServerCreds{Host: "203.0.113.5", User: "root"})
			sess.ClientHost, sess.ClientHostDecided = tc.clientHost, true
			cs, err := sess.FindContainers()
			if err != nil {
				t.Fatal(err)
			}
			var cur *core.Container
			for i := range cs {
				if core.IsXRay(&cs[i]) {
					cur = &cs[i]
				}
			}
			if cur == nil {
				t.Fatal("нет XRay в стенде")
			}
			cls, err := sess.LoadClients(cur)
			if err != nil || len(cls) == 0 {
				t.Fatalf("клиенты: %v", err)
			}
			u := &ui{win: w, selectedRow: -1, status: widget.NewLabel(""), sess: sess, cur: cur}
			u.showXRayConfig(cls[0])
			waitUntil(t, func() bool { return strings.Contains(u.status.Text, tc.want) })
		})
	}
}
