package main

import (
	"strings"
	"testing"

	"amnezia-admin/core"
	"amnezia-admin/internal/fakesrv"
)

// TestAWG2NoteInConfigDialog — ДОЕЗД строки честности в окно «Конфиг
// готов»: клиент создан на amnezia-awg2 настоящим путём; на amnezia-awg
// строки нет.
func TestAWG2NoteInConfigDialog(t *testing.T) {
	for _, c := range []struct {
		name string
		srv  *fakesrv.Server
		ct   core.Container
		want bool
	}{
		{"awg2", fakesrv.NewAWG2(), core.Container{Name: "amnezia-awg2", Dir: "/opt/amnezia/awg", Proto: "AmneziaWG 2", Managed: true}, true},
		{"awg", fakesrv.New(), core.Container{Name: "amnezia-awg", Dir: "/opt/amnezia/awg", Proto: "AmneziaWG", Managed: true}, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			u := testUI(t)
			configsEnv(t)
			sess := core.NewSessionWithRunner(c.srv, &core.ServerCreds{Host: "203.0.113.10", User: "root", Password: "x"})
			nu, err := sess.AddUser(&c.ct, "Carol")
			if err != nil {
				t.Fatalf("AddUser: %v", err)
			}
			u.showConfigDialog(nu, "создан")
			txt := popupText(t, u)
			if got := strings.Contains(txt, "Параметры маскировки взяты из файла сервера"); got != c.want {
				t.Errorf("строка честности видна=%v, ждали %v: %s", got, c.want, txt)
			}
			u.win.Canvas().Overlays().Top().Hide()
		})
	}
}
