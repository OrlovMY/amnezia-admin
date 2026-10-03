package main

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"

	"amnezia-admin/core"
	"amnezia-admin/internal/fakesrv"
)

// TestAWG2NotePrinted — ДОЕЗД строки честности в CLI: пользователь создан
// на amnezia-awg2 настоящим путём (fakesrv), при сохранении конфига строка
// «параметры взяты из файла сервера» напечатана; на amnezia-awg — нет.
func TestAWG2NotePrinted(t *testing.T) {
	for _, c := range []struct {
		name string
		srv  *fakesrv.Server
		ct   core.Container
		want bool
	}{
		{"awg2", fakesrv.NewAWG2(), core.Container{Name: "amnezia-awg2", Dir: "/opt/amnezia/awg", Proto: "AmneziaWG (версия 2)", Support: core.SupportYes}, true},
		{"awg", fakesrv.New(), core.Container{Name: "amnezia-awg", Dir: "/opt/amnezia/awg", Proto: "AmneziaWG (старый)", Support: core.SupportYes}, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			sess := core.NewSessionWithRunner(c.srv, &core.ServerCreds{Host: "203.0.113.10", User: "root", Password: "x"})
			u, err := sess.AddUser(&c.ct, "Carol")
			if err != nil {
				t.Fatalf("AddUser: %v", err)
			}
			var buf bytes.Buffer
			if err := saveUserConfigTo(&buf, filepath.Join(t.TempDir(), "k"), u, c.ct.Proto); err != nil {
				t.Fatal(err)
			}
			got := strings.Contains(buf.String(), "Параметры маскировки взяты из файла сервера")
			if got != c.want {
				t.Errorf("строка честности напечатана=%v, ждали %v. Вывод:\n%s", got, c.want, buf.String())
			}
		})
	}
}
