package main

import (
	"strings"
	"testing"

	"amnezia-admin/core"
	"amnezia-admin/internal/fakesrv"
)

// TestW2PrintContainersThreeStates — PR-W2, CLI: список протоколов сервера
// (меню «Установленные протоколы») в трёх состояниях; контейнеры — из
// настоящего FindContainers по выводу docker ps fakesrv. Порядок —
// фиксированный, а не порядок docker.
func TestW2PrintContainersThreeStates(t *testing.T) {
	srv := fakesrv.New()
	srv.Names = []string{"amnezia-foo", "amnezia-xray", "nginx", "amnezia-awg"}
	sess := core.NewSessionWithRunner(srv, &core.ServerCreds{Host: "203.0.113.10", User: "root", Password: "x"})
	cs, err := sess.FindContainers()
	if err != nil {
		t.Fatal(err)
	}
	out := captureStdout(t, func() { printContainers(cs, true) })
	lines := strings.Split(strings.TrimSpace(stripANSI(out)), "\n")
	want := []string{
		"1. AmneziaWG (старый) [amnezia-awg]",
		"2. XRay — только просмотр: не удалось прочитать server.json [amnezia-xray]", // AL-01: причина экземпляра
		"3. незнакомый контейнер amnezia-foo [amnezia-foo]",
	}
	if len(lines) != len(want) {
		t.Fatalf("строк %d, ожидалось %d:\n%s", len(lines), len(want), out)
	}
	for i, w := range want {
		if strings.TrimSpace(lines[i]) != w {
			t.Errorf("строка %d: %q, ожидалось %q", i+1, strings.TrimSpace(lines[i]), w)
		}
	}
	if strings.Contains(out, "nginx") {
		t.Error("чужой контейнер показан")
	}
}

func stripANSI(s string) string {
	var b strings.Builder
	esc := false
	for _, r := range s {
		switch {
		case r == 0x1b:
			esc = true
		case esc && r == 'm':
			esc = false
		case !esc:
			b.WriteRune(r)
		}
	}
	return b.String()
}
