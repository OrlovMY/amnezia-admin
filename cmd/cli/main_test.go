package main

import (
	"bytes"
	"strings"
	"testing"

	"amnezia-admin/core"
	"amnezia-admin/internal/fakesrv"
)

// TestDryRunFlagPrintsDiffAndWritesNothing — Е4: план собирается на fakesrv
// через core.NewSessionWithRunner (без сети и без реального SSH), а вывод
// -dry-run — это ровно printPlan (та же функция, что main() вызывает в
// ветках add/del/rename/toggle/rekey при -dry-run). Доказывает две вещи:
// (1) вывод содержит diff по обоим файлам в заявленном формате
// ("--- <path> (было)" / "+++ <path> (станет)"); (2) само построение плана
// (PlanAddUser) не посылает на сервер ни одной команды записи/sync/backup —
// dry-run только читает.
func TestDryRunFlagPrintsDiffAndWritesNothing(t *testing.T) {
	srv := fakesrv.New()
	sess := core.NewSessionWithRunner(srv, &core.ServerCreds{Host: "1.2.3.4", User: "root", Password: "x"})
	c := &core.Container{Name: "amnezia-awg", Dir: "/opt/amnezia/awg", Proto: "AmneziaWG", Managed: true}

	plan, err := sess.PlanAddUser(c, "Канарейка")
	if err != nil {
		t.Fatalf("PlanAddUser: %v", err)
	}

	var buf bytes.Buffer
	printPlan(&buf, plan)
	out := buf.String()

	for _, want := range []string{
		"--- /opt/amnezia/awg/wg0.conf (было)",
		"+++ /opt/amnezia/awg/wg0.conf (станет)",
		"--- /opt/amnezia/awg/clientsTable (было)",
		"+++ /opt/amnezia/awg/clientsTable (станет)",
		"+PublicKey",
		"+AllowedIPs",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("вывод printPlan не содержит %q; got:\n%s", want, out)
		}
	}

	for _, cmd := range srv.Commands() {
		if strings.Contains(cmd, "cat > ") {
			t.Errorf("PlanAddUser не должен писать: %q", cmd)
		}
		if strings.Contains(cmd, "syncconf") {
			t.Errorf("PlanAddUser не должен вызывать syncconf: %q", cmd)
		}
		if strings.Contains(cmd, "backup") {
			t.Errorf("PlanAddUser не должен делать backup: %q", cmd)
		}
	}
}

// TestPrintPlanNoChangeShowsNote — RenameUser не меняет wg0.conf (Г1):
// printPlan обязан явно показать "(без изменений)", а не пустой diff,
// который легко принять за "функция ничего не вывела/сломалась".
func TestPrintPlanNoChangeShowsNote(t *testing.T) {
	srv := fakesrv.New()
	sess := core.NewSessionWithRunner(srv, &core.ServerCreds{Host: "1.2.3.4", User: "root", Password: "x"})
	c := &core.Container{Name: "amnezia-awg", Dir: "/opt/amnezia/awg", Proto: "AmneziaWG", Managed: true}

	clients, err := sess.LoadClients(c)
	if err != nil {
		t.Fatalf("LoadClients: %v", err)
	}
	if len(clients) == 0 {
		t.Fatal("fakesrv.New() должен дать хотя бы одного клиента")
	}

	plan, err := sess.PlanRename(c, clients[0].ClientID, "Новое Имя")
	if err != nil {
		t.Fatalf("PlanRename: %v", err)
	}

	var buf bytes.Buffer
	printPlan(&buf, plan)
	out := buf.String()

	if !strings.Contains(out, "--- /opt/amnezia/awg/wg0.conf (было)\n+++ /opt/amnezia/awg/wg0.conf (станет)\n(без изменений)\n") {
		t.Errorf("printPlan не отметил wg0.conf как неизменённый при rename; got:\n%s", out)
	}
	if !strings.Contains(out, "+Новое Имя") && !strings.Contains(out, "Новое Имя") {
		t.Errorf("printPlan не показал новое имя в diff clientsTable; got:\n%s", out)
	}
}
