package core

// Раунд 2 ревью A3б PR-1: SEC F1 (частичная запись и sudo), F2 (имя файла
// при коде 3), QA — fakesrv исполняет настоящий скрипт, имена временных
// файлов — часть протокола.

import (
	"bytes"
	"strings"
	"testing"

	"amnezia-admin/internal/fakesrv"
)

// TestFakesrvRunsRealScript — канарейка QA (седьмая ступень): fakesrv обязан
// ИСПОЛНЯТЬ скрипт из команды, а не моделировать его. Скрипт, подменённый на
// `exit 42`, обязан дать код 42.
func TestFakesrvRunsRealScript(t *testing.T) {
	srv := fakesrv.New()
	c := awgContainer()
	cmd, err := CASWriteCommand(CASLabelApply, c.Name, c.Dir, "wg0.conf", strings.Repeat("0", 64), CASAbsent)
	if err != nil {
		t.Fatal(err)
	}
	cmd = strings.Replace(cmd, CASWriteScript, "exit 42", 1)
	_, err = srv.Run(cmd, CASWriteStdin(nil, []byte("[]")))
	outcome, code := casOutcomeOf(err)
	if code != 42 || outcome != casUnknown {
		t.Fatalf("fakesrv не исполнил скрипт из команды: код %d, err %v", code, err)
	}
}

// TestPartialWriteRealScript — SEC F1, доезд настоящим скриптом: mv на
// clientsTable падает с Permission denied → скрипт выходит кодом 6, ядро
// отвечает «неизвестно» (записано частично), не «изменил другой», без повтора
// под sudo; wg0.conf на сервере уже новый.
func TestPartialWriteRealScript(t *testing.T) {
	srv := fakesrv.New()
	srv.FailMvTo = "clientsTable"
	sess := NewSessionWithRunner(srv, testCreds())
	c := awgContainer()
	plan, err := sess.PlanAddUser(c, "Carol")
	if err != nil {
		t.Fatal(err)
	}
	_, err = sess.Apply(plan)
	assertOnly(t, err, ErrWriteUnknown)
	if !strings.Contains(err.Error(), "записано частично") {
		t.Errorf("текст не говорит о частичной записи: %v", err)
	}
	for _, cmd := range srv.Commands() {
		if strings.Contains(cmd, "sudo ") {
			t.Errorf("повтор под sudo после записи: %.60q", cmd)
		}
	}
	wg, _ := srv.File(c.Dir + "/wg0.conf")
	tbl, _ := srv.File(c.Dir + "/clientsTable")
	if !bytes.Equal(wg, plan.wgAfter) || !bytes.Equal(tbl, plan.tblBefore) {
		t.Error("ждали: wg0.conf новый, clientsTable прежняя")
	}
	if srv.TempLeft != 0 {
		t.Errorf("скрипт оставил временных файлов: %d", srv.TempLeft)
	}
}

// TestChangedFileNamedOnlyWhenKnown — SEC F2: при коде 3 файл называется,
// только если скрипт его назвал; иначе — «wg0.conf или clientsTable».
func TestChangedFileNamedOnlyWhenKnown(t *testing.T) {
	for _, tc := range []struct{ stderr, want string }{
		{"changed: clientsTable", "/opt/amnezia/awg/clientsTable изменился"},
		{"changed: wg0.conf", "/opt/amnezia/awg/wg0.conf изменился"},
		{"", "/opt/amnezia/awg/wg0.conf или clientsTable изменился"},
	} {
		t.Run("stderr="+tc.stderr, func(t *testing.T) {
			r := stubRunner{base: fakesrv.New(), match: "flock -w 15",
				err: &fakesrv.ExitError{Cmd: "x", Status: 3, Stderr: tc.stderr}}
			_, err := NewSessionWithRunner(r, testCreds()).AddUser(awgContainer(), "Carol")
			assertOnly(t, err, ErrCASMismatch)
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("ждали %q: %v", tc.want, err)
			}
		})
	}
}

// TestDeniedBeforeWriteRetriesUnderSudo — sudo-фолбэк записи сохранён там,
// где записи точно не было: docker не пустил к своему сокету.
func TestDeniedBeforeWriteRetriesUnderSudo(t *testing.T) {
	r := &denyDockerOnce{base: fakesrv.New()}
	if _, err := NewSessionWithRunner(r, testCreds()).AddUser(awgContainer(), "Carol"); err != nil {
		t.Fatalf("AddUser: %v", err)
	}
	if r.sudoWrites != 1 {
		t.Errorf("повторов записи под sudo: %d, ждали ровно 1", r.sudoWrites)
	}
}

type denyDockerOnce struct {
	base       *fakesrv.Server
	denied     bool
	sudoWrites int
}

func (r *denyDockerOnce) Run(cmd string, stdin []byte) (string, error) {
	if isCASWriteCmd(cmd) {
		if strings.Contains(cmd, " env LC_ALL=C sudo -n docker exec ") {
			r.sudoWrites++
			return r.base.Run(cmd, stdin)
		}
		if !r.denied {
			r.denied = true
			return "", &fakesrv.ExitError{Cmd: "x", Status: 1,
				Stderr: "permission denied while trying to connect to the Docker daemon socket at unix:///var/run/docker.sock"}
		}
	}
	return r.base.Run(cmd, stdin)
}

// TestCASTempInfixIsProtocol — QA: имена временных файлов — часть протокола.
func TestCASTempInfixIsProtocol(t *testing.T) {
	for _, want := range []string{
		`"$d/$cf` + CASTempInfix + `$$"`, `"$d/clientsTable` + CASTempInfix + `$$"`,
		`"$d/$cf"` + CASTempInfix + `*`, `"$d"/clientsTable` + CASTempInfix + `*`,
	} {
		if !strings.Contains(CASWriteScript, want) {
			t.Errorf("скрипт не использует имя временного файла по протоколу: %s", want)
		}
	}
}
