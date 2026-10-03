package core_test

// AU-LOGIC PR-4, H1: повтор записи под sudo при sudoers «только docker».
// Только публичный API — файл компилируется на 624fb24 и падает там
// поведением. sudoersRunner — модель sudo поверх fakesrv: sudo сверяет с
// sudoers ПЕРВУЮ программу после себя (и после флагов вида -n); разрешён
// только docker. Без sudo docker не пускает к своему сокету.

import (
	"fmt"
	"strings"
	"testing"

	"amnezia-admin/core"
	"amnezia-admin/internal/fakesrv"
)

type sudoersRunner struct {
	srv      *fakesrv.Server
	sudoRuns []string // первые программы под sudo
}

// progAfterSudo — первая программа после `sudo` и его флагов.
func progAfterSudo(words []string) string {
	for _, w := range words {
		if !strings.HasPrefix(w, "-") {
			return w
		}
	}
	return ""
}

func (r *sudoersRunner) Run(cmd string, stdin []byte) (string, error) {
	words := strings.Fields(cmd)
	// sudo где угодно в цепочке (перед timeout или внутри flock) — сверка.
	for i, w := range words {
		if w != "sudo" {
			continue
		}
		prog := progAfterSudo(words[i+1:])
		r.sudoRuns = append(r.sudoRuns, prog)
		if prog != "docker" {
			return "", &exitErr{code: 1, msg: fmt.Sprintf("команда: exit status 1; stderr: Sorry, user admin is not allowed to execute '/usr/bin/%s' as root on host.", prog)}
		}
		// разрешено: sudo исполняет docker от root — сокет доступен
		return r.srv.Run(cmd, stdin)
	}
	// без sudo: любой docker — отказ сокета
	for _, w := range words {
		if w == "docker" {
			return "", &exitErr{code: 1, msg: "команда: exit status 1; stderr: permission denied while trying to connect to the Docker daemon socket at unix:///var/run/docker.sock"}
		}
	}
	return r.srv.Run(cmd, stdin)
}

// TestSudoDockerOnlyCanWrite — пользователь с `NOPASSWD: docker` пишет, как в
// v0.2.0: повтор под sudo начинается с docker, а не с timeout.
func TestSudoDockerOnlyCanWrite(t *testing.T) {
	srv := fakesrv.New()
	r := &sudoersRunner{srv: srv}
	sess := core.NewSessionWithRunner(r, raceCreds())
	if _, err := sess.AddUser(raceContainer(), "Carol"); err != nil {
		t.Fatalf("AddUser при sudoers «только docker»: %v (программы под sudo: %v)", err, r.sudoRuns)
	}
	if !userOnServer(t, srv, "Carol") {
		t.Errorf("сказано «готово», но Carol на сервере нет")
	}
	for _, p := range r.sudoRuns {
		if p != "docker" {
			t.Errorf("под sudo запущено %q — sudoers «только docker» это запрещает", p)
		}
	}
}
