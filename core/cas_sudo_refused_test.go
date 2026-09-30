package core_test

// Отказ sudo — «ничего не записано» (ErrSudoDenied). Отдельный файл: на
// 624fb24 этого исхода нет вовсе, а cas_sudo_test.go обязан собираться там.

import (
	"errors"
	"strings"
	"testing"

	"amnezia-admin/core"
	"amnezia-admin/internal/fakesrv"
)

// TestSudoRefusedIsNotWritten — sudo не разрешает даже docker: отказ sudo —
// «ничего не записано» (ErrSudoDenied), не «неизвестно, записано ли».
func TestSudoRefusedIsNotWritten(t *testing.T) {
	srv := fakesrv.New()
	r := &noSudoRunner{srv: srv}
	_, err := core.NewSessionWithRunner(r, raceCreds()).AddUser(raceContainer(), "Carol")
	if err == nil {
		t.Fatal("запись прошла без права на docker")
	}
	if !errors.Is(err, core.ErrSudoDenied) {
		t.Errorf("ждали ErrSudoDenied: %v", err)
	}
	if errors.Is(err, core.ErrWriteUnknown) {
		t.Errorf("отказ sudo выдан за «неизвестно, записано ли»: %v", err)
	}
	if userOnServer(t, srv, "Carol") {
		t.Errorf("Carol на сервере, хотя sudo отказал")
	}
}

// noSudoRunner — sudo запрещает всё (пароль требуется, -n), docker без sudo
// не пускает к сокету; чтение идёт по сокету через sudo docker тоже нельзя —
// поэтому чтения пропускаются как есть (модель: читать можно, писать нет).
type noSudoRunner struct{ srv *fakesrv.Server }

func (r *noSudoRunner) Run(cmd string, stdin []byte) (string, error) {
	if !strings.Contains(cmd, "flock") {
		return r.srv.Run(cmd, stdin)
	}
	if strings.Contains(cmd, "sudo") {
		return "", &exitErr{code: 1, msg: "команда: exit status 1; stderr: sudo: a password is required"}
	}
	return "", &exitErr{code: 1, msg: "команда: exit status 1; stderr: permission denied while trying to connect to the Docker daemon socket at unix:///var/run/docker.sock"}
}
