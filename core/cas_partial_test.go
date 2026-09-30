package core_test

// SEC F1 (раунд 2 ревью A3б PR-1): частичная запись и sudo-фолбэк. Только
// публичный API — файл компилируется на c77c12f и падает там поведением.

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"testing"

	"amnezia-admin/core"
	"amnezia-admin/internal/fakesrv"
)

// exitErr — ошибка с кодом выхода (форма ssh.ExitError: метод ExitStatus).
type exitErr struct {
	code int
	msg  string
}

func (e *exitErr) Error() string   { return e.msg }
func (e *exitErr) ExitStatus() int { return e.code }

// partialRunner — первая команда записи (со stdin, без sudo) «записывает»
// только wg0.conf (первая строка stdin), а второй mv падает с Permission
// denied — так выглядит частичная запись на сервере.
type partialRunner struct {
	srv  *fakesrv.Server
	code int
	done bool
}

func (r *partialRunner) Run(cmd string, stdin []byte) (string, error) {
	if stdin != nil && !r.done && !strings.HasPrefix(cmd, "sudo ") {
		r.done = true
		first := strings.SplitN(string(stdin), "\n", 2)[0]
		if wg, err := base64.StdEncoding.DecodeString(first); err == nil && first != "-" {
			r.srv.SetFile(raceContainer().Dir+"/wg0.conf", wg)
		}
		return "", &exitErr{code: r.code, msg: fmt.Sprintf("команда записи: exit status %d; stderr: mv: cannot move to clientsTable: Permission denied", r.code)}
	}
	return r.srv.Run(cmd, stdin)
}

// TestPartialWriteNotRetriedUnderSudo — после частичной записи (wg0.conf
// новый, clientsTable прежняя, «Permission denied» в stderr) ответ —
// «неизвестно, записано ли»: не успех и не «изменил другой». Код 1 — mv
// сообщил отказ, код 6 — скрипт сам сказал «частично». На c77c12f общий
// sudo-фолбэк повторял команду, повтор видел уже НАШ wg0.conf и отвечал
// «изменился».
func TestPartialWriteNotRetriedUnderSudo(t *testing.T) {
	for _, code := range []int{1, 6} {
		t.Run(fmt.Sprintf("код %d", code), func(t *testing.T) {
			srv := fakesrv.New()
			r := &partialRunner{srv: srv, code: code}
			_, err := core.NewSessionWithRunner(r, raceCreds()).AddUser(raceContainer(), "Carol")
			if err == nil {
				t.Fatal("частичная запись выдана за успех")
			}
			if errors.Is(err, core.ErrCASMismatch) {
				t.Errorf("частичная запись выдана за «изменил другой»: %v", err)
			}
			for _, cmd := range srv.Commands() {
				if strings.HasPrefix(cmd, "sudo ") {
					t.Errorf("после записи повтор под sudo недопустим: %.60q", cmd)
				}
			}
		})
	}
}
