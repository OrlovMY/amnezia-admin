package core

import (
	"bytes"
	"fmt"

	"golang.org/x/crypto/ssh"
)

// Runner выполняет одну команду на сервере и возвращает stdout.
// Реализации: sshRunner (боевая, поверх *ssh.Client) и internal/fakesrv.Server
// (фейковый сервер Amnezia в памяти для юнит-тестов — без сети, без диска,
// без реального SSH). Интерфейс структурный: internal/fakesrv не импортирует
// core (иначе был бы цикл импорта в тестах пакета core), фейку достаточно
// иметь метод Run с той же сигнатурой.
type Runner interface {
	Run(cmd string, stdin []byte) (string, error)
}

// sshRunner — боевая реализация Runner поверх установленного SSH-соединения.
// Тело — бывший Session.run (core.go, до выделения интерфейса Runner);
// текст ошибки не менялся.
type sshRunner struct {
	client *ssh.Client
}

func (r sshRunner) Run(cmd string, stdin []byte) (string, error) {
	sess, err := r.client.NewSession()
	if err != nil {
		return "", err
	}
	defer sess.Close()
	if stdin != nil {
		sess.Stdin = bytes.NewReader(stdin)
	}
	var out, errb bytes.Buffer
	sess.Stdout = &out
	sess.Stderr = &errb
	err = sess.Run(cmd)
	if err != nil {
		return out.String(), fmt.Errorf("команда %q: %w; stderr: %s", cmd, err, errb.String())
	}
	return out.String(), nil
}

// NewSessionWithRunner собирает Session вокруг произвольного Runner, минуя
// SSH. Нужен тестам пакета core (на internal/fakesrv.Server) и встроенному
// SSH-серверу (PR-4). Экспортирован намеренно — без него внешнему коду
// (в т.ч. тестам) нечем было бы подменить транспорт.
func NewSessionWithRunner(r Runner, creds *ServerCreds) *Session {
	return &Session{r: r, Creds: creds}
}
