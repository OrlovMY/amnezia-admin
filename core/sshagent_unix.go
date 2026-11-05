//go:build !windows

package core

import (
	"errors"
	"io"
	"net"
	"time"

	"golang.org/x/crypto/ssh/agent"
)

// agentTimeout — предел на общение с агентом; переменная — шов для тестов.
var agentTimeout = 30 * time.Second

// dialAgent — соединение с ssh-agent по Unix-сокету sock.
func dialAgent(sock string) (agent.ExtendedAgent, io.Closer, error) {
	if sock == "" {
		return nil, nil, errors.New("SSH_AUTH_SOCK не задан")
	}
	c, err := net.DialTimeout("unix", sock, agentTimeout)
	if err != nil {
		return nil, nil, errors.New("недоступен: " + err.Error())
	}
	// Дедлайн — на КАЖДУЮ операцию с агентом (список ключей, каждая
	// подпись), а не от момента подключения: зависший агент не вешает
	// ConnectNew, а долгое рукопожатие не исчерпывает общий срок.
	dc := deadlineConn{c}
	return agent.NewClient(dc), c, nil
}

type deadlineConn struct{ net.Conn }

func (d deadlineConn) Read(b []byte) (int, error) {
	_ = d.Conn.SetDeadline(time.Now().Add(agentTimeout))
	return d.Conn.Read(b)
}

func (d deadlineConn) Write(b []byte) (int, error) {
	_ = d.Conn.SetDeadline(time.Now().Add(agentTimeout))
	return d.Conn.Write(b)
}
