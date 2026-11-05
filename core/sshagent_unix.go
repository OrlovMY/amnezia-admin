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
	// Дедлайн на всё общение с агентом (список ключей и подписи во время
	// рукопожатия): зависший агент не вешает ConnectNew навсегда.
	_ = c.SetDeadline(time.Now().Add(agentTimeout))
	return agent.NewClient(c), c, nil
}
