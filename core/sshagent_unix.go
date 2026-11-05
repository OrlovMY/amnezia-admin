//go:build !windows

package core

import (
	"errors"
	"io"
	"net"

	"golang.org/x/crypto/ssh/agent"
)

// dialAgent — соединение с ssh-agent по Unix-сокету sock.
func dialAgent(sock string) (agent.ExtendedAgent, io.Closer, error) {
	if sock == "" {
		return nil, nil, errors.New("SSH_AUTH_SOCK не задан")
	}
	c, err := net.Dial("unix", sock)
	if err != nil {
		return nil, nil, errors.New("недоступен: " + err.Error())
	}
	return agent.NewClient(c), c, nil
}
