//go:build windows

package core

import (
	"io"

	"golang.org/x/crypto/ssh/agent"
)

// dialAgent — на Windows OpenSSH-агент слушает named pipe
// \\.\pipe\openssh-ssh-agent; для него нужна go-winio, которую по решению
// не добавляем. Честный отказ, а не молчание: причина попадёт в
// KeyAttempt.Notes.
func dialAgent(string) (agent.ExtendedAgent, io.Closer, error) {
	return nil, nil, ErrAgentUnsupported
}
