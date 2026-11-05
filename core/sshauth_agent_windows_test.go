//go:build windows

package core

import (
	"strings"
	"testing"
)

// TestConnectNewAgentUnsupportedWindows — на Windows агент не
// поддерживается, и об этом сказано в причинах, а не промолчано.
func TestConnectNewAgentUnsupportedWindows(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", `\\.\pipe\openssh-ssh-agent`)
	srv := startFakeAuthServer(t, nil, sshPw)
	ps := &pwSource{pw: sshPw}
	sess, att, err := ConnectNew("127.0.0.1", srv.port, "root", AuthSource{KeyDir: t.TempDir(), Password: ps.fn}, trustPolicy(t))
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Client.Close()
	if att.Outcome != KeysUnavailable || !strings.Contains(strings.Join(ps.got.Notes, ";"), ErrAgentUnsupported.Error()) {
		t.Fatalf("got %#v, want KeysUnavailable с «агент не поддерживается»", ps.got)
	}
}
