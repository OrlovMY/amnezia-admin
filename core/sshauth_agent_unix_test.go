//go:build !windows

package core

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// startTestAgent — ssh-agent в памяти на Unix-сокете во временном каталоге
// (короткий путь: на macOS предел длины пути сокета ~104 байта).
func startTestAgent(t *testing.T) (sock string, pub ssh.PublicKey) {
	return startTestAgentOpt(t, false)
}

// refusingAgent — агент, который ключи показывает, а подписывать отказывается.
type refusingAgent struct{ agent.Agent }

func (refusingAgent) Sign(ssh.PublicKey, []byte) (*ssh.Signature, error) {
	return nil, errors.New("агент отказал в подписи")
}

func startTestAgentOpt(t *testing.T, refuse bool) (sock string, pub ssh.PublicKey) {
	t.Helper()
	dir, err := os.MkdirTemp("", "ag")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock = filepath.Join(dir, "s")
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	kr := agent.NewKeyring()
	if err := kr.Add(agent.AddedKey{PrivateKey: priv}); err != nil {
		t.Fatal(err)
	}
	var serve agent.Agent = kr
	if refuse {
		serve = refusingAgent{kr}
	}
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); _ = agent.ServeAgent(serve, c) }()
		}
	}()
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return sock, s.PublicKey()
}

// TestConnectNewAgentKeyAccepted — ключ из агента (SSH_AUTH_SOCK) принят;
// каталог ключей пуст — вошли именно агентом.
func TestConnectNewAgentKeyAccepted(t *testing.T) {
	sock, pub := startTestAgent(t)
	t.Setenv("SSH_AUTH_SOCK", sock)
	srv := startFakeAuthServer(t, []ssh.PublicKey{pub}, "")
	sess, att, err := ConnectNew("127.0.0.1", srv.port, "root", AuthSource{KeyDir: t.TempDir()}, trustPolicy(t))
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Client.Close()
	if att.Outcome != KeysAccepted || len(att.Offered) != 1 || !strings.HasPrefix(att.Offered[0], "агент: ") {
		t.Fatalf("att = %#v, want KeysAccepted по ключу агента", att)
	}
}

// TestConnectNewAgentUnreachable — сокет указан, но агента нет: причина
// сообщается, исход — «ключей нет».
func TestConnectNewAgentUnreachable(t *testing.T) {
	srv := startFakeAuthServer(t, nil, sshPw)
	ps := &pwSource{pw: sshPw}
	sock := filepath.Join(t.TempDir(), "нет-сокета")
	sess, att, err := ConnectNew("127.0.0.1", srv.port, "root", AuthSource{KeyDir: t.TempDir(), AgentSocket: sock, Password: ps.fn}, trustPolicy(t))
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Client.Close()
	if att.Outcome != KeysUnavailable || !strings.Contains(strings.Join(ps.got.Notes, ";"), "агент: недоступен") {
		t.Fatalf("att = %#v, want KeysUnavailable с причиной «агент недоступен»", ps.got)
	}
}

// TestConnectNewAgentSignRefused — сервер ключ одобрил, агент не подписал:
// исход KeysSignFailed, не «сервер отверг ключи».
func TestConnectNewAgentSignRefused(t *testing.T) {
	sock, pub := startTestAgentOpt(t, true)
	t.Setenv("SSH_AUTH_SOCK", sock)
	srv := startFakeAuthServer(t, []ssh.PublicKey{pub}, sshPw)
	ps := &pwSource{pw: sshPw}
	sess, att, err := ConnectNew("127.0.0.1", srv.port, "root", AuthSource{KeyDir: t.TempDir(), Password: ps.fn}, trustPolicy(t))
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Client.Close()
	if att.Outcome != KeysSignFailed || ps.got.Outcome != KeysSignFailed {
		t.Fatalf("Outcome=%v (колбэк %v), want KeysSignFailed", att.Outcome, ps.got.Outcome)
	}
}
