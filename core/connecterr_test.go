package core

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// Табличный тест различения: каждый вид — по своему признаку, и случай «нет
// признака» обязан остаться ConnectUnknown, а не стать одним из известных.
func TestClassifyConnectError(t *testing.T) {
	authErr := fmt.Errorf("ssh: handshake failed: %w",
		errors.New("ssh: unable to authenticate, attempted methods [none password], no supported methods remain"))
	changed := fmt.Errorf("ssh: handshake failed: %w",
		newHostKeyError(ErrHostKeyChanged, "h", "SHA256:a", "SHA256:b", "x"))
	mismatch := fmt.Errorf("ssh: handshake failed: %w",
		newHostKeyError(ErrHostKeyMismatch, "h", "SHA256:a", "SHA256:b", "x"))
	unknownHost := fmt.Errorf("ssh: handshake failed: %w",
		newHostKeyError(ErrHostKeyUnknown, "h", "", "SHA256:b", "x"))
	refused := &net.OpError{Op: "dial", Net: "tcp", Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)}
	dns := &net.DNSError{Err: "no such host", Name: "nohost.invalid", IsNotFound: true}
	cases := []struct {
		name string
		err  error
		want ConnectErrKind
		text string
	}{
		{"отказ аутентификации", authErr, ConnectAuthRejected, ConnectAuthRejectedText},
		{"ключ хоста изменился", changed, ConnectHostKey, ConnectHostKeyChangedText},
		{"ключ хоста не совпал с хранилищем", mismatch, ConnectHostKey, ConnectHostKeyChangedText},
		{"ключ хоста не подтверждён", unknownHost, ConnectHostKey, "ssh: handshake failed: " + ErrHostKeyUnknown.Error()},
		{"отказ соединения", refused, ConnectNetwork, ConnectNetworkText},
		{"имя не разрешилось", dns, ConnectNetwork, ConnectNetworkText},
		{"таймаут", fmt.Errorf("dial: %w", os.ErrDeadlineExceeded), ConnectNetwork, ConnectNetworkText},
		// Данных нет: EOF посреди рукопожатия может быть чем угодно
		// (fail2ban, MaxStartups, не SSH на порту) — не угадываем.
		{"неизвестно: EOF", fmt.Errorf("ssh: handshake failed: %w", io.EOF), ConnectUnknown, ConnectUnknownText + ": ssh: handshake failed: EOF"},
		{"неизвестно: прочее", errors.New("ssh: no common algorithm"), ConnectUnknown, ConnectUnknownText + ": ssh: no common algorithm"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ce := ClassifyConnectError(c.err)
			if ce.Kind != c.want {
				t.Fatalf("вид = %d, ожидался %d", ce.Kind, c.want)
			}
			if !strings.HasPrefix(ce.Error(), c.text) {
				t.Errorf("текст %q не начинается с %q", ce.Error(), c.text)
			}
			if !strings.Contains(ce.Error(), c.err.Error()) {
				t.Errorf("исходная причина потеряна: %q", ce.Error())
			}
			if !errors.Is(ce, c.err) {
				t.Errorf("Unwrap не ведёт к исходной ошибке")
			}
			if c.want != ConnectAuthRejected && strings.Contains(ce.Error(), "authorized_keys") {
				t.Errorf("совет про ключ входа без признака отказа аутентификации: %q", ce.Error())
			}
		})
	}
	if ClassifyConnectError(nil) != nil {
		t.Error("nil должен остаться nil")
	}
}

// Тест доезда (а): настоящий SSH-сервер проекта, неверный пароль — боевой
// путь ConnectWithHostKey обязан дать ConnectAuthRejected, а не голый текст
// x/crypto/ssh. Пароль не должен попасть в текст.
func TestConnectWrongPasswordReachesAuthRejected(t *testing.T) {
	srv, _ := newFakeSSHServer(t, "127.0.0.1:0")
	creds := credsForFakeSSH(t, srv)
	creds.Password = "WRONG-secret-pass-123"
	_, err := ConnectWithHostKey(creds, HostKeyPolicy{
		KnownHostsPath:      filepath.Join(t.TempDir(), "known_hosts"),
		ExpectedFingerprint: srv.Fingerprint(),
	})
	if err == nil {
		t.Fatal("подключение с неверным паролем прошло")
	}
	var ce *ConnectError
	if !errors.As(err, &ce) || ce.Kind != ConnectAuthRejected {
		t.Fatalf("ожидался ConnectAuthRejected, получено %T: %v", err, err)
	}
	if !strings.HasPrefix(err.Error(), ConnectAuthRejectedText) {
		t.Errorf("текст: %q", err.Error())
	}
	if strings.Contains(err.Error(), creds.Password) {
		t.Error("пароль попал в текст ошибки")
	}
}

// Тест доезда (в): порт, на котором никто не слушает.
func TestConnectRefusedReachesNetwork(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	host, port, _ := net.SplitHostPort(ln.Addr().String())
	ln.Close()
	_, err = ConnectWithHostKey(&ServerCreds{Host: host, Port: port, User: "root", Password: "p"},
		HostKeyPolicy{KnownHostsPath: filepath.Join(t.TempDir(), "known_hosts")})
	var ce *ConnectError
	if !errors.As(err, &ce) || ce.Kind != ConnectNetwork {
		t.Fatalf("ожидался ConnectNetwork, получено %T: %v", err, err)
	}
}

// Тест доезда (б): сервер «переустановили» — новый ключ хоста на том же
// адресе; вид ConnectHostKey, errors.Is по-прежнему видит ErrHostKeyChanged.
func TestConnectHostKeyChangedReachesHostKey(t *testing.T) {
	srv, _ := newFakeSSHServer(t, "127.0.0.1:0")
	creds := credsForFakeSSH(t, srv)
	kh := filepath.Join(t.TempDir(), "known_hosts")
	sess, err := ConnectWithHostKey(creds, HostKeyPolicy{KnownHostsPath: kh, ExpectedFingerprint: srv.Fingerprint()})
	if err != nil {
		t.Fatalf("первое подключение: %v", err)
	}
	sess.Close()
	restartFakeSSHServerSameAddr(t, srv)
	_, err = ConnectWithHostKey(creds, HostKeyPolicy{KnownHostsPath: kh})
	var ce *ConnectError
	if !errors.As(err, &ce) || ce.Kind != ConnectHostKey || !errors.Is(err, ErrHostKeyChanged) {
		t.Fatalf("ожидался ConnectHostKey/ErrHostKeyChanged, получено %T: %v", err, err)
	}
	if !strings.HasPrefix(err.Error(), ConnectHostKeyChangedText) {
		t.Errorf("текст: %q", err.Error())
	}
}

// Регресс на прежней ревизии (2f84e37): использует только старый API, поэтому
// компилируется там и падает поведением — прежде наружу шёл голый текст
// x/crypto/ssh без совета получить новый ключ vpn://.
func TestConnectWrongPasswordSaysGetNewKey(t *testing.T) {
	srv, _ := newFakeSSHServer(t, "127.0.0.1:0")
	creds := credsForFakeSSH(t, srv)
	creds.Password = "WRONG-secret-pass-456"
	_, err := ConnectWithHostKey(creds, HostKeyPolicy{
		KnownHostsPath:      filepath.Join(t.TempDir(), "known_hosts"),
		ExpectedFingerprint: srv.Fingerprint(),
	})
	if err == nil || !strings.Contains(err.Error(), "получите новый ключ vpn://") {
		t.Fatalf("нет понятного объяснения отказа входа: %v", err)
	}
}
