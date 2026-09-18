package main

// Звено «текст, который печатает CLI» из теста на звенья (A2, Г4(а)).
// Живёт в cmd/cli, потому что проверяет именно то, что видит человек в
// терминале, а не значение ошибки внутри core.
//
// Ошибка настоящая: настоящий SSH к fakesrv.ListenSSH на эфемерном порту,
// настоящий core.Session, настоящий sshRunner внутри него. Секрет попадает
// на сервер в составе пути контейнера, сервер возвращает его в stderr, и
// ошибка идёт ровно тем путём, которым идёт боевая.
//
// ЧЕГО ЭТОТ ТЕСТ НЕ ДЕЛАЕТ: он не исполняет ветку печати внутри run() — туда
// нет способа подать управляемую серверную ошибку, не меняя fakesrv (а
// internal/fakesrv в этот PR не входит). Он берёт ту же ошибку и ту же
// формулу печати, что run(): fmt.Fprintln(stderr, "Ошибка:", err).
//
// Секрет — заведомо фиктивный литерал.

import (
	"bytes"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"amnezia-admin/core"
	"amnezia-admin/internal/fakesrv"
)

const fakeCLISecret = "test-psk-AAAABBBBCCCC"

func TestCLIPrintedErrorHasNoSecret(t *testing.T) {
	const user, password = "root", "fakepw-stderrmask-test"
	hostKey, err := fakesrv.NewHostKey()
	if err != nil {
		t.Fatalf("NewHostKey: %v", err)
	}
	srv, err := fakesrv.ListenSSH("127.0.0.1:0", user, password, hostKey, fakesrv.New())
	if err != nil {
		t.Fatalf("ListenSSH: %v", err)
	}
	t.Cleanup(func() { srv.Close() })

	host, port, err := splitHostPortForTest(srv.Addr())
	if err != nil {
		t.Fatalf("Addr: %v", err)
	}
	sess, err := core.ConnectWithHostKey(
		&core.ServerCreds{Host: host, User: user, Password: password, Port: port},
		core.HostKeyPolicy{
			KnownHostsPath:      filepath.Join(t.TempDir(), "known_hosts"),
			ExpectedFingerprint: srv.Fingerprint(),
		})
	if err != nil {
		t.Fatalf("ConnectWithHostKey: %v", err)
	}
	t.Cleanup(sess.Close)

	// Секрет уходит на сервер в составе пути: сервер не знает такого файла и
	// печатает путь целиком в stderr — ровно так, как wg-утилиты печатают
	// неузнанную строку.
	bogus := &core.Container{
		Name:    "amnezia-awg",
		Dir:     "/opt/amnezia/PresharedKey = " + fakeCLISecret,
		Proto:   "AmneziaWG",
		Managed: true,
	}
	_, planErr := sess.PlanAddUser(bogus, "Канарейка")
	if planErr == nil {
		t.Fatal("ожидалась ошибка чтения wg0.conf — без неё тесту нечего проверять")
	}

	// Та же формула печати, что в run(): fmt.Fprintln(stderr, "Ошибка:", err).
	var buf bytes.Buffer
	fmt.Fprintln(&buf, "Ошибка:", planErr)

	if strings.Contains(buf.String(), fakeCLISecret) {
		t.Errorf("CLI напечатал секрет в открытом виде:\n%s", buf.String())
	}
	if !strings.Contains(buf.String(), "PresharedKey = <скрыто>") {
		t.Errorf("маскировка съела имя ключа или структуру строки:\n%s", buf.String())
	}
}

func splitHostPortForTest(addr string) (string, string, error) {
	i := strings.LastIndex(addr, ":")
	if i < 0 {
		return "", "", fmt.Errorf("нет порта в %q", addr)
	}
	return addr[:i], addr[i+1:], nil
}
