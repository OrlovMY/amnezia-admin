package fakesrv

import "testing"

// TestListenSSHRejectsNonLoopback — SEC-01, ревью PR-4А круг 1, Low: адрес,
// не резолвящийся в loopback (127.0.0.0/8 или ::1), обязан быть отклонён
// самим ListenSSH — ограничение "только 127.0.0.1" (В2 п.1) не должно быть
// негласным допущением одних лишь вызывающих (cmd/fakeserver, тесты core).
func TestListenSSHRejectsNonLoopback(t *testing.T) {
	hostKey, err := NewHostKey()
	if err != nil {
		t.Fatalf("NewHostKey: %v", err)
	}
	exec := New()

	cases := []string{
		"0.0.0.0:0",
		"192.168.1.1:2222",
		"example.com:2222", // не IP вовсе
		"localhost:2222",   // имя, не литеральный loopback-адрес
	}
	for _, addr := range cases {
		t.Run(addr, func(t *testing.T) {
			srv, err := ListenSSH(addr, "u", "p", hostKey, exec)
			if err == nil {
				srv.Close()
				t.Fatalf("ListenSSH(%q) = nil error, want отказ (не loopback)", addr)
			}
		})
	}
}

// TestListenSSHAcceptsLoopback — та же граница со стороны "должно работать":
// 127.0.0.1 и ::1 обязаны по-прежнему подниматься.
func TestListenSSHAcceptsLoopback(t *testing.T) {
	hostKey, err := NewHostKey()
	if err != nil {
		t.Fatalf("NewHostKey: %v", err)
	}
	exec := New()

	for _, addr := range []string{"127.0.0.1:0", "[::1]:0"} {
		t.Run(addr, func(t *testing.T) {
			srv, err := ListenSSH(addr, "u", "p", hostKey, exec)
			if err != nil {
				t.Fatalf("ListenSSH(%q): %v", addr, err)
			}
			srv.Close()
		})
	}
}
