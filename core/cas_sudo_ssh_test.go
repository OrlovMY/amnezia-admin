package core_test

// H1 боевым путём через НАСТОЯЩИЙ sshRunner (слияние H1, канарейка PR4.2):
// текст ошибки sshRunner содержит саму команду («команда %q: …; stderr: …»),
// а в команде записи — текст скрипта с меткой «not moved: ». Признак
// «отказ до записи» (casDeniedBeforeWrite) искал метку во всём тексте ошибки
// и потому НИКОГДА не срабатывал на настоящем SSH: повтор под sudo не
// выполнялся, и пользователь «docker только через sudo» получал «неизвестно,
// записаны ли изменения». Тесты ядра этого не видели: их подставные
// исполнители не кладут команду в текст ошибки.

import (
	"net"
	"path/filepath"
	"testing"

	"amnezia-admin/core"
	"amnezia-admin/internal/fakesrv"
)

func TestCASSudoRetryOverRealSSH(t *testing.T) {
	hk, err := fakesrv.NewHostKey()
	if err != nil {
		t.Fatal(err)
	}
	srv := fakesrv.New()
	ln, err := fakesrv.ListenSSHSudoOnly("127.0.0.1:0", "u", "pw", hk, srv)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	host, port, _ := net.SplitHostPort(ln.Addr())
	sess, err := core.ConnectWithHostKey(&core.ServerCreds{Host: host, Port: port, User: "u", Password: "pw"},
		core.HostKeyPolicy{KnownHostsPath: filepath.Join(t.TempDir(), "kh"), ExpectedFingerprint: ln.Fingerprint()})
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	ct := &core.Container{Name: "amnezia-awg", Dir: "/opt/amnezia/awg", Proto: "AmneziaWG", Support: core.SupportYes}
	if _, err := sess.AddUser(ct, "Carol"); err != nil {
		t.Fatalf("запись пользователем «docker только через sudo» не прошла: %v", err)
	}
	cl, err := sess.LoadClients(ct)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, c := range cl {
		if c.Name() == "Carol" {
			found = true
		}
	}
	if !found {
		t.Error("Carol нет на сервере после «готово»")
	}
}
