package core

// SEC-01 K1: проверка «ключ неизвестен» и запись в known_hosts разделены
// вопросом человеку. Если за это время другая копия записала для того же
// адреса ДРУГОЙ ключ (например, копия, которую обманули MITM), безусловное
// дописывание дало бы две строки для одного хоста — и knownhosts принял бы
// любую из них, обходя жёсткий ErrHostKeyChanged. Шов — Prompt: пока
// человек «думает», строка с чужим ключом подсаживается в файл.

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"amnezia-admin/internal/fakesrv"
	"golang.org/x/crypto/ssh/knownhosts"
)

func TestKnownHostsRecheckUnderLock(t *testing.T) {
	hostKey, err := fakesrv.NewHostKey()
	if err != nil {
		t.Fatal(err)
	}
	srv, err := fakesrv.ListenSSH("127.0.0.1:0", fakeSSHUser, fakeSSHPassword, hostKey, fakesrv.New())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { srv.Close() })
	creds := credsForFakeSSH(t, srv)
	addr := knownhosts.Normalize(srv.Addr())

	t.Run("другая копия записала ДРУГОЙ ключ — отказ, не писать", func(t *testing.T) {
		kh := filepath.Join(t.TempDir(), "known_hosts")
		other, err := fakesrv.NewHostKey()
		if err != nil {
			t.Fatal(err)
		}
		planted := knownhosts.Line([]string{addr}, other.PublicKey()) + "\n"
		prompt := func(string, string) bool {
			if err := os.WriteFile(kh, []byte(planted), 0600); err != nil {
				t.Fatal(err)
			}
			return true
		}
		sess, err := ConnectWithHostKey(creds, HostKeyPolicy{KnownHostsPath: kh, Prompt: prompt})
		if err == nil {
			sess.Close()
			t.Error("подключение принято, хотя для адреса уже записан другой ключ")
		} else if !errors.Is(err, ErrHostKeyChanged) {
			t.Errorf("ждали ErrHostKeyChanged: %v", err)
		}
		data, _ := os.ReadFile(kh)
		if string(data) != planted {
			t.Errorf("known_hosts изменён — дописана вторая строка для того же адреса:\n%s", data)
		}
	})

	t.Run("другая копия записала ТОТ ЖЕ ключ — принять, не дублировать", func(t *testing.T) {
		kh := filepath.Join(t.TempDir(), "known_hosts")
		prompt := func(host, fp string) bool {
			// Та же строка, что запишет сама программа.
			if err := appendKnownHost(kh, addr, hostKey.PublicKey()); err != nil {
				t.Fatal(err)
			}
			return true
		}
		sess, err := ConnectWithHostKey(creds, HostKeyPolicy{KnownHostsPath: kh, Prompt: prompt})
		if err != nil {
			t.Fatalf("тот же ключ уже записан — подключение обязано пройти: %v", err)
		}
		sess.Close()
		data, _ := os.ReadFile(kh)
		if n := strings.Count(string(data), "\n"); n != 1 {
			t.Errorf("строк в known_hosts %d, ждали 1 (дубликат):\n%s", n, data)
		}
	})
}
