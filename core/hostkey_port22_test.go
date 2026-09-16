package core

// Регресс на баг High, найденный владельцем на живой приёмке: после первого
// подключения к реальному серверу на СТАНДАРТНОМ порту 22 повторное
// подключение падало с "knownhosts: SplitHostPort(host): address host:
// missing port in address" — checkHostKey передавал в knownhosts-колбэк УЖЕ
// нормализованный addr (knownhosts.Normalize срезает порт 22), а колбэк из
// x/crypto/ssh/knownhosts требует адрес строго в форме host:port. Фикс:
// колбэку теперь передаётся исходный hostname (с портом), нормализованный
// addr остаётся только для записи строки known_hosts, текстов ошибок и
// ExpectedFingerprint. internal/fakesrv/cmd/fakeserver проблему не ловили,
// т.к. слушают нестандартные порты — для них Normalize порт сохраняет.
//
// Тесты этого файла — без сети (никакого net.Listen/ssh.Dial), напрямую
// вызывают checkHostKey с net.Addr-заглушкой, как и делает
// ConnectWithHostKey.HostKeyCallback внутри.

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"

	"amnezia-admin/internal/fakesrv"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// mustHostKey — новая пара ключей хоста для теста; t.Fatal при ошибке.
func mustHostKey(t *testing.T) ssh.Signer {
	t.Helper()
	k, err := fakesrv.NewHostKey()
	if err != nil {
		t.Fatalf("fakesrv.NewHostKey: %v", err)
	}
	return k
}

// callCheckHostKey — как ConnectWithHostKey.HostKeyCallback, но без ssh.Dial:
// hostname — то, что SSH-клиент передал бы в HostKeyCallback (host:port).
func callCheckHostKey(pol HostKeyPolicy, hostname string, remote net.Addr, key ssh.PublicKey) (accepted bool, err error) {
	fp := ssh.FingerprintSHA256(key)
	addr := knownhosts.Normalize(hostname)
	return checkHostKey(pol, addr, hostname, remote, fp, key)
}

// TestHostKeyPort22NoSplitHostPortError — п.2 задания: known_hosts со строкой
// без порта (как её пишет appendKnownHost/knownhosts.Line для порта 22),
// сверка идёт по hostname с портом ":22" — раньше здесь падал
// "missing port in address", а не (не)совпадение ключа.
func TestHostKeyPort22NoSplitHostPortError(t *testing.T) {
	key := mustHostKey(t)
	otherKey := mustHostKey(t)
	remote := &net.TCPAddr{IP: net.ParseIP("203.0.113.10"), Port: 22}

	newKH := func(t *testing.T) string {
		t.Helper()
		path := filepath.Join(t.TempDir(), "known_hosts")
		if err := appendKnownHost(path, "example.com", key.PublicKey()); err != nil {
			t.Fatalf("appendKnownHost: %v", err)
		}
		return path
	}

	t.Run("известный адрес, тот же ключ — принят", func(t *testing.T) {
		khPath := newKH(t)
		pol := HostKeyPolicy{KnownHostsPath: khPath}

		accepted, err := callCheckHostKey(pol, "example.com:22", remote, key.PublicKey())
		if err != nil {
			t.Fatalf("checkHostKey: %v (ожидался успех — ключ уже в known_hosts)", err)
		}
		if !accepted {
			t.Fatal("accepted = false, want true")
		}
	})

	t.Run("известный адрес, другой ключ — ErrHostKeyChanged (не SplitHostPort)", func(t *testing.T) {
		khPath := newKH(t)
		pol := HostKeyPolicy{KnownHostsPath: khPath}

		accepted, err := callCheckHostKey(pol, "example.com:22", remote, otherKey.PublicKey())
		if accepted {
			t.Fatal("accepted = true, want false (ключ сменился)")
		}
		if !errors.Is(err, ErrHostKeyChanged) {
			t.Fatalf("err = %v, want errors.Is(err, ErrHostKeyChanged) (не ошибка SplitHostPort)", err)
		}
	})

	t.Run("неизвестный адрес (другой хост, тот же known_hosts) — путь «неизвестен»", func(t *testing.T) {
		khPath := newKH(t)
		promptCalls := 0
		pol := HostKeyPolicy{
			KnownHostsPath: khPath,
			Prompt:         func(string, string) bool { promptCalls++; return false },
		}

		accepted, err := callCheckHostKey(pol, "other.com:22", remote, key.PublicKey())
		if accepted {
			t.Fatal("accepted = true, want false (неизвестный хост)")
		}
		if !errors.Is(err, ErrHostKeyUnknown) {
			t.Fatalf("err = %v, want errors.Is(err, ErrHostKeyUnknown) (не ошибка SplitHostPort)", err)
		}
		if promptCalls != 1 {
			t.Fatalf("promptCalls = %d, want 1 (путь «неизвестен» обязан дойти до Prompt)", promptCalls)
		}
	})
}

// TestHostKeyPort22FullCycle — п.2 задания, второй тест: полный цикл «первое
// подключение пишет строку -> второе с тем же ключом проходит без Prompt» для
// адреса с портом 22.
func TestHostKeyPort22FullCycle(t *testing.T) {
	key := mustHostKey(t)
	khPath := filepath.Join(t.TempDir(), "known_hosts")
	remote := &net.TCPAddr{IP: net.ParseIP("203.0.113.10"), Port: 22}

	promptCalls := 0
	pol := HostKeyPolicy{
		KnownHostsPath: khPath,
		Prompt:         func(string, string) bool { promptCalls++; return true },
	}

	accepted1, err1 := callCheckHostKey(pol, "gw01.example.net:22", remote, key.PublicKey())
	if err1 != nil {
		t.Fatalf("первое 'подключение' (TOFU): %v", err1)
	}
	if !accepted1 {
		t.Fatal("первое 'подключение' должно быть принято")
	}
	if promptCalls != 1 {
		t.Fatalf("promptCalls после первого 'подключения' = %d, want 1", promptCalls)
	}

	data, err := os.ReadFile(khPath)
	if err != nil {
		t.Fatalf("known_hosts после первого 'подключения': %v", err)
	}
	if len(data) == 0 {
		t.Fatal("known_hosts не записан после первого 'подключения'")
	}

	accepted2, err2 := callCheckHostKey(pol, "gw01.example.net:22", remote, key.PublicKey())
	if err2 != nil {
		t.Fatalf("второе 'подключение' (уже известен): %v (баг — SplitHostPort на порту 22 после первой записи)", err2)
	}
	if !accepted2 {
		t.Fatal("второе 'подключение' должно быть принято")
	}
	if promptCalls != 1 {
		t.Fatalf("promptCalls после второго 'подключения' = %d, want всё ещё 1 (Prompt на известном сервере не вызывается)", promptCalls)
	}
}

// TestHostKeyPort22AddressForms — п.3 задания: та же проверка для FQDN,
// IPv4 и IPv6-адреса на порту 22 одним табличным тестом.
func TestHostKeyPort22AddressForms(t *testing.T) {
	cases := []struct {
		name     string
		hostname string // как его передал бы SSH-клиент в HostKeyCallback
	}{
		{"FQDN", "gw01.thedatum.one:22"},
		{"IPv4", "203.0.113.10:22"},
		{"IPv6", "[2001:db8::1]:22"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			key := mustHostKey(t)
			khPath := filepath.Join(t.TempDir(), "known_hosts")
			remote := &net.TCPAddr{IP: net.ParseIP("203.0.113.10"), Port: 22}

			promptCalls := 0
			pol := HostKeyPolicy{
				KnownHostsPath: khPath,
				Prompt:         func(string, string) bool { promptCalls++; return true },
			}

			// Первое "подключение" — TOFU, запись строки.
			accepted1, err1 := callCheckHostKey(pol, tc.hostname, remote, key.PublicKey())
			if err1 != nil {
				t.Fatalf("первое 'подключение' (%s): %v", tc.hostname, err1)
			}
			if !accepted1 {
				t.Fatalf("первое 'подключение' (%s) должно быть принято", tc.hostname)
			}

			// Второе — уже известный адрес, тот же ключ: должно пройти без
			// ошибки SplitHostPort и без повторного Prompt.
			accepted2, err2 := callCheckHostKey(pol, tc.hostname, remote, key.PublicKey())
			if err2 != nil {
				t.Fatalf("второе 'подключение' (%s): %v", tc.hostname, err2)
			}
			if !accepted2 {
				t.Fatalf("второе 'подключение' (%s) должно быть принято", tc.hostname)
			}
			if promptCalls != 1 {
				t.Fatalf("%s: promptCalls = %d, want 1", tc.hostname, promptCalls)
			}
		})
	}
}
