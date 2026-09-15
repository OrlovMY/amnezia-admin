package core

// Правка ревью (changes-requested, Medium, QA-01, круг 1 по фиксу порта 22):
// TestHostKeyPort22* (hostkey_port22_test.go) зовут checkHostKey напрямую
// через хелпер callCheckHostKey — сторож стоит ВНУТРИ checkHostKey и не
// замечает порчу СБОРКИ конфигурации в hostKeyCallback (например
// checkHostKey(pol, addr, addr, …) вместо (pol, addr, hostname, …) —
// ревьюер проверил подменой M2, весь `go test ./core/` до этого файла
// оставался зелёным). Тесты этого файла идут через НАСТОЯЩЕЕ SSH-
// рукопожатие (ssh.NewClientConn) с тем же hostKeyCallback, что и
// ConnectWithHostKey, — так порча видна ровно там, где она произошла.
//
// Приём (без bind на порт 22): fakesrv.SSHServer слушает "127.0.0.1:0",
// но hostname, который увидит HostKeyCallback, задаётся ОТДЕЛЬНО — вторым
// аргументом ssh.NewClientConn, а не адресом, на который реально открыт
// net.Dial. Именно так делает ssh.Dial внутри (hostname = строка, которую
// ему передали для набора, а не то, что вернул net.Conn.RemoteAddr()), и
// именно так ведёт себя ConnectWithHostKey: net.JoinHostPort(creds.Host,
// creds.Port) идёт в ssh.Dial(_, addr, _), и этот же addr долетает до
// HostKeyCallback как hostname. Поэтому подставить "gw01.example.net:22"
// или "[2001:db8::1]:22" можно, реально слушая только на loopback.

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"amnezia-admin/internal/fakesrv"
	"golang.org/x/crypto/ssh"
)

// connectViaCallback — как ConnectWithHostKey, но без ssh.Dial: настоящее
// SSH-рукопожатие (пароль fakeSSH*) поверх net.Dial к srv, с hostname,
// заданным ОТДЕЛЬНО (см. комментарий выше). Закрывает клиента перед
// возвратом, если рукопожатие прошло целиком (host key + auth) — сессии не
// нужны, интересует только исход HostKeyCallback (и auth как побочное
// подтверждение, что до неё дошло).
func connectViaCallback(t *testing.T, srv *fakesrv.SSHServer, hostname string, pol HostKeyPolicy) (fp string, err error) {
	t.Helper()
	conn, derr := net.Dial("tcp", srv.Addr())
	if derr != nil {
		t.Fatalf("net.Dial(%s): %v", srv.Addr(), derr)
	}

	var acceptedFp string
	cfg := &ssh.ClientConfig{
		User:            fakeSSHUser,
		Auth:            []ssh.AuthMethod{ssh.Password(fakeSSHPassword)},
		HostKeyCallback: hostKeyCallback(pol, &acceptedFp),
	}

	c, chans, reqs, herr := ssh.NewClientConn(conn, hostname, cfg)
	if herr != nil {
		conn.Close()
		return "", herr
	}
	client := ssh.NewClient(c, chans, reqs)
	defer client.Close()
	return acceptedFp, nil
}

// TestHostKeyCallbackPort22FullCycle — п.1 changes-requested: первое
// подключение (TOFU) пишет строку БЕЗ порта (адрес с портом 22), второе —
// проходит без Prompt, смена ключа хоста даёт ErrHostKeyChanged. Всё через
// hostKeyCallback + настоящее рукопожатие, не через checkHostKey напрямую.
func TestHostKeyCallbackPort22FullCycle(t *testing.T) {
	srv, _ := newFakeSSHServer(t, "127.0.0.1:0")
	khPath := filepath.Join(t.TempDir(), "known_hosts")
	const hostname = "gw01.example.net:22"

	promptCalls := 0
	pol := HostKeyPolicy{
		KnownHostsPath: khPath,
		Prompt:         func(string, string) bool { promptCalls++; return true },
	}

	fp1, err1 := connectViaCallback(t, srv, hostname, pol)
	if err1 != nil {
		t.Fatalf("первое подключение (TOFU): %v", err1)
	}
	if fp1 != srv.Fingerprint() {
		t.Fatalf("fp1 = %s, want %s", fp1, srv.Fingerprint())
	}
	if promptCalls != 1 {
		t.Fatalf("promptCalls после первого подключения = %d, want 1", promptCalls)
	}

	data, err := os.ReadFile(khPath)
	if err != nil {
		t.Fatalf("known_hosts: %v", err)
	}
	line := strings.TrimSpace(string(data))
	if !strings.HasPrefix(line, "gw01.example.net ") {
		t.Fatalf("known_hosts строка = %q, want префикс %q (БЕЗ порта — порт 22 срезан Normalize)", line, "gw01.example.net ")
	}

	// Второе подключение — тот же адрес, тот же ключ: без Prompt, без ошибки
	// SplitHostPort (это и есть регресс, которого не было бы видно без
	// прохода через hostKeyCallback целиком).
	fp2, err2 := connectViaCallback(t, srv, hostname, pol)
	if err2 != nil {
		t.Fatalf("второе подключение (уже известен): %v", err2)
	}
	if fp2 != srv.Fingerprint() {
		t.Fatalf("fp2 = %s, want %s", fp2, srv.Fingerprint())
	}
	if promptCalls != 1 {
		t.Fatalf("promptCalls после второго подключения = %d, want всё ещё 1", promptCalls)
	}

	// Смена ключа хоста на том же адресе — жёсткий отказ.
	srv2 := restartFakeSSHServerSameAddr(t, srv)
	if srv2.Fingerprint() == srv.Fingerprint() {
		t.Fatal("тестовая настройка сломана: отпечатки до/после рестарта совпали")
	}
	onChangedCalls := 0
	pol.OnChanged = func(string, string, string) { onChangedCalls++ }

	_, err3 := connectViaCallback(t, srv2, hostname, pol)
	if !errors.Is(err3, ErrHostKeyChanged) {
		t.Fatalf("err3 = %v, want errors.Is(err, ErrHostKeyChanged)", err3)
	}
	if onChangedCalls != 1 {
		t.Fatalf("onChangedCalls = %d, want 1", onChangedCalls)
	}
}

// TestHostKeyCallbackAddressForms — табличный вариант changes-requested:
// IPv6-адрес на порту 22 (пишется без порта и без скобок) и нестандартный
// порт (пишется [host]:port) — тоже через настоящее рукопожатие.
func TestHostKeyCallbackAddressForms(t *testing.T) {
	cases := []struct {
		name       string
		hostname   string
		wantPrefix string // ожидаемое начало строки known_hosts (адрес + пробел)
	}{
		{"IPv6 порт 22 — без скобок и без порта", "[2001:db8::1]:22", "2001:db8::1 "},
		{"нестандартный порт — [host]:port", "sometag.example:2222", "[sometag.example]:2222 "},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv, _ := newFakeSSHServer(t, "127.0.0.1:0")
			khPath := filepath.Join(t.TempDir(), "known_hosts")

			promptCalls := 0
			pol := HostKeyPolicy{
				KnownHostsPath: khPath,
				Prompt:         func(string, string) bool { promptCalls++; return true },
			}

			if _, err := connectViaCallback(t, srv, tc.hostname, pol); err != nil {
				t.Fatalf("первое подключение (%s): %v", tc.hostname, err)
			}
			data, err := os.ReadFile(khPath)
			if err != nil {
				t.Fatalf("known_hosts: %v", err)
			}
			line := strings.TrimSpace(string(data))
			if !strings.HasPrefix(line, tc.wantPrefix) {
				t.Fatalf("known_hosts строка = %q, want префикс %q", line, tc.wantPrefix)
			}

			if _, err := connectViaCallback(t, srv, tc.hostname, pol); err != nil {
				t.Fatalf("второе подключение (%s): %v", tc.hostname, err)
			}
			if promptCalls != 1 {
				t.Fatalf("%s: promptCalls = %d, want 1 (второе подключение — без Prompt)", tc.hostname, promptCalls)
			}
		})
	}
}
