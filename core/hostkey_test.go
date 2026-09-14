package core

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"amnezia-admin/internal/fakesrv"
	"golang.org/x/crypto/ssh/knownhosts"
)

// ---------- вспомогательные функции для тестов на настоящем SSH ----------
//
// В отличие от NewSessionWithRunner (подмена транспорта интерфейсом Runner,
// используется в остальных тестах core), проверка ключа хоста происходит
// ВНУТРИ ssh.Dial — её нельзя протестировать без настоящего TCP+SSH
// рукопожатия. internal/fakesrv.SSHServer — встроенный SSH-сервер на
// 127.0.0.1 (В2 п.1), команды исполняет тот же fakesrv.Server, что и везде.

const fakeSSHUser = "root"
const fakeSSHPassword = "fakeSSHPassword1234"

// newFakeSSHServer поднимает fakesrv.SSHServer на addr (обычно "127.0.0.1:0")
// поверх свежего fakesrv.Server (дефолтное состояние — контейнер amnezia-awg,
// два клиента). Закрывается автоматически по t.Cleanup.
func newFakeSSHServer(t *testing.T, addr string) (*fakesrv.SSHServer, *fakesrv.Server) {
	t.Helper()
	hostKey, err := fakesrv.NewHostKey()
	if err != nil {
		t.Fatalf("fakesrv.NewHostKey: %v", err)
	}
	exec := fakesrv.New()
	srv, err := fakesrv.ListenSSH(addr, fakeSSHUser, fakeSSHPassword, hostKey, exec)
	if err != nil {
		t.Fatalf("fakesrv.ListenSSH(%q): %v", addr, err)
	}
	t.Cleanup(func() { srv.Close() })
	return srv, exec
}

// restartFakeSSHServerSameAddr закрывает srv и поднимает НОВЫЙ сервер (с
// НОВЫМ, отличным от исходного, ключом хоста) на ТОМ ЖЕ АДРЕСЕ — имитирует
// «сервер переустановили» (TestHostKeyMismatch, cmd/fakeserver -new-hostkey).
// Небольшой ретрай на bind — сразу после Close порт иногда на мгновение занят.
func restartFakeSSHServerSameAddr(t *testing.T, srv *fakesrv.SSHServer) *fakesrv.SSHServer {
	t.Helper()
	addr := srv.Addr()
	if err := srv.Close(); err != nil {
		t.Fatalf("Close исходного сервера: %v", err)
	}
	hostKey, err := fakesrv.NewHostKey()
	if err != nil {
		t.Fatalf("fakesrv.NewHostKey: %v", err)
	}
	exec := fakesrv.New()

	var next *fakesrv.SSHServer
	var lastErr error
	for i := 0; i < 20; i++ {
		next, lastErr = fakesrv.ListenSSH(addr, fakeSSHUser, fakeSSHPassword, hostKey, exec)
		if lastErr == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if lastErr != nil {
		t.Fatalf("не удалось перезапустить сервер на прежнем адресе %s: %v", addr, lastErr)
	}
	t.Cleanup(func() { next.Close() })
	return next
}

func credsForFakeSSH(t *testing.T, srv *fakesrv.SSHServer) *ServerCreds {
	t.Helper()
	host, port, err := net.SplitHostPort(srv.Addr())
	if err != nil {
		t.Fatalf("SplitHostPort(%q): %v", srv.Addr(), err)
	}
	return &ServerCreds{Host: host, User: fakeSSHUser, Password: fakeSSHPassword, Port: port}
}

func alwaysTrustPrompt(string, string) bool { return true }

// closeIfAny закрывает сессию, если подключение неожиданно удалось на
// ветке, где тест ожидает отказ (SEC-01/BE-01, ревью PR-4А круг 1, Medium):
// без этого регрессия «принимает то, что должна отклонять» не падает
// быстро, а виснет — Close() встроенного сервера в t.Cleanup ждёт клиента,
// который сам никогда не отключится.
func closeIfAny(sess *Session) {
	if sess != nil {
		sess.Close()
	}
}

func assertKnownHostsEmpty(t *testing.T, path string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return
		}
		t.Fatalf("known_hosts: %v", err)
	}
	if len(data) != 0 {
		t.Fatalf("known_hosts должен остаться пуст, получено: %q", data)
	}
}

// ---------- Д: обязательные тесты части А ----------

func TestHostKeyUnknown(t *testing.T) {
	t.Run("Prompt == nil", func(t *testing.T) {
		srv, _ := newFakeSSHServer(t, "127.0.0.1:0")
		creds := credsForFakeSSH(t, srv)
		khPath := filepath.Join(t.TempDir(), "known_hosts")

		sess, err := ConnectWithHostKey(creds, HostKeyPolicy{KnownHostsPath: khPath})
		closeIfAny(sess)
		if !errors.Is(err, ErrHostKeyUnknown) {
			t.Fatalf("err = %v, want ErrHostKeyUnknown", err)
		}
		assertKnownHostsEmpty(t, khPath)
	})

	t.Run("Prompt вернул false", func(t *testing.T) {
		srv, _ := newFakeSSHServer(t, "127.0.0.1:0")
		creds := credsForFakeSSH(t, srv)
		khPath := filepath.Join(t.TempDir(), "known_hosts")
		called := false

		sess, err := ConnectWithHostKey(creds, HostKeyPolicy{
			KnownHostsPath: khPath,
			Prompt:         func(host, fp string) bool { called = true; return false },
		})
		closeIfAny(sess)
		if !errors.Is(err, ErrHostKeyUnknown) {
			t.Fatalf("err = %v, want ErrHostKeyUnknown", err)
		}
		if !called {
			t.Fatal("Prompt не был вызван")
		}
		assertKnownHostsEmpty(t, khPath)
	})

	t.Run("Prompt вернул true", func(t *testing.T) {
		srv, _ := newFakeSSHServer(t, "127.0.0.1:0")
		creds := credsForFakeSSH(t, srv)
		khPath := filepath.Join(t.TempDir(), "known_hosts")

		var gotHost, gotFp string
		promptCalls, onChangedCalls := 0, 0
		sess, err := ConnectWithHostKey(creds, HostKeyPolicy{
			KnownHostsPath: khPath,
			Prompt: func(host, fp string) bool {
				promptCalls++
				gotHost, gotFp = host, fp
				return true
			},
			OnChanged: func(host, knownFp, presentedFp string) { onChangedCalls++ },
		})
		if err != nil {
			t.Fatalf("ConnectWithHostKey: %v", err)
		}
		defer sess.Close()

		if promptCalls != 1 {
			t.Fatalf("promptCalls = %d, want 1", promptCalls)
		}
		if onChangedCalls != 0 {
			t.Fatalf("onChangedCalls = %d, want 0 (неизвестный сервер — не смена ключа)", onChangedCalls)
		}
		if gotFp != srv.Fingerprint() {
			t.Fatalf("Prompt получил fp = %s, want %s", gotFp, srv.Fingerprint())
		}
		if sess.HostKeyFingerprint != srv.Fingerprint() {
			t.Fatalf("sess.HostKeyFingerprint = %s, want %s", sess.HostKeyFingerprint, srv.Fingerprint())
		}

		data, err := os.ReadFile(khPath)
		if err != nil {
			t.Fatalf("known_hosts: %v", err)
		}
		lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
		if len(lines) != 1 {
			t.Fatalf("known_hosts: %d строк, want 1: %q", len(lines), data)
		}
		if !strings.Contains(lines[0], gotHost) {
			t.Fatalf("known_hosts строка %q не содержит адрес %q", lines[0], gotHost)
		}

		// exec дошёл до Runner: LoadClients видит дефолтных клиентов fakesrv.
		clients, err := sess.LoadClients(awgContainer())
		if err != nil {
			t.Fatalf("LoadClients: %v", err)
		}
		if len(clients) != 2 {
			t.Fatalf("LoadClients вернул %d записей, want 2", len(clients))
		}
	})
}

func TestHostKeyMatch(t *testing.T) {
	srv, _ := newFakeSSHServer(t, "127.0.0.1:0")
	creds := credsForFakeSSH(t, srv)
	khPath := filepath.Join(t.TempDir(), "known_hosts")

	sess1, err := ConnectWithHostKey(creds, HostKeyPolicy{KnownHostsPath: khPath, Prompt: alwaysTrustPrompt})
	if err != nil {
		t.Fatalf("первичное подключение (TOFU): %v", err)
	}
	sess1.Close()

	promptCalls, onChangedCalls := 0, 0
	sess2, err := ConnectWithHostKey(creds, HostKeyPolicy{
		KnownHostsPath: khPath,
		Prompt:         func(string, string) bool { promptCalls++; return true },
		OnChanged:      func(string, string, string) { onChangedCalls++ },
	})
	if err != nil {
		t.Fatalf("второе подключение (ключ уже известен): %v", err)
	}
	defer sess2.Close()

	if promptCalls != 0 {
		t.Fatalf("promptCalls = %d, want 0 (ключ уже известен и совпал)", promptCalls)
	}
	if onChangedCalls != 0 {
		t.Fatalf("onChangedCalls = %d, want 0", onChangedCalls)
	}
}

func TestHostKeyMismatch(t *testing.T) {
	khPath := filepath.Join(t.TempDir(), "known_hosts")

	srvA, _ := newFakeSSHServer(t, "127.0.0.1:0")
	credsA := credsForFakeSSH(t, srvA)
	fpA := srvA.Fingerprint()

	sessA, err := ConnectWithHostKey(credsA, HostKeyPolicy{KnownHostsPath: khPath, Prompt: alwaysTrustPrompt})
	if err != nil {
		t.Fatalf("подключение к A: %v", err)
	}
	sessA.Close()

	srvB := restartFakeSSHServerSameAddr(t, srvA)
	fpB := srvB.Fingerprint()
	if fpA == fpB {
		t.Fatalf("тестовая настройка сломана: отпечатки A и B совпали")
	}
	credsB := credsForFakeSSH(t, srvB)

	before, err := os.ReadFile(khPath)
	if err != nil {
		t.Fatalf("known_hosts перед попыткой B: %v", err)
	}

	var gotHost, gotKnown, gotPresented string
	promptCalls, onChangedCalls := 0, 0
	sessB, err := ConnectWithHostKey(credsB, HostKeyPolicy{
		KnownHostsPath: khPath,
		Prompt:         func(string, string) bool { promptCalls++; return true },
		OnChanged: func(host, knownFp, presentedFp string) {
			onChangedCalls++
			gotHost, gotKnown, gotPresented = host, knownFp, presentedFp
		},
	})
	closeIfAny(sessB)
	if !errors.Is(err, ErrHostKeyChanged) {
		t.Fatalf("err = %v, want ErrHostKeyChanged", err)
	}
	if promptCalls != 0 {
		t.Fatalf("Prompt не должен вызываться при смене ключа, calls = %d", promptCalls)
	}
	if onChangedCalls != 1 {
		t.Fatalf("onChangedCalls = %d, want 1", onChangedCalls)
	}
	if gotKnown != fpA {
		t.Fatalf("OnChanged: knownFp = %s, want %s", gotKnown, fpA)
	}
	if gotPresented != fpB {
		t.Fatalf("OnChanged: presentedFp = %s, want %s", gotPresented, fpB)
	}
	_ = gotHost

	after, err := os.ReadFile(khPath)
	if err != nil {
		t.Fatalf("known_hosts после попытки B: %v", err)
	}
	if !bytes.Equal(before, after) {
		t.Fatalf("known_hosts изменился при отказе смены ключа:\nбыло:  %q\nстало: %q", before, after)
	}

	t.Run("ExpectedFingerprint == fp(B) тоже не помогает", func(t *testing.T) {
		sess, err := ConnectWithHostKey(credsB, HostKeyPolicy{
			KnownHostsPath:      khPath,
			ExpectedFingerprint: fpB,
		})
		closeIfAny(sess)
		if !errors.Is(err, ErrHostKeyChanged) {
			t.Fatalf("err = %v, want ErrHostKeyChanged (ExpectedFingerprint не должен обходить смену ключа)", err)
		}
	})
}

// TestForgetThenTOFU — часть А, сигнатура и поведение по правке координатора
// 2026-09-14 23:58 у Г1 (SEC-01 High, круг 1 ревью PR-4А): прежний
// ForgetHostKey(pin, path) снимал след ТОЛЬКО в .avlt, и после легитимной
// переустановки сервера на той же машине R2 зацикливался — известный-но-
// другой ключ никуда не девался из known_hosts, следующая попытка снова
// давала ErrHostKeyChanged. ForgetHostKey теперь снимает ОБА следа: .avlt И
// строку АДРЕСА в known_hosts (прочие адреса не трогает). Сам вызов
// по-прежнему не создаёт соединений (нет ssh.Dial внутри ForgetHostKey);
// проверка "следующее подключение идёт путём неизвестного сервера" делает
// это уже отдельным, настоящим ConnectWithHostKey к fakesrv.
func TestForgetThenTOFU(t *testing.T) {
	pin := "forgetPin1234"
	payload := VaultPayload{
		Label:              "Test",
		Key:                "vpn://abc",
		Created:            "2024-01-01T00:00:00Z",
		HostKeyFingerprint: "SHA256:oldFingerprintPlaceholderXXXXXXXXXXXXXXXXXX",
	}
	data, err := SealVault(pin, payload, testArgonParams, false)
	if err != nil {
		t.Fatalf("SealVault: %v", err)
	}
	vaultPath := filepath.Join(t.TempDir(), "test.avlt")
	if err := os.WriteFile(vaultPath, data, 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	// Сервер, к которому в итоге подключимся; known_hosts заранее содержит
	// СТАРЫЙ (не совпадающий с реальным) ключ этого же адреса — имитация
	// "сервер переустановили на той же машине, адрес прежний, ключ другой" —
	// и отдельную строку ДРУГОГО адреса, которая обязана пережить Forget.
	srv, _ := newFakeSSHServer(t, "127.0.0.1:0")
	addr := knownhosts.Normalize(srv.Addr())

	khPath := filepath.Join(t.TempDir(), "known_hosts")
	oldKey, err := fakesrv.NewHostKey()
	if err != nil {
		t.Fatalf("fakesrv.NewHostKey (старый ключ): %v", err)
	}
	if err := appendKnownHost(khPath, addr, oldKey.PublicKey()); err != nil {
		t.Fatalf("appendKnownHost(старый ключ этого адреса): %v", err)
	}
	otherAddr := "other-host.example:2222"
	otherKey, err := fakesrv.NewHostKey()
	if err != nil {
		t.Fatalf("fakesrv.NewHostKey (другой адрес): %v", err)
	}
	if err := appendKnownHost(khPath, otherAddr, otherKey.PublicKey()); err != nil {
		t.Fatalf("appendKnownHost(другой адрес): %v", err)
	}

	before, err := os.ReadFile(khPath)
	if err != nil {
		t.Fatalf("known_hosts до Forget: %v", err)
	}
	if strings.Count(string(before), "\n") != 2 {
		t.Fatalf("тестовая настройка сломана: ожидалось 2 строки known_hosts, получено %q", before)
	}

	if err := ForgetHostKey(pin, vaultPath, khPath, addr); err != nil {
		t.Fatalf("ForgetHostKey: %v", err)
	}

	// .avlt: отпечаток снят, остальное не изменилось.
	newData, err := os.ReadFile(vaultPath)
	if err != nil {
		t.Fatalf("ReadFile после ForgetHostKey: %v", err)
	}
	got, info, err := OpenVaultInfo(pin, newData)
	if err != nil {
		t.Fatalf("OpenVaultInfo после ForgetHostKey: %v", err)
	}
	if got.HostKeyFingerprint != "" {
		t.Fatalf("HostKeyFingerprint = %q, want пусто", got.HostKeyFingerprint)
	}
	if info.MachineBind {
		t.Fatal("MachineBind должен остаться false (как было при SealVault)")
	}
	if got.Key != payload.Key || got.Label != payload.Label || got.Created != payload.Created {
		t.Fatalf("остальной payload не должен меняться: got %+v", got)
	}

	// known_hosts: строка ЭТОГО адреса пропала, строка ДРУГОГО осталась.
	afterKH, err := os.ReadFile(khPath)
	if err != nil {
		t.Fatalf("known_hosts после ForgetHostKey: %v", err)
	}
	lines := nonEmptyLines(string(afterKH))
	if len(lines) != 1 {
		t.Fatalf("known_hosts после Forget: %d строк, want 1 (только другой адрес): %q", len(lines), afterKH)
	}
	if !strings.Contains(lines[0], "other-host.example") {
		t.Fatalf("строка другого адреса пропала: %q", afterKH)
	}
	if strings.Contains(string(afterKH), addr) {
		t.Fatalf("строка забытого адреса %q всё ещё в known_hosts: %q", addr, afterKH)
	}

	// Следующее подключение — обычный путь НЕИЗВЕСТНОГО сервера (запись
	// адреса удалена), а не OnChanged (сервер предъявляет свой настоящий
	// ключ, которого в known_hosts после Forget уже нет вовсе).
	creds := credsForFakeSSH(t, srv)
	promptCalls, onChangedCalls := 0, 0
	sess, err := ConnectWithHostKey(creds, HostKeyPolicy{
		KnownHostsPath:      khPath,
		ExpectedFingerprint: got.HostKeyFingerprint, // "" — как после Forget
		Prompt:              func(string, string) bool { promptCalls++; return true },
		OnChanged:           func(string, string, string) { onChangedCalls++ },
	})
	if err != nil {
		if sess != nil {
			sess.Close()
		}
		t.Fatalf("ConnectWithHostKey после Forget: %v", err)
	}
	defer sess.Close()
	if promptCalls != 1 {
		t.Fatalf("promptCalls = %d, want 1 (Prompt, не OnChanged)", promptCalls)
	}
	if onChangedCalls != 0 {
		t.Fatalf("onChangedCalls = %d, want 0", onChangedCalls)
	}

	// Строка другого адреса пережила весь сценарий целиком.
	finalKH, err := os.ReadFile(khPath)
	if err != nil {
		t.Fatalf("known_hosts в конце теста: %v", err)
	}
	if !strings.Contains(string(finalKH), "other-host.example") {
		t.Fatalf("строка другого адреса пропала к концу теста: %q", finalKH)
	}
}

// nonEmptyLines — вспомогательная для проверок содержимого known_hosts.
func nonEmptyLines(s string) []string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if strings.TrimSpace(l) != "" {
			out = append(out, l)
		}
	}
	return out
}

// TestHostKeyExpectedFingerprintPins — рекомендация Д: ExpectedFingerprint
// (из -hostkey/.avlt) пинингует новый ключ без вопроса, если совпал; если не
// совпал — отказ без записи, вне зависимости от Prompt.
func TestHostKeyExpectedFingerprintPins(t *testing.T) {
	t.Run("совпал — без вопроса, записан", func(t *testing.T) {
		srv, _ := newFakeSSHServer(t, "127.0.0.1:0")
		creds := credsForFakeSSH(t, srv)
		khPath := filepath.Join(t.TempDir(), "known_hosts")

		sess, err := ConnectWithHostKey(creds, HostKeyPolicy{
			KnownHostsPath:      khPath,
			ExpectedFingerprint: srv.Fingerprint(),
		})
		if err != nil {
			t.Fatalf("ConnectWithHostKey: %v", err)
		}
		defer sess.Close()

		data, err := os.ReadFile(khPath)
		if err != nil {
			t.Fatalf("known_hosts: %v", err)
		}
		if len(bytes.TrimSpace(data)) == 0 {
			t.Fatal("known_hosts не записан")
		}
	})

	t.Run("не совпал — отказ, файл пуст", func(t *testing.T) {
		srv, _ := newFakeSSHServer(t, "127.0.0.1:0")
		creds := credsForFakeSSH(t, srv)
		khPath := filepath.Join(t.TempDir(), "known_hosts")

		sess, err := ConnectWithHostKey(creds, HostKeyPolicy{
			KnownHostsPath:      khPath,
			ExpectedFingerprint: "SHA256:wrongWrongWrongWrongWrongWrongWrongWrong00",
		})
		closeIfAny(sess)
		if !errors.Is(err, ErrHostKeyMismatch) {
			t.Fatalf("err = %v, want ErrHostKeyMismatch", err)
		}
		assertKnownHostsEmpty(t, khPath)
	})
}

// TestVaultVsKnownHostsDisagreeRefuses — известный ключ в known_hosts
// совпадает с реально предъявленным сервером, но ExpectedFingerprint (как из
// .avlt) — другой: расхождение vault vs known_hosts, всегда отказ.
func TestVaultVsKnownHostsDisagreeRefuses(t *testing.T) {
	srv, _ := newFakeSSHServer(t, "127.0.0.1:0")
	creds := credsForFakeSSH(t, srv)
	khPath := filepath.Join(t.TempDir(), "known_hosts")

	sess1, err := ConnectWithHostKey(creds, HostKeyPolicy{KnownHostsPath: khPath, Prompt: alwaysTrustPrompt})
	if err != nil {
		t.Fatalf("первичное подключение: %v", err)
	}
	sess1.Close()

	promptCalls := 0
	sess2, err := ConnectWithHostKey(creds, HostKeyPolicy{
		KnownHostsPath:      khPath,
		ExpectedFingerprint: "SHA256:vaultSaysSomethingElseVaultSaysSomethingEl",
		Prompt:              func(string, string) bool { promptCalls++; return true },
	})
	closeIfAny(sess2)
	if !errors.Is(err, ErrHostKeyMismatch) {
		t.Fatalf("err = %v, want ErrHostKeyMismatch", err)
	}
	if promptCalls != 0 {
		t.Fatalf("Prompt не должен вызываться, calls = %d", promptCalls)
	}
}

// TestNoInsecureHostKey — страж (рекомендация Д, расширен по ревью PR-4А
// круг 1, SEC-01 Low): полное отключение проверки ключа хоста не должно
// возвращаться никуда в модуле — не только в core (часть Б будет
// переписывать подключение в cmd/cli и cmd/gui, и страж обязан заметить
// регресс и там), а не только в *текущем* пакете. Идёт от корня модуля
// (".."), т.к. `go test` запускает пакет из его собственного каталога.
func TestNoInsecureHostKey(t *testing.T) {
	root := ".."
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		if filepath.Ext(path) != ".go" {
			return nil
		}
		data, rerr := os.ReadFile(path)
		if rerr != nil {
			return fmt.Errorf("ReadFile(%s): %w", path, rerr)
		}
		if strings.Contains(string(data), "Insecure"+"IgnoreHostKey") {
			t.Errorf("%s: содержит полное отключение проверки ключа хоста — запрещено (В2 п.3)", path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("обход дерева модуля от %s: %v", root, err)
	}
}

// TestHostKeyErrorFieldsViaErrorsAs — ревью PR-4-Б, круг 1, SEC-01 Medium:
// GUI раньше добывал "полученный" отпечаток регэкспом из текста ошибки
// ErrHostKeyMismatch (тот же класс хрупкости, что чинили у ErrCASMismatch в
// PR-3). Теперь Addr/KnownFp/PresentedFp — поля *HostKeyError, достаются
// через errors.As; errors.Is(err, ErrHostKeyChanged/Mismatch) продолжает
// работать (Unwrap), а текст Error() — тот же, что был у fmt.Errorf(%w...).
func TestHostKeyErrorFieldsViaErrorsAs(t *testing.T) {
	t.Run("ErrHostKeyChanged — Addr/KnownFp/PresentedFp совпадают с аргументами OnChanged", func(t *testing.T) {
		khPath := filepath.Join(t.TempDir(), "known_hosts")
		srvA, _ := newFakeSSHServer(t, "127.0.0.1:0")
		credsA := credsForFakeSSH(t, srvA)
		fpA := srvA.Fingerprint()

		sessA, err := ConnectWithHostKey(credsA, HostKeyPolicy{KnownHostsPath: khPath, Prompt: alwaysTrustPrompt})
		if err != nil {
			t.Fatalf("подключение к A: %v", err)
		}
		sessA.Close()

		srvB := restartFakeSSHServerSameAddr(t, srvA)
		fpB := srvB.Fingerprint()
		credsB := credsForFakeSSH(t, srvB)

		sess, err := ConnectWithHostKey(credsB, HostKeyPolicy{KnownHostsPath: khPath})
		closeIfAny(sess)

		var hke *HostKeyError
		if !errors.As(err, &hke) {
			t.Fatalf("errors.As(err, *HostKeyError) = false; err = %v", err)
		}
		if !errors.Is(err, ErrHostKeyChanged) {
			t.Fatalf("errors.Is(err, ErrHostKeyChanged) = false (Unwrap сломан?); err = %v", err)
		}
		if hke.KnownFp != fpA {
			t.Errorf("hke.KnownFp = %s, want %s (записанный в known_hosts)", hke.KnownFp, fpA)
		}
		if hke.PresentedFp != fpB {
			t.Errorf("hke.PresentedFp = %s, want %s (только что предъявленный)", hke.PresentedFp, fpB)
		}
		if hke.Addr == "" {
			t.Error("hke.Addr пуст")
		}
		// Текст Error() — тот же, что раньше собирал fmt.Errorf(%w...): содержит
		// оба отпечатка и слово "ИЗМЕНИЛСЯ" (ErrHostKeyChanged.Error()).
		for _, want := range []string{"ИЗМЕНИЛСЯ", fpA, fpB} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("err.Error() не содержит %q: %q", want, err.Error())
			}
		}
	})

	t.Run("ErrHostKeyMismatch (vault vs known_hosts) — KnownFp/PresentedFp", func(t *testing.T) {
		srv, _ := newFakeSSHServer(t, "127.0.0.1:0")
		creds := credsForFakeSSH(t, srv)
		khPath := filepath.Join(t.TempDir(), "known_hosts")

		sess1, err := ConnectWithHostKey(creds, HostKeyPolicy{KnownHostsPath: khPath, Prompt: alwaysTrustPrompt})
		if err != nil {
			t.Fatalf("первичное подключение: %v", err)
		}
		sess1.Close()

		expected := "SHA256:vaultSaysSomethingElseVaultSaysSomethingEl"
		sess2, err := ConnectWithHostKey(creds, HostKeyPolicy{KnownHostsPath: khPath, ExpectedFingerprint: expected})
		closeIfAny(sess2)

		var hke *HostKeyError
		if !errors.As(err, &hke) {
			t.Fatalf("errors.As(err, *HostKeyError) = false; err = %v", err)
		}
		if !errors.Is(err, ErrHostKeyMismatch) {
			t.Fatalf("errors.Is(err, ErrHostKeyMismatch) = false; err = %v", err)
		}
		if hke.KnownFp != expected {
			t.Errorf("hke.KnownFp = %s, want %s (ожидавшийся по хранилищу)", hke.KnownFp, expected)
		}
		if hke.PresentedFp != srv.Fingerprint() {
			t.Errorf("hke.PresentedFp = %s, want %s (настоящий ключ сервера)", hke.PresentedFp, srv.Fingerprint())
		}
	})

	t.Run("ErrHostKeyUnknown — KnownFp пуст, PresentedFp заполнен", func(t *testing.T) {
		srv, _ := newFakeSSHServer(t, "127.0.0.1:0")
		creds := credsForFakeSSH(t, srv)
		khPath := filepath.Join(t.TempDir(), "known_hosts")

		sess, err := ConnectWithHostKey(creds, HostKeyPolicy{KnownHostsPath: khPath})
		closeIfAny(sess)

		var hke *HostKeyError
		if !errors.As(err, &hke) {
			t.Fatalf("errors.As(err, *HostKeyError) = false; err = %v", err)
		}
		if hke.KnownFp != "" {
			t.Errorf("hke.KnownFp = %q, want пусто (сервер вообще не встречался)", hke.KnownFp)
		}
		if hke.PresentedFp != srv.Fingerprint() {
			t.Errorf("hke.PresentedFp = %s, want %s", hke.PresentedFp, srv.Fingerprint())
		}
	})
}

// mkVaultTmpBlocker создаёт path+".tmp" КАК ДИРЕКТОРИЮ — WriteVaultFile/
// removeKnownHostLines пишут через tmp+rename (как SaveVault), и запись в
// путь, который уже занят директорией, гарантированно и детерминированно
// падает на любой ОС (Windows в том числе) без манипуляций правами доступа.
func mkVaultTmpBlocker(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(path+".tmp", 0755); err != nil {
		t.Fatalf("mkVaultTmpBlocker(%s): %v", path, err)
	}
}

// TestForgetHostKeyVaultWriteFails — ревью PR-4-Б, круг 1, SEC-01 Medium
// (сценарий, найденный ревьюером): раньше GUI различал сбой хранилища и
// сбой known_hosts по strings.Contains(err.Error(), "хранилищ") — голая
// ошибка ОС от WriteVaultFile этого слова не содержит, поэтому сбой ЗАПИСИ
// .avlt приписывался known_hosts, человеку советовали "удалите строку", а
// хранилище оставалось со старым отпечатком — следующая попытка снова
// давала Mismatch/Changed → снова Forget → снова сбой записи: замкнутый
// круг. Тест доказывает: (1) ошибка — ErrForgetVault, НЕ ErrForgetKnownHosts;
// (2) .avlt НЕ изменился (отпечаток остался старым — "ничего не забыто");
// (3) known_hosts вообще не тронут (removeKnownHostLines не вызывается).
func TestForgetHostKeyVaultWriteFails(t *testing.T) {
	pin := "forgetPin1234"
	oldFp := "SHA256:oldFingerprintPlaceholderXXXXXXXXXXXXXXXXXX"
	payload := VaultPayload{Label: "Test", Key: "vpn://abc", Created: "2024-01-01T00:00:00Z", HostKeyFingerprint: oldFp}
	data, err := SealVault(pin, payload, testArgonParams, false)
	if err != nil {
		t.Fatalf("SealVault: %v", err)
	}
	vaultPath := filepath.Join(t.TempDir(), "test.avlt")
	if err := os.WriteFile(vaultPath, data, 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	khPath := filepath.Join(t.TempDir(), "known_hosts")
	addr := "some-host.example:22"
	key, err := fakesrv.NewHostKey()
	if err != nil {
		t.Fatalf("fakesrv.NewHostKey: %v", err)
	}
	if err := appendKnownHost(khPath, addr, key.PublicKey()); err != nil {
		t.Fatalf("appendKnownHost: %v", err)
	}
	khBefore, err := os.ReadFile(khPath)
	if err != nil {
		t.Fatalf("known_hosts до Forget: %v", err)
	}

	mkVaultTmpBlocker(t, vaultPath) // WriteVaultFile упадёт на os.WriteFile(vaultPath+".tmp", ...)

	err = ForgetHostKey(pin, vaultPath, khPath, addr)
	if err == nil {
		t.Fatal("ForgetHostKey вернул nil при заблокированной записи .avlt")
	}
	if !errors.Is(err, ErrForgetVault) {
		t.Errorf("err = %v, want errors.Is(err, ErrForgetVault)", err)
	}
	if errors.Is(err, ErrForgetKnownHosts) {
		t.Errorf("err ошибочно классифицирован как ErrForgetKnownHosts (ложная инструкция «удалите строку»): %v", err)
	}

	// .avlt не тронут — отпечаток остался СТАРЫМ (ничего не забыто).
	stillSealed, err := os.ReadFile(vaultPath)
	if err != nil {
		t.Fatalf("ReadFile(vaultPath) после неудачного Forget: %v", err)
	}
	got, err := OpenVault(pin, stillSealed)
	if err != nil {
		t.Fatalf("OpenVault после неудачного Forget: %v", err)
	}
	if got.HostKeyFingerprint != oldFp {
		t.Errorf("HostKeyFingerprint = %q, want прежний %q (ForgetHostKey не должен был ничего забыть)", got.HostKeyFingerprint, oldFp)
	}

	// known_hosts вообще не тронут.
	khAfter, err := os.ReadFile(khPath)
	if err != nil {
		t.Fatalf("known_hosts после неудачного Forget: %v", err)
	}
	if !bytes.Equal(khBefore, khAfter) {
		t.Fatalf("known_hosts изменился при сбое записи хранилища:\nбыло:  %q\nстало: %q", khBefore, khAfter)
	}
}

// TestForgetHostKeyKnownHostsWriteFails — обратный сценарий: .avlt уже
// успешно перезапечатан (отпечаток стёрт), но правка known_hosts не
// удалась. Ошибка обязана быть ErrForgetKnownHosts (не ErrForgetVault) —
// только эта ветка means "исправьте known_hosts вручную", хранилище уже в
// порядке и трогать его снова не нужно.
func TestForgetHostKeyKnownHostsWriteFails(t *testing.T) {
	pin := "forgetPin1234"
	oldFp := "SHA256:oldFingerprintPlaceholderXXXXXXXXXXXXXXXXXX"
	payload := VaultPayload{Label: "Test", Key: "vpn://abc", Created: "2024-01-01T00:00:00Z", HostKeyFingerprint: oldFp}
	data, err := SealVault(pin, payload, testArgonParams, false)
	if err != nil {
		t.Fatalf("SealVault: %v", err)
	}
	vaultPath := filepath.Join(t.TempDir(), "test.avlt")
	if err := os.WriteFile(vaultPath, data, 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	khPath := filepath.Join(t.TempDir(), "known_hosts")
	addr := "some-host.example:22"
	key, err := fakesrv.NewHostKey()
	if err != nil {
		t.Fatalf("fakesrv.NewHostKey: %v", err)
	}
	if err := appendKnownHost(khPath, addr, key.PublicKey()); err != nil {
		t.Fatalf("appendKnownHost: %v", err)
	}
	khBefore, err := os.ReadFile(khPath)
	if err != nil {
		t.Fatalf("known_hosts до Forget: %v", err)
	}

	mkVaultTmpBlocker(t, khPath) // removeKnownHostLines упадёт на os.WriteFile(khPath+".tmp", ...)

	err = ForgetHostKey(pin, vaultPath, khPath, addr)
	if err == nil {
		t.Fatal("ForgetHostKey вернул nil при заблокированной записи known_hosts")
	}
	if !errors.Is(err, ErrForgetKnownHosts) {
		t.Errorf("err = %v, want errors.Is(err, ErrForgetKnownHosts)", err)
	}
	if errors.Is(err, ErrForgetVault) {
		t.Errorf("err ошибочно классифицирован как ErrForgetVault (хранилище уже перезапечатано успешно): %v", err)
	}

	// .avlt УЖЕ перезапечатан — отпечаток стёрт, несмотря на общий отказ Forget.
	stillSealed, err := os.ReadFile(vaultPath)
	if err != nil {
		t.Fatalf("ReadFile(vaultPath) после Forget: %v", err)
	}
	got, err := OpenVault(pin, stillSealed)
	if err != nil {
		t.Fatalf("OpenVault после Forget: %v", err)
	}
	if got.HostKeyFingerprint != "" {
		t.Errorf("HostKeyFingerprint = %q, want пусто (хранилище должно быть перезапечатано ДО сбоя known_hosts)", got.HostKeyFingerprint)
	}

	// known_hosts не изменился (WriteFile(tmp) упал до Rename).
	khAfter, err := os.ReadFile(khPath)
	if err != nil {
		t.Fatalf("known_hosts после Forget: %v", err)
	}
	if !bytes.Equal(khBefore, khAfter) {
		t.Fatalf("known_hosts изменился, хотя запись должна была упасть:\nбыло:  %q\nстало: %q", khBefore, khAfter)
	}
}
