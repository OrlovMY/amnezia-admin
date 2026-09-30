package core

// Незнание (CLAUDE.md): ключ, который не удалось записать в known_hosts, —
// это не «ключ сохранён». Тест доезда — настоящий SSH (fakesrv на
// эфемерном порту), запись ломается каталогом на месте замка; тест
// различения — отказ записи отличается и от «неизвестен», и от «сменился».

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"amnezia-admin/internal/fakesrv"
)

// blockKnownHostsWrite — настоящая поломка ЗАПИСИ, при которой чтение и
// замок работают: на Windows known_hosts только для чтения (rename поверх
// него отказывает), на Unix каталог без права записи (временный файл не
// создать). Под root на Unix права не действуют — пропуск с причиной.
func blockKnownHostsWrite(t *testing.T, kh string) {
	t.Helper()
	if err := os.WriteFile(kh, []byte("# пусто\n"), 0600); err != nil {
		t.Fatal(err)
	}
	lf, err := os.OpenFile(kh+".lock", os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		t.Fatal(err)
	}
	lf.Close()
	if runtime.GOOS == "windows" {
		if err := os.Chmod(kh, 0400); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { os.Chmod(kh, 0600) })
		return
	}
	if os.Geteuid() == 0 {
		t.Skip("под root права каталога не мешают записи — поломку записи так не выразить")
	}
	dir := filepath.Dir(kh)
	if err := os.Chmod(dir, 0500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(dir, 0700) })
}

func TestKnownHostsWriteFailureIsNotSaved(t *testing.T) {
	srv, _ := newFakeSSHServer(t, "127.0.0.1:0")
	kh := filepath.Join(t.TempDir(), "known_hosts")
	blockKnownHostsWrite(t, kh)
	for _, tc := range []struct {
		name string
		pol  HostKeyPolicy
	}{
		{"подтверждение человеком", HostKeyPolicy{KnownHostsPath: kh, Prompt: alwaysTrustPrompt}},
		{"закреплённый отпечаток", HostKeyPolicy{KnownHostsPath: kh, ExpectedFingerprint: srv.Fingerprint()}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sess, err := ConnectWithHostKey(credsForFakeSSH(t, srv), tc.pol)
			if err == nil {
				sess.Close()
				t.Fatal("подключение прошло, хотя ключ не записан в known_hosts")
			}
			if !errors.Is(err, ErrKnownHostsWrite) {
				t.Errorf("ждали ErrKnownHostsWrite: %v", err)
			}
			for _, other := range []error{ErrHostKeyUnknown, ErrHostKeyChanged, ErrHostKeyMismatch} {
				if errors.Is(err, other) {
					t.Errorf("отказ записи выдан за %q: %v", other, err)
				}
			}
			if !strings.Contains(err.Error(), "не сохранён") {
				t.Errorf("текст не говорит «не сохранён»: %v", err)
			}
		})
	}
	if b, _ := os.ReadFile(kh); string(b) != "# пусто\n" {
		t.Errorf("known_hosts изменился, хотя запись отказала: %q", b)
	}
}

// TestKnownHostsLockBusy — замок держит «другая копия»: запись ждёт и,
// дождавшись knownHostsLockWait, отказывает ErrKnownHostsBusy, а не пишет
// мимо замка. Держатель — второй открытый дескриптор того же файла замка
// (flock и LockFileEx различают дескрипторы и внутри одного процесса).
func TestKnownHostsLockBusy(t *testing.T) {
	kh := filepath.Join(t.TempDir(), "known_hosts")
	holder, err := os.OpenFile(kh+".lock", os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Close()
	busy, err := tryLockFile(holder)
	if err != nil || busy {
		t.Fatalf("держатель не взял замок: busy=%v err=%v", busy, err)
	}
	start := time.Now()
	signer, err := fakesrv.NewHostKey()
	if err != nil {
		t.Fatal(err)
	}
	key := signer.PublicKey()
	err = appendKnownHost(kh, "127.0.0.1:2222", key)
	if !errors.Is(err, ErrKnownHostsBusy) {
		t.Fatalf("ждали ErrKnownHostsBusy при занятом замке: %v", err)
	}
	if d := time.Since(start); d < knownHostsLockWait {
		t.Errorf("отказ через %v — раньше срока ожидания %v", d, knownHostsLockWait)
	}
	if _, err := os.Stat(kh); !os.IsNotExist(err) {
		t.Errorf("known_hosts записан мимо занятого замка")
	}
	if err := unlockFile(holder); err != nil {
		t.Fatal(err)
	}
	if err := appendKnownHost(kh, "127.0.0.1:2222", key); err != nil {
		t.Fatalf("после снятия замка запись обязана пройти: %v", err)
	}
}
