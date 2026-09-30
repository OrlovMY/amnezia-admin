package core

// Чтение known_hosts под замком (аудит known_hosts, М-1). На Windows rename
// поверх файла, открытого другим процессом или потоком на чтение, отказывает
// «файл занят» (посылка проверена TestKnownHostsRenameOverOpenFile). Чтобы
// окно чтения было не микросекундным, а сотни миллисекунд, файл большой:
// 50000 настоящих записей — knownhosts.New держит его открытым, пока
// разбирает. Писатель стартует, когда читатель уже внутри. С замком писатель
// ждёт и пишет; без замка на Windows rename отказывает.

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"amnezia-admin/internal/fakesrv"
	"golang.org/x/crypto/ssh/knownhosts"
)

// TestKnownHostsRenameOverOpenFile — посылка: на Windows запись поверх
// known_hosts, открытого на чтение, отказывает; на Unix — проходит.
func TestKnownHostsRenameOverOpenFile(t *testing.T) {
	kh := filepath.Join(t.TempDir(), "known_hosts")
	if err := os.WriteFile(kh, []byte("# x\n"), 0600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(kh)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	k, _ := fakesrv.NewHostKey()
	err = appendKnownHost(kh, "127.0.0.1:2222", k.PublicKey())
	if runtime.GOOS == "windows" && err == nil {
		t.Error("на Windows rename поверх открытого файла прошёл — посылка замка на чтение неверна")
	}
	if runtime.GOOS != "windows" && err != nil {
		t.Errorf("на %s rename поверх открытого файла обязан проходить: %v", runtime.GOOS, err)
	}
}

func TestKnownHostsReadHoldsLock(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skipf("ОС %s: rename поверх открытого файла здесь разрешён (TestKnownHostsRenameOverOpenFile), замку на чтение нечего защищать", runtime.GOOS)
	}
	k, err := fakesrv.NewHostKey()
	if err != nil {
		t.Fatal(err)
	}
	var big bytes.Buffer
	for i := 0; i < 50000; i++ {
		big.WriteString(knownhosts.Line([]string{fmt.Sprintf("[10.%d.%d.%d]:2222", i/65536, i/256%256, i%256)}, k.PublicKey()))
		big.WriteByte('\n')
	}
	for round := 0; round < 3; round++ {
		kh := filepath.Join(t.TempDir(), "known_hosts")
		if err := os.WriteFile(kh, big.Bytes(), 0600); err != nil {
			t.Fatal(err)
		}
		var wg sync.WaitGroup
		wg.Add(1)
		start := time.Now()
		var readDur time.Duration
		go func() {
			defer wg.Done()
			remote := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 2222}
			_, _ = lookupKnownHost(kh, "127.0.0.1:2222", remote, k.PublicKey())
			readDur = time.Since(start)
		}()
		time.Sleep(20 * time.Millisecond)
		werr := appendKnownHost(kh, "127.0.0.1:3333", k.PublicKey())
		wg.Wait()
		if readDur < 60*time.Millisecond {
			t.Fatalf("чтение заняло %v — окно слишком узкое, тест ничего не доказывает (увеличьте файл)", readDur)
		}
		if werr != nil {
			t.Errorf("раунд %d: запись во время чтения отказала: %v", round, werr)
		}
	}
}
