package core

// Гонка записи known_hosts (найдено канарейкой A3б PR-4): две копии
// программы, впервые подключаясь к незнакомым серверам, пишут один файл
// known_hosts. Тест — НАСТОЯЩИЕ процессы (дочерние копии тестового бинаря),
// а не горутины: межпроцессной гонки внутрипроцессный мьютекс не видит.
// Серверы — fakesrv.SSHServer на эфемерных портах 127.0.0.1.

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

	"amnezia-admin/internal/fakesrv"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

const khChildEnv = "AMNEZIA_KH_CHILD" // адреса через запятую
const khPathEnv = "AMNEZIA_KH_PATH"

// TestKnownHostsChild — тело дочернего процесса: подключается по очереди к
// каждому адресу, принимая ключ (Prompt = да), и пишет в общий known_hosts.
// Без переменной окружения — пропуск: это не самостоятельный тест.
func TestKnownHostsChild(t *testing.T) {
	addrs := os.Getenv(khChildEnv)
	if addrs == "" {
		t.Skip("тело дочернего процесса TestKnownHostsTwoProcesses")
	}
	for _, a := range strings.Split(addrs, ",") {
		host, port, _ := strings.Cut(a, ":")
		sess, err := ConnectWithHostKey(&ServerCreds{Host: host, Port: port, User: fakeSSHUser, Password: fakeSSHPassword},
			HostKeyPolicy{KnownHostsPath: os.Getenv(khPathEnv), Prompt: alwaysTrustPrompt})
		if err != nil {
			t.Errorf("KH-ОТКАЗ %s: %v", a, err)
			continue
		}
		sess.Close()
	}
}

// TestKnownHostsTwoProcesses — два процесса по 40 новых серверов каждый,
// один known_hosts, 10 раундов (на Linux гонка редка — окно узкое, поэтому
// серверов много). Инвариант: оба процесса завершились успешно, и в файле
// есть строка КАЖДОГО из 80 серверов. Отдельно считается МОЛЧАЛИВАЯ потеря:
// сервер, подключение к которому прошло («ключ принят»), а строки нет.
func TestKnownHostsTwoProcesses(t *testing.T) {
	if os.Getenv(khChildEnv) != "" {
		t.Skip("дочерний процесс")
	}
	const perChild, rounds = 40, 10
	for r := 0; r < rounds; r++ {
		kh := filepath.Join(t.TempDir(), "known_hosts")
		var groups [2][]string
		var fps []string
		wantFp := map[string]string{}
		for c := 0; c < 2; c++ {
			for i := 0; i < perChild; i++ {
				srv, _ := newFakeSSHServer(t, "127.0.0.1:0")
				groups[c] = append(groups[c], srv.Addr())
				fps = append(fps, srv.Addr())
				wantFp[knownhosts.Normalize(srv.Addr())] = srv.Fingerprint()
			}
		}
		var wg sync.WaitGroup
		outs := make([]string, 2)
		errs := make([]error, 2)
		for c := 0; c < 2; c++ {
			wg.Add(1)
			go func(c int) {
				defer wg.Done()
				cmd := exec.Command(os.Args[0], "-test.run", "^TestKnownHostsChild$", "-test.count=1")
				cmd.Env = append(os.Environ(), khChildEnv+"="+strings.Join(groups[c], ","), khPathEnv+"="+kh)
				out, err := cmd.CombinedOutput()
				outs[c], errs[c] = string(out), err
			}(c)
		}
		wg.Wait()
		for c := 0; c < 2; c++ {
			if errs[c] != nil {
				t.Errorf("раунд %d: процесс %d упал: %v\n%s", r, c, errs[c], outs[c])
			}
		}
		data, _ := os.ReadFile(kh)
		missing := khMissing(string(data), fps)
		// Второй признак (QA-01): разбор итогового файла ТЕМ ЖЕ разборщиком,
		// что у программы (ssh.ParseKnownHosts), — ровно по одной записи на
		// сервер, каждая с его ключом; полузаписанная или склеенная строка —
		// ошибка разбора.
		for _, msg := range khParseCheck(data, wantFp) {
			t.Errorf("раунд %d: %s", r, msg)
		}
		refused := strings.Join(outs[:], "\n")
		var silent []string
		for _, m := range missing {
			if !strings.Contains(refused, "KH-ОТКАЗ "+m+":") {
				silent = append(silent, m)
			}
		}
		if len(missing) != 0 {
			t.Errorf("раунд %d: в known_hosts нет %d из %d серверов; из них МОЛЧА (подключение прошло, строки нет): %d %v",
				r, len(missing), len(fps), len(silent), silent)
		}
	}
}

// khMissing — адреса host:port, для которых в known_hosts нет строки
// ([host]:port — форма knownhosts.Line для порта не 22).
func khMissing(data string, addrs []string) []string {
	var miss []string
	for _, a := range addrs {
		host, port, _ := strings.Cut(a, ":")
		p, _ := strconv.Atoi(port)
		if !strings.Contains(data, fmt.Sprintf("[%s]:%d ", host, p)) {
			miss = append(miss, a)
		}
	}
	return miss
}

var _ = fakesrv.New

// khParseCheck — разбор known_hosts через ssh.ParseKnownHosts: ровно одна
// запись на каждый адрес из want, с его отпечатком, и ничего сверх.
func khParseCheck(data []byte, want map[string]string) []string {
	var bad []string
	seen := map[string]int{}
	rest := data
	for len(bytes.TrimSpace(rest)) > 0 {
		_, hosts, key, _, next, err := ssh.ParseKnownHosts(rest)
		if err != nil {
			bad = append(bad, fmt.Sprintf("known_hosts не разбирается: %v", err))
			break
		}
		for _, h := range hosts {
			seen[h]++
			if fp, ok := want[h]; !ok {
				bad = append(bad, fmt.Sprintf("лишняя запись для %s", h))
			} else if got := ssh.FingerprintSHA256(key); got != fp {
				bad = append(bad, fmt.Sprintf("%s: ключ %s, ждали %s", h, got, fp))
			}
		}
		rest = next
	}
	for h := range want {
		if seen[h] != 1 {
			bad = append(bad, fmt.Sprintf("%s: записей %d, ждали ровно 1", h, seen[h]))
		}
	}
	return bad
}
