package core

// АУДИТ-МЕНЮ-QR-LOGIC М-1 и М-2.
// М-2: две копии программы сохраняют конфиги с одинаковыми (или
// одинаковыми без учёта регистра) именами в один каталог. Тест — НАСТОЯЩИЕ
// процессы (дочерние копии тестового бинаря), как у known_hosts
// (TestKnownHostsTwoProcesses): межпроцессной гонки горутины не покажут.

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const confChildEnv = "AMNEZIA_CONF_CHILD" // каталог|вариант|сколько

// TestSaveConfigChild — тело дочернего процесса: сохраняет n конфигов с
// новыми ключами; вариант «upper» — имена в верхнем регистре через одно.
func TestSaveConfigChild(t *testing.T) {
	v := os.Getenv(confChildEnv)
	if v == "" {
		t.Skip("тело дочернего процесса TestSaveConfigTwoProcesses")
	}
	parts := strings.Split(v, "|")
	dir, variant := parts[0], parts[1]
	var n int
	fmt.Sscanf(parts[2], "%d", &n)
	for i := 0; i < n; i++ {
		priv, pub, err := genKey()
		if err != nil {
			t.Fatal(err)
		}
		name := fmt.Sprintf("Клиент-%02d", i)
		if variant == "upper" && i%2 == 1 {
			name = strings.ToUpper(name)
		}
		conf := "[Interface]\nPrivateKey = " + priv + "\nAddress = 10.8.1.2/32\n"
		if _, err := SaveClientConfig(dir, name, conf, ""); err != nil {
			fmt.Printf("CONF-ОТКАЗ %s: %v\n", pub, err)
			continue
		}
		fmt.Printf("CONF-SAVED %s\n", pub)
	}
}

// TestSaveConfigTwoProcesses — два процесса по 30 конфигов с совпадающими
// именами (второй — через одно в другом регистре), 8 раундов. Инвариант:
// каждый конфиг, о котором процесс сказал «сохранён», находится по ключу.
// Молчаливая потеря — «сохранён», а файла с этим ключом нет.
func TestSaveConfigTwoProcesses(t *testing.T) {
	if os.Getenv(confChildEnv) != "" {
		t.Skip("дочерний процесс")
	}
	const perChild, rounds = 30, 8
	for r := 0; r < rounds; r++ {
		dir := filepath.Join(t.TempDir(), "Конфигурации")
		var wg sync.WaitGroup
		outs := make([]string, 2)
		errs := make([]error, 2)
		for c, variant := range []string{"same", "upper"} {
			wg.Add(1)
			go func(c int, variant string) {
				defer wg.Done()
				cmd := exec.Command(os.Args[0], "-test.run", "^TestSaveConfigChild$", "-test.count=1")
				cmd.Env = append(os.Environ(), confChildEnv+"="+dir+"|"+variant+"|"+fmt.Sprint(perChild))
				out, err := cmd.CombinedOutput()
				outs[c], errs[c] = string(out), err
			}(c, variant)
		}
		wg.Wait()
		var saved, refused int
		var silent []string
		for c := 0; c < 2; c++ {
			if errs[c] != nil {
				t.Fatalf("раунд %d: процесс %d упал: %v\n%s", r, c, errs[c], outs[c])
			}
			for _, l := range strings.Split(outs[c], "\n") {
				switch {
				case strings.HasPrefix(l, "CONF-SAVED "):
					saved++
					pub := strings.TrimSpace(strings.TrimPrefix(l, "CONF-SAVED "))
					if got := FindSavedConfig(dir, nil, pub); got.State != SavedFound {
						silent = append(silent, pub)
					}
				case strings.HasPrefix(l, "CONF-ОТКАЗ "):
					refused++
				}
			}
		}
		if saved+refused != 2*perChild {
			t.Fatalf("раунд %d: проверка ничего не значит: исходов %d из %d", r, saved+refused, 2*perChild)
		}
		if len(silent) != 0 {
			t.Fatalf("раунд %d: МОЛЧА потеряно конфигов (сказано «сохранён», файла с ключом нет): %d из %d", r, len(silent), saved)
		}
	}
}

// TestConfigsLockTimeout — замок каталога держит другой: по таймауту —
// громкий отказ ErrConfigsBusy, файл не записан.
func TestConfigsLockTimeout(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "Конфигурации")
	os.MkdirAll(dir, 0o700)
	lf, err := os.OpenFile(filepath.Join(dir, configsLockName), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer lf.Close()
	if busy, err := tryLockFile(lf); err != nil || busy {
		t.Fatalf("замок не взят: busy=%v err=%v", busy, err)
	}
	defer unlockFile(lf)
	old := configsLockWait
	configsLockWait = 200 * time.Millisecond
	defer func() { configsLockWait = old }()
	// Замок в ЭТОМ процессе: flock на Unix — на открытое описание файла,
	// второе открытие из того же процесса тоже его не получит; LockFileEx на
	// Windows — так же. Поэтому проверка честная и без второго процесса.
	_, err = SaveClientConfig(dir, "Петя", "[Interface]\n", "")
	if !errors.Is(err, ErrConfigsBusy) || !strings.Contains(err.Error(), "конфиг не сохранён, повторите") {
		t.Fatalf("таймаут замка: %v", err)
	}
	if _, serr := os.Stat(filepath.Join(dir, "Петя.conf")); serr == nil {
		t.Error("при занятом замке файл записан")
	}
}

// TestSameClientFileTable — М-1: «занятый файл — не мой», если он не
// читается, не разбирается или с другим ключом; «мой» — только этот ключ
// или прежний (rekey). Подмена «не читается → мой» обязана краснеть.
func TestSameClientFileTable(t *testing.T) {
	priv, pub, _ := genKey()
	otherPriv, _, _ := genKey()
	_, oldPub, _ := genKey()
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		os.WriteFile(p, []byte(body), 0o600)
		return p
	}
	mineP := write("mine.conf", "[Interface]\nPrivateKey = "+priv+"\n")
	otherP := write("other.conf", "[Interface]\nPrivateKey = "+otherPriv+"\n")
	junkP := write("junk.conf", "не конфиг")
	unreadP := write("unread.conf", "[Interface]\nPrivateKey = "+priv+"\n") // свой ключ, но НЕ читается
	old := readSavedFile
	readSavedFile = func(p string) ([]byte, error) {
		if p == unreadP {
			return nil, errors.New("open " + p + ": Access is denied.")
		}
		return old(p)
	}
	defer func() { readSavedFile = old }()
	for _, c := range []struct {
		name           string
		path, mine, rp string
		want           bool
	}{
		{"тот же ключ", mineP, pub, "", true},
		{"прежний ключ (rekey)", otherP, pub, pubOf(t, otherPriv), true},
		{"другой ключ", otherP, pub, oldPub, false},
		{"не разбирается", junkP, pub, "", false},
		{"не читается (свой ключ внутри)", unreadP, pub, "", false},
		{"файла нет", filepath.Join(dir, "нет.conf"), pub, "", false},
		{"у нового конфига ключа нет", otherP, "", "", false},
	} {
		if got := sameClientFile(c.path, c.mine, c.rp, ".conf"); got != c.want {
			t.Errorf("%s: %v, ожидалось %v", c.name, got, c.want)
		}
	}
}

func pubOf(t *testing.T, priv string) string {
	t.Helper()
	p, err := pubFromPriv(priv)
	if err != nil {
		t.Fatal(err)
	}
	return p
}
