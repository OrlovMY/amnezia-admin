package core

// Раунд 4 (аудит AU-LOGIC 1e90660): H1 — замок на каталоге /run/lock и
// настоящий flock; M1 — ветки скрипта «нет утилиты», «отказ sha256sum»,
// «второй mv при rename» доезжают через настоящий скрипт; L3 — текст отката
// с кодом 6.

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"amnezia-admin/internal/fakesrv"
)

// TestMissingContainerToolRealScript — M1: утилиты контейнера нет в PATH
// настоящего скрипта → код 5 даёт сам скрипт; ничего не записано.
func TestMissingContainerToolRealScript(t *testing.T) {
	for _, tool := range []string{"sha256sum", "base64", "mv", "rm"} {
		t.Run(tool, func(t *testing.T) {
			srv := fakesrv.New()
			srv.MissingTool = tool
			sess := NewSessionWithRunner(srv, testCreds())
			c := awgContainer()
			wg, tbl := snapshot(t, srv, c)
			_, err := sess.AddUser(c, "Carol")
			assertOnly(t, err, ErrServerToolMissing)
			if !strings.Contains(err.Error(), "нет утилиты "+tool+" (код 5)") {
				t.Errorf("ждали код 5 от скрипта с названием %s: %v", tool, err)
			}
			assertUnchanged(t, srv, c, wg, tbl)
			if srv.TempLeft != 0 {
				t.Errorf("оставлено временных файлов: %d", srv.TempLeft)
			}
		})
	}
}

// TestSha256FailureRealScript — M1: sha256sum есть, но падает → сумма не
// посчитана: «неизвестно», не «изменён» и не «absent»; ничего не записано.
func TestSha256FailureRealScript(t *testing.T) {
	srv := fakesrv.New()
	srv.FailTool = "sha256sum"
	sess := NewSessionWithRunner(srv, testCreds())
	c := awgContainer()
	wg, tbl := snapshot(t, srv, c)
	_, err := sess.AddUser(c, "Carol")
	assertOnly(t, err, ErrWriteUnknown)
	// Прямая проверка мимо assertOnly (N2): подмена в помощнике не глушит.
	if err == nil || errors.Is(err, ErrCASMismatch) || !strings.Contains(err.Error(), "код выхода 1") {
		t.Errorf("отказ sha256sum обязан дать «неизвестно» с кодом 1, не «изменён»: %v", err)
	}
	assertUnchanged(t, srv, c, wg, tbl)
	if srv.TempLeft != 0 {
		t.Errorf("оставлено временных файлов: %d", srv.TempLeft)
	}
}

// TestRenameMvFailureRealScript — M1: при rename (wg0.conf не пишется) mv
// clientsTable падает → код 1: «неизвестно», не успех и не «частично»
// (частичной записи нет — wg0.conf не трогали).
func TestRenameMvFailureRealScript(t *testing.T) {
	srv := fakesrv.New()
	srv.FailMvTo = "clientsTable"
	sess := NewSessionWithRunner(srv, testCreds())
	c := awgContainer()
	clients, err := sess.LoadClients(c)
	if err != nil {
		t.Fatal(err)
	}
	wg, tbl := snapshot(t, srv, c)
	err = sess.RenameUser(c, clients[0].ClientID, "Renamed")
	assertOnly(t, err, ErrWriteUnknown)
	if err != nil && strings.Contains(err.Error(), "частично") {
		t.Errorf("при rename частичной записи быть не может: %v", err)
	}
	assertUnchanged(t, srv, c, wg, tbl)
}

// TestLockOpenFailureIsNotWritten — H1: код 66 (flock не открыл замок) —
// docker exec не запускался: «ничего не записано», не «неизвестно».
func TestLockOpenFailureIsNotWritten(t *testing.T) {
	r := stubRunner{base: fakesrv.New(), match: "flock -w 15",
		err: &fakesrv.ExitError{Cmd: "x", Status: 66, Stderr: "flock: cannot open lock file /run/lock: Permission denied"}}
	_, err := NewSessionWithRunner(r, testCreds()).AddUser(awgContainer(), "Carol")
	assertOnly(t, err, ErrServerToolMissing)
	if !strings.Contains(err.Error(), "ничего не записано") {
		t.Errorf("текст обязан сказать «ничего не записано»: %v", err)
	}
}

// TestRollbackPartialText — L3: откат с кодом 6 — wg0.conf вернулся,
// clientsTable — нет; так и сказано.
func TestRollbackPartialText(t *testing.T) {
	srv := fakesrv.New()
	srv.WriteFault = map[int]fakesrv.WriteFault{2: {Code: 6}}
	srv.FailSyncconf = errBoom
	_, err := NewSessionWithRunner(srv, testCreds()).AddUser(awgContainer(), "Carol")
	if err == nil || !strings.Contains(err.Error(), "wg0.conf вернулся к прежнему, clientsTable — нет") {
		t.Errorf("ждали текст частичного отката: %v", err)
	}
}

var errBoom = &fakesrv.ExitError{Cmd: "wg syncconf", Status: 1, Stderr: "I/O error"}

// casLockPrefix — настоящая строка замка из CASWriteCommand (до docker exec).
func casLockPrefix(t *testing.T) string {
	t.Helper()
	cmd, err := CASWriteCommand(CASLabelApply, "amnezia-awg", "/opt/amnezia/awg", strings.Repeat("a", 64), CASAbsent)
	if err != nil {
		t.Fatal(err)
	}
	i := strings.Index(cmd, " docker exec ")
	if i < 0 {
		t.Fatal("в команде нет docker exec")
	}
	return cmd[:i]
}

// TestCASLockLineRealFlock — H1: настоящая строка замка (timeout + flock на
// CASLockDir) исполняется настоящими sh и flock: свободный замок — 0,
// занятый — 4. Если доступен `sudo -n` (раннеры CI), то же в обоих порядках
// «пользователь, потом root» и «root, потом пользователь»: ни в одном нет 66.
// Только Linux: на Windows и macOS нет flock(1) и /run/lock — причина
// названа в пропуске. На Linux отсутствие flock — провал, не пропуск.
func TestCASLockLineRealFlock(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skipf("ОС %s: нет flock(1) из util-linux и /run/lock — строку замка исполняет только Linux (целевой сервер — Linux)", runtime.GOOS)
	}
	for _, tool := range []string{"sh", "flock", "timeout"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Fatalf("на Linux нет %s — строку замка проверить нечем: %v", tool, err)
		}
	}
	prefix := casLockPrefix(t)
	run := func(sudo bool) int {
		line := prefix + " true"
		var cmd *exec.Cmd
		if sudo {
			cmd = exec.Command("sudo", "-n", "sh", "-c", line)
		} else {
			cmd = exec.Command("sh", "-c", line)
		}
		out, err := cmd.CombinedOutput()
		if err == nil {
			return 0
		}
		var ee *exec.ExitError
		if !asExit(err, &ee) {
			t.Fatalf("запуск %q: %v", line, err)
		}
		t.Logf("%q (sudo=%v): код %d, вывод %s", line, sudo, ee.ExitCode(), out)
		return ee.ExitCode()
	}
	if code := run(false); code != 0 {
		t.Fatalf("свободный замок: код %d, ждали 0", code)
	}

	// Каталога замка нет: 66 и НИЧЕГО не создано (косая черта в конце).
	// Отдельный путь вместо настоящего /run/lock.
	missing := filepath.Join(t.TempDir(), "nolock")
	if !strings.HasSuffix(prefix, " "+CASLockDir) {
		t.Fatalf("строка замка не кончается на %q: %q", CASLockDir, prefix)
	}
	// Путь подменяется с сохранением того, как CASLockDir оканчивается:
	// косую черту добавляет не тест, а сама константа.
	line := strings.TrimSuffix(prefix, CASLockDir) + missing + strings.TrimPrefix(CASLockDir, "/run/lock") + " true"
	out, err := exec.Command("sh", "-c", line).CombinedOutput()
	var ee *exec.ExitError
	if !asExit(err, &ee) || ee.ExitCode() != 66 {
		t.Errorf("каталога замка нет: ждали код 66, получили %v (%s)", err, out)
	}
	if _, statErr := os.Stat(missing); !os.IsNotExist(statErr) {
		t.Errorf("flock создал %s, хотя каталога не было (нужна косая черта в конце)", missing)
	}

	// Занятый замок: держит другой процесс, строка ждёт 15 с — укорочено
	// нельзя (флаги — часть протокола), поэтому держим дольше ожидания.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	holder := exec.CommandContext(ctx, "flock", CASLockDir, "sleep", "30")
	if err := holder.Start(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(500 * time.Millisecond)
	if code := run(false); code != 4 {
		t.Errorf("занятый замок: код %d, ждали 4", code)
	}
	cancel()
	_ = holder.Wait()

	if exec.Command("sudo", "-n", "true").Run() != nil {
		if os.Getenv("CI") != "" {
			t.Fatal("CI без sudo -n: порядок «пользователь, потом root» (H1) не проверен")
		}
		t.Skip("нет sudo -n (не CI): порядок «пользователь, потом root» проверяется в CI и журналом WSL в отчёте")
	}
	for _, order := range [][2]bool{{false, true}, {true, false}} {
		for _, sudo := range order {
			if code := run(sudo); code != 0 {
				t.Errorf("порядок %v: sudo=%v дал код %d (66 — прежний дефект H1)", order, sudo, code)
			}
		}
	}
}

func asExit(err error, target **exec.ExitError) bool {
	ee, ok := err.(*exec.ExitError)
	if ok {
		*target = ee
	}
	return ok
}
