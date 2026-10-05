package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"amnezia-admin/core"
)

// cliSession — сессия к fakesrv из setupFakeSSHForRunWithExec (known_hosts
// уже прогрет).
func cliSession(t *testing.T, key, kh string) *core.Session {
	t.Helper()
	cfg, err := core.DecodeVpnKey(key)
	if err != nil {
		t.Fatal(err)
	}
	creds, err := core.CredsFromConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	s, err := core.ConnectWithHostKey(creds, core.HostKeyPolicy{KnownHostsPath: kh})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s
}

// TestCLIProgressOnlyTTY — без терминала прогресса нет (вывод прежний); с
// терминалом — «[NN%] прочитано X из Y…» и предупреждение о записи.
func TestCLIProgressOnlyTTY(t *testing.T) {
	if cliProgress(&bytes.Buffer{}, false) != nil {
		t.Fatal("без терминала есть прогресс")
	}
	var b bytes.Buffer
	fn := cliProgress(&b, true)
	fn(core.Progress{Stage: core.StageRead, Done: 4, Total: 8, Text: "прочитано файлов 4 из 8 — amnezia-awg (проход 1 из 2)"})
	fn(core.Progress{Stage: core.StageContainer, Done: 0, Total: 1, Writing: true, Text: "контейнер 1 из 1"})
	out := b.String()
	if !strings.Contains(out, "[ 50%] прочитано файлов 4 из 8") || !strings.Contains(out, "прервать нельзя") {
		t.Errorf("прогресс:\n%q", out)
	}
}

// TestCLICtrlC — Ctrl+C (отменённый контекст): backup — копия не
// сохранена, файла нет, код 2; restore до записи — на сервер ничего не
// записано, код 2.
func TestCLICtrlC(t *testing.T) {
	key, kh, srv := setupFakeSSHForRunWithExec(t)
	sess := cliSession(t, key, kh)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	dir := t.TempDir()
	var out, errOut bytes.Buffer
	code := runBackup(ctx, strings.NewReader(""), &out, &errOut, false, sess, filepath.Join(dir, "c.aabk"), "", true, time.Now())
	if code != 2 || !strings.Contains(out.String(), "Отменено — копия не сохранена") {
		t.Fatalf("backup: код %d:\n%s\n%s", code, out.String(), errOut.String())
	}
	if ents, _ := os.ReadDir(dir); len(ents) != 0 {
		t.Errorf("после отмены в каталоге: %v", ents)
	}

	p := filepath.Join(t.TempDir(), "ok.aabk")
	if code, _, e := cliRun(t, kh, "", "backup", "-key", key, "-o", p, "-no-password"); code != 0 {
		t.Fatalf("копия: %d %s", code, e)
	}
	out.Reset()
	code = runRestore(ctx, strings.NewReader(""), &out, &errOut, false, sess, p, "", true, false, false, true, time.Now())
	if code != 2 || !strings.Contains(out.String(), "на сервер ничего не записано") || flocks(srv) != 0 {
		t.Fatalf("restore: код %d записей %d:\n%s", code, flocks(srv), out.String())
	}
}
