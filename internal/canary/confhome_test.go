package canary

// Долг канарейки 02.10: дочерние amnezia-admin сохраняли конфиги canary-* в
// НАСТОЯЩИЙ каталог данных пользователя (%LOCALAPPDATA%\amnezia-admin\…) —
// и при прогоне канарейки, и при каждом go test этого пакета (у пакета не
// было подмены каталога данных). Теперь:
//   - TestMain (runIsolated) подменяет каталог данных всего процесса на
//     «унаследованный» временный и после прогона требует, чтобы в нём не
//     появилось НИ ОДНОГО файла: настоящий каталог данных тесты не видят
//     вовсе, а запись «по наследству» обнаруживается и роняет прогон;
//   - TestChildConfigsInConfHome — настоящий дочерний процесс: конфиг лежит
//     в Env.ConfHome, путь в выводе — оттуда, в унаследованном — пусто.
// Подмена «childEnv не добавляет ChildDataEnv» роняет оба поведением.

import (
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// inheritedHome — каталог данных, который наследует любой дочерний процесс
// из окружения теста. Ничего писать в него нельзя.
var inheritedHome string

func runIsolated(m *testing.M) int {
	dir, err := os.MkdirTemp("", "amnezia-canary-inherited-")
	if err != nil {
		fmt.Fprintln(os.Stderr, "TestMain:", err)
		return 1
	}
	defer os.RemoveAll(dir)
	// Кэши Go выводятся из HOME — запомнить их до подмены (как cmd/cli).
	for _, k := range []string{"GOMODCACHE", "GOPATH", "GOCACHE"} {
		if os.Getenv(k) != "" {
			continue
		}
		if out, err := exec.Command("go", "env", k).Output(); err == nil {
			if v := strings.TrimSpace(string(out)); v != "" {
				os.Setenv(k, v)
			}
		}
	}
	inheritedHome = dir
	for _, kv := range ChildDataEnv(dir) {
		k, v, _ := strings.Cut(kv, "=")
		os.Setenv(k, v)
	}
	code := m.Run()
	if leaked := filesUnder(dir); len(leaked) > 0 {
		fmt.Fprintf(os.Stderr, "СТОРОЖ: прогон записал %d файл(ов) в унаследованный каталог данных (на машине владельца это настоящий каталог данных amnezia-admin): %s\n",
			len(leaked), strings.Join(leaked, "; "))
		return 1
	}
	return code
}

// filesUnder — файлы под dir (имена относительно dir; содержимое не читается).
func filesUnder(dir string) []string {
	var out []string
	filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			rel, _ := filepath.Rel(dir, p)
			out = append(out, rel)
		}
		return nil
	})
	return out
}

// TestChildConfigsInConfHome — дочерний amnezia-admin (настоящий, против
// fakesrv) сохраняет конфиг canary-* в Env.ConfHome, путь в выводе (его
// показывают подсказки К3/К8) — из ConfHome, в унаследованном каталоге
// данных — ни одного файла.
func TestChildConfigsInConfHome(t *testing.T) {
	f := emptyFake(t, false)
	f.env.NewBin = newCLI(t)
	r := f.env.cli(f.env.NewBin, f.env.KeyEnv, "add", "-name", "canary-iso")
	if r.code != 0 {
		t.Fatalf("add: код %d: %s", r.code, r.title)
	}
	p := savedPath(r.conf)
	if p == "" {
		t.Fatalf("путь сохранённого конфига не напечатан: %q", r.conf)
	}
	if rel, err := filepath.Rel(f.env.ConfHome, p); err != nil || strings.HasPrefix(rel, "..") {
		t.Errorf("конфиг сохранён в %q — вне временного ConfHome %q", p, f.env.ConfHome)
	}
	if got := filesUnder(f.env.ConfHome); len(got) == 0 {
		t.Errorf("в ConfHome нет ни одного файла — дочерняя программа писала не туда")
	}
	if leaked := filesUnder(inheritedHome); len(leaked) > 0 {
		t.Errorf("дочерняя программа записала в унаследованный каталог данных: %v", leaked)
	}
}

// TestChildConfHomeLazy — Env без ConfHome (собранный не через
// cmd/canary-a3b) всё равно не отдаёт дочерней программе наследуемый
// каталог данных: заводится временный.
func TestChildConfHomeLazy(t *testing.T) {
	e := &Env{}
	env, err := e.childEnv(nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(e.ConfHome) })
	if e.ConfHome == "" || e.ConfHome == inheritedHome {
		t.Fatalf("ConfHome %q", e.ConfHome)
	}
	last := map[string]string{}
	for _, kv := range env {
		k, v, _ := strings.Cut(kv, "=")
		last[strings.ToUpper(k)] = v
	}
	for _, k := range []string{"LOCALAPPDATA", "XDG_CONFIG_HOME", "HOME"} {
		if last[k] != e.ConfHome {
			t.Errorf("%s дочерней программы = %q, ждали %q", k, last[k], e.ConfHome)
		}
	}
}
