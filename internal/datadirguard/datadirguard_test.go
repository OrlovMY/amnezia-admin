package datadirguard

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestMain(m *testing.M) { os.Exit(Run(m, nil)) }

// TestLeakChild — пишет в каталог данных ТОЛЬКО по просьбе родителя.
func TestLeakChild(t *testing.T) {
	base := os.Getenv("LOCALAPPDATA")
	if runtime.GOOS != "windows" {
		base = os.Getenv("XDG_CONFIG_HOME")
	}
	if os.Getenv("DATADIRGUARD_RMDIR") == "1" {
		// каталог исчез — обойти его нельзя
		if err := os.RemoveAll(base); err != nil {
			t.Fatal(err)
		}
		return
	}
	if os.Getenv("DATADIRGUARD_LEAK") != "1" {
		t.Skip("запускается из TestGuardCatchesLeak")
	}
	p := filepath.Join(base, "amnezia-admin", "Конфигурации", "canary-leak.conf")
	os.MkdirAll(filepath.Dir(p), 0o700)
	if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestGuardCatchesLeak — КАНАРЕЙКА сторожа: прогон, записавший файл в
// унаследованный каталог данных, обязан упасть, назвав файл; тот же прогон
// без записи — пройти.
func TestGuardCatchesLeak(t *testing.T) {
	for _, leak := range []bool{true, false} {
		cmd := exec.Command(os.Args[0], "-test.run", "^TestLeakChild$", "-test.count=1")
		cmd.Env = os.Environ()
		if leak {
			cmd.Env = append(cmd.Env, "DATADIRGUARD_LEAK=1")
		}
		out, err := cmd.CombinedOutput()
		switch {
		case leak && (err == nil || !strings.Contains(string(out), "canary-leak.conf")):
			t.Errorf("запись в каталог данных не поймана: %v\n%s", err, out)
		case !leak && err != nil:
			t.Errorf("прогон без записи упал: %v\n%s", err, out)
		}
	}
}

// TestGuardFailsOnUnreadableDir — QA-01 Н4: каталог не обойти (исчез во
// время прогона) — прогон падает «не обойти», а не «утечек нет».
func TestGuardFailsOnUnreadableDir(t *testing.T) {
	cmd := exec.Command(os.Args[0], "-test.run", "^TestLeakChild$", "-test.count=1")
	cmd.Env = append(os.Environ(), "DATADIRGUARD_RMDIR=1")
	out, err := cmd.CombinedOutput()
	if err == nil || !strings.Contains(string(out), "не обойти") {
		t.Errorf("каталог не обойти, а прогон не упал: %v\n%s", err, out)
	}
}

// TestFilesError — Files на несуществующем каталоге — ошибка.
func TestFilesError(t *testing.T) {
	if _, err := Files(filepath.Join(t.TempDir(), "нет")); err == nil {
		t.Errorf("обход несуществующего каталога без ошибки")
	}
}

// TestLeaksIgnoresOnlyGoTelemetry — исключение ровно одно на ОС:
// телеметрия Go там, где её кладёт os.UserConfigDir подменённого каталога.
func TestLeaksIgnoresOnlyGoTelemetry(t *testing.T) {
	files := []string{
		"go/telemetry/local/go@go1.26.3.count",
		"Library/Application Support/go/telemetry/local/go@go1.26.3.count",
		"go/env",
		"amnezia-admin/Конфигурации/canary-x.conf",
		"Library/Application Support/amnezia-admin/Конфигурации/canary-x.conf",
		"gotelemetry/x",
	}
	for _, c := range []struct {
		goos   string
		ignore string // единственный пропущенный файл ("" — никакой)
	}{
		{"linux", files[0]},
		{"darwin", files[1]},
		{"windows", ""},
	} {
		got := leaksFor(c.goos, files)
		want := len(files)
		if c.ignore != "" {
			want--
		}
		if len(got) != want {
			t.Errorf("%s: утечки %v, ждали всё, кроме %q", c.goos, got, c.ignore)
		}
		for _, g := range got {
			if g == c.ignore {
				t.Errorf("%s: %q не пропущен", c.goos, g)
			}
		}
	}
}
