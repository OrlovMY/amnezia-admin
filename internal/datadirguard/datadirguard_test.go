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
	if os.Getenv("DATADIRGUARD_LEAK") != "1" {
		t.Skip("запускается из TestGuardCatchesLeak")
	}
	base := os.Getenv("LOCALAPPDATA")
	if runtime.GOOS != "windows" {
		base = os.Getenv("XDG_CONFIG_HOME")
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
