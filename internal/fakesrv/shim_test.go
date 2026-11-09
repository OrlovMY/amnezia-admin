package fakesrv

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestShimTakesEffect — обёртки утилит действуют в той оболочке, которую
// выбирает FindSh, при любом PATH процесса теста. Прежде на Windows без sh в
// PATH (go test из PowerShell/cmd) бралась запускалка Git\bin\sh.exe, она
// ставила /usr/bin впереди каталога обёрток, и случаи «частично (6)»,
// «нет утилиты (5)», «sha256sum упал» проходили записью — это и были
// «нестабильные» TestApplyErrorsClassified, TestPR3WgMoveReasonNamed,
// TestXRayPartialNoRestart, TestPR3CLIWriteOutcomes. Тест убирает sh из
// PATH, чтобы боевым путём пройти запасную ветку FindSh.
func TestShimTakesEffect(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Setenv("PATH", os.Getenv("SystemRoot")+`\System32`)
	}
	// Каждый случай исполняет команду с PATH=обёртки так же, как execScript,
	// и требует СБОЯ: прошедшая команда — обёртка обойдена.
	for _, c := range []struct{ name, mvTo, missing, fail, cmd string }{
		{"mv на clientsTable", "clientsTable", "", "", `: > "$1/a" && mv -f "$1/a" "$1/clientsTable"`},
		{"нет base64", "", "base64", "", `command -v base64`},
		{"sha256sum падает", "", "", "sha256sum", `echo x | sha256sum`},
	} {
		t.Run(c.name, func(t *testing.T) {
			sh, err := FindSh()
			if err != nil {
				t.Fatalf("sh не найден — проверка обёрток не выполнилась бы: %v", err)
			}
			s := &Server{FailMvTo: c.mvTo, MissingTool: c.missing, FailTool: c.fail}
			tmp := t.TempDir()
			shim, err := s.toolShim(sh, tmp)
			if err != nil {
				t.Fatalf("FindSh выбрал %s, обёртки не действуют: %v", sh, err)
			}
			cmd := exec.Command(sh, "-c", c.cmd, "probe", filepath.ToSlash(tmp))
			cmd.Env = append(os.Environ(), "PATH="+shim)
			if out, err := cmd.CombinedOutput(); err == nil {
				t.Fatalf("оболочка %s обошла обёртку: %q прошла (%s) — сбой записи не смоделирован", sh, c.cmd, out)
			}
		})
	}
}

// TestCheckShimCatchesLauncher — канарейка самой проверки: запускалка Git
// for Windows обходит обёртки, и checkShim обязан это назвать, а не
// пропустить. Без запускалки (не Windows, нет Git) проверять нечего.
func TestCheckShimCatchesLauncher(t *testing.T) {
	launcher := `C:\Program Files\Git\bin\sh.exe`
	if runtime.GOOS != "windows" {
		t.Skip("запускалка Git for Windows есть только на Windows")
	}
	if _, err := os.Stat(launcher); err != nil {
		t.Skip("нет Git for Windows")
	}
	real := realSh(launcher)
	if strings.EqualFold(real, launcher) {
		t.Fatalf("realSh не заменил запускалку %s настоящей оболочкой", launcher)
	}
	s := &Server{FailMvTo: "clientsTable"}
	if _, err := s.toolShim(real, t.TempDir()); err != nil {
		t.Fatalf("настоящая оболочка %s: %v", real, err)
	}
	_, err := s.toolShim(launcher, t.TempDir())
	if err == nil || !strings.Contains(err.Error(), "не берёт обёртки") {
		t.Fatalf("checkShim пропустил запускалку, обходящую обёртки: %v", err)
	}
}
