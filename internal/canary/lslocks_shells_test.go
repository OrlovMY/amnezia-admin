package canary

// AU-LOGIC раунд 3 Low-4: команда К5 (lslocksCmdlineCmd) — в НАСТОЯЩИХ
// оболочках (dash, bash, busybox sh), как TestCASScriptRealShells в core:
// командная строка с переводом строки склеивается, ошибка открытия /proc
// вышедшего процесса не попадает в вывод. Канарейка внутри: прежняя форма
// (`… < /proc/… 2>/dev/null`) обязана в каждой оболочке протечь — иначе
// тест не доказывает, что скобки что-то глушат.

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
)

func TestLslocksCmdlineRealShells(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skipf("ОС %s: /proc и оболочки dash/busybox — на Linux (CI, job checks linux)", runtime.GOOS)
	}
	type shell struct {
		name string
		argv []string
	}
	var shells []shell
	var missing []string
	for _, n := range []string{"dash", "bash"} {
		if p, err := exec.LookPath(n); err == nil {
			shells = append(shells, shell{n, []string{p}})
		} else {
			missing = append(missing, n)
		}
	}
	bb := os.Getenv("AMNEZIA_BUSYBOX")
	if bb == "" {
		bb, _ = exec.LookPath("busybox")
	}
	if bb != "" {
		shells = append(shells, shell{"busybox sh", []string{bb, "sh"}})
	} else {
		missing = append(missing, "busybox")
	}
	if len(missing) > 0 {
		if os.Getenv("CI") != "" {
			t.Fatalf("CI без %v — команда К5 в настоящих оболочках не проверена", missing)
		}
		t.Skipf("нет %v (не CI)", missing)
	}
	live := exec.Command("sh", "-c", "sleep 30", "x\n"+"amnezia-admin-apply")
	if err := live.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = live.Process.Kill(); _ = live.Wait() }()
	gone := exec.Command("true")
	if err := gone.Run(); err != nil {
		t.Fatal(err)
	}
	livePID, gonePID := fmt.Sprint(live.Process.Pid), fmt.Sprint(gone.Process.Pid)
	fake := fmt.Sprintf("lslocks() { printf 'COMMAND PID TYPE PATH\\nsh %s FLOCK /run/lock/\\nflock %s FLOCK /run/lock/\\n'; }; ", livePID, gonePID)
	oldForm := strings.Replace(lslocksCmdlineCmd, `{ tr '\0\n' '  ' < /proc/"$p"/cmdline; } 2>/dev/null`, `tr '\0\n' '  ' < /proc/"$p"/cmdline 2>/dev/null`, 1)
	if oldForm == lslocksCmdlineCmd {
		t.Fatal("канарейка не легла: в команде нет подавления в скобках")
	}
	run := func(sh shell, cmd string) string {
		out, err := exec.Command(sh.argv[0], append(sh.argv[1:], "-c", fake+cmd)...).CombinedOutput()
		if err != nil {
			t.Fatalf("%s: %v\n%s", sh.name, err, out)
		}
		return string(out)
	}
	for _, sh := range shells {
		out := run(sh, lslocksCmdlineCmd)
		hs, ok, why := parseHoldersCmd(out)
		if !ok || len(hs) != 2 {
			t.Errorf("%s: держатели не разобраны (%v %s):\n%s", sh.name, ok, why, out)
			continue
		}
		for _, h := range hs {
			switch h.pid {
			case livePID:
				if !strings.Contains(h.cmd, "amnezia-admin-apply") {
					t.Errorf("%s: командная строка живого процесса обрезана: %q", sh.name, h.cmd)
				}
			case gonePID:
				if h.cmd != "" {
					t.Errorf("%s: у вышедшего процесса непустая строка (ошибка /proc в выводе?): %q", sh.name, h.cmd)
				}
			}
		}
		// канарейка: прежняя форма протекает
		if hs, _, _ := parseHoldersCmd(run(sh, oldForm)); func() bool {
			for _, h := range hs {
				if h.pid == gonePID && h.cmd != "" {
					return false
				}
			}
			return true
		}() {
			t.Errorf("%s: прежняя форма не протекла — проверка подавления ничего не доказывает", sh.name)
		}
	}
}
