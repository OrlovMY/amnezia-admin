package ciguard

// QA-01 Н2: канарейка сторожа internal/datadirguard — здесь, а не только в
// его собственном пакете. Дочерний прогон, записавший файл в
// унаследованный каталог данных, обязан упасть и назвать файл; без записи —
// пройти. Провал сообщается через fail() (метка «ПРОВАЛ:»): подмена
// Errorf→Logf в TestGuardCatchesLeak и ослабленный счёт в Run (> 1 вместо
// > 0: дочерний прогон пишет ровно один файл) отсюда видны.

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestDatadirguardCanary(t *testing.T) {
	// Подсадки в файлы CI этого сторожа не касаются — в их прогонах он
	// не нужен (и стоил бы по дочернему go test на подсадку).
	if activePlant(t) != nil {
		t.Skip("прогон с подсадкой в CI-файл")
	}
	for _, leak := range []bool{true, false} {
		cmd := exec.Command("go", "test", "-count=1", "-run", "^TestLeakChild$", "amnezia-admin/internal/datadirguard")
		cmd.Env = os.Environ()
		if leak {
			cmd.Env = append(cmd.Env, "DATADIRGUARD_LEAK=1")
		}
		out, err := cmd.CombinedOutput()
		switch {
		case leak && (err == nil || !strings.Contains(string(out), "canary-leak.conf")):
			fail(t, "datadirguard не поймал запись в каталог данных: %v\n%s", err, out)
		case !leak && err != nil:
			fail(t, "datadirguard уронил прогон без записи: %v\n%s", err, out)
		}
	}
}
