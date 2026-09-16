// Файл buildtargets_test.go — сторож против расхождения двух списков целей
// графического приложения: таблицы guiTargets в этом пакете и фактических
// сборок в scripts/build-release.sh.
//
// Зачем: check обещает графический интерфейс только для пары из guiTargets.
// Если в скрипт добавят цель (или уберут), а таблицу забудут — утилита
// начнёт врать молча, и ни один другой тест этого не заметит. Скрипт здесь
// только читается.
package envcheck

import (
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// guiBuildRe — строка сборки GUI: `-o dist/amnezia-admin-gui-<ос>-<арх>`
// в команде, собирающей ./cmd/gui.
var guiBuildRe = regexp.MustCompile(`-o\s+dist/amnezia-admin-gui-([a-z0-9]+)-([a-z0-9]+)(\.exe)?\b`)

func TestGUITargetsMatchBuildScript(t *testing.T) {
	const script = "../../scripts/build-release.sh"
	data, err := os.ReadFile(script)
	if err != nil {
		t.Fatalf("не прочитать %s: %v", script, err)
	}

	// Имена ОС в скрипте — человеческие (linux/windows/macos), в Go — GOOS.
	goosOf := map[string]string{"linux": "linux", "windows": "windows", "macos": "darwin"}

	var inScript []string
	for _, line := range strings.Split(string(data), "\n") {
		// Только команды сборки: в скрипте ./cmd/gui встречается ещё и в
		// `go list -deps`, где выходного файла нет.
		if !strings.Contains(line, "./cmd/gui") || !strings.Contains(line, "go build") {
			continue
		}
		m := guiBuildRe.FindStringSubmatch(line)
		if m == nil {
			t.Errorf("строка собирает ./cmd/gui, но имя выходного файла не разобрано: %s", strings.TrimSpace(line))
			continue
		}
		gooS, ok := goosOf[m[1]]
		if !ok {
			t.Errorf("неизвестная ОС %q в %s", m[1], strings.TrimSpace(line))
			continue
		}
		inScript = append(inScript, gooS+"/"+m[2])
	}
	if len(inScript) == 0 {
		t.Fatalf("в %s не найдено ни одной сборки ./cmd/gui — тест перестал что-либо проверять", script)
	}

	var inTable []string
	for pair := range guiTargets {
		inTable = append(inTable, pair)
	}
	sort.Strings(inScript)
	sort.Strings(inTable)
	if strings.Join(inScript, " ") != strings.Join(inTable, " ") {
		t.Fatalf("цели GUI разошлись:\n  scripts/build-release.sh: %v\n  таблица guiTargets:       %v", inScript, inTable)
	}
}
