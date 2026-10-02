package canary

// PR-W1, раунд 2 (ревью SEC W-R3, W-R4).

import (
	"errors"
	"strings"
	"testing"
)

// TestOldWriterTableUnknownNotRun — SEC W-R3: «таблицы нет» — только по
// явному «no» от test -f. Таблица есть, но cat упал, или ответ test -f не
// разобран — контроль НЕ выполняется (ни одной прежней записи), таблица на
// сервере не заменяется пустой.
func TestOldWriterTableUnknownNotRun(t *testing.T) {
	for _, c := range []struct {
		name string
		hook func(cmd string) (string, error, bool)
	}{
		{"cat clientsTable упал", func(cmd string) (string, error, bool) {
			if strings.HasSuffix(cmd, " cat /opt/amnezia/awg/clientsTable") {
				return "Permission denied", errors.New("exit status 1"), true
			}
			return "", nil, false
		}},
		{"ответ test -f не разобран", func(cmd string) (string, error, bool) {
			if strings.Contains(cmd, "test -f /opt/amnezia/awg/clientsTable") {
				return "sh: test: ошибка", nil, true
			}
			return "", nil, false
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := emptyFake(t, true)
			f.env.RaceRounds = 2
			tbl, _ := f.exec.File("/opt/amnezia/awg/clientsTable")
			orig := f.env.Remote
			f.env.Remote = func(cmd string) (string, error) {
				if out, err, ok := c.hook(cmd); ok {
					return out, err
				}
				return orig(cmd)
			}
			_, _, err := f.env.oldWriterRace()
			if err == nil || !strings.Contains(err.Error(), "контроль не выполнялся") {
				t.Fatalf("ждали отказ «контроль не выполнялся», получено %v", err)
			}
			for _, cmd := range f.exec.Commands() {
				if strings.Contains(cmd, "cat > ") {
					t.Fatalf("прежняя запись выполнялась: %.100s", cmd)
				}
			}
			if now, _ := f.exec.File("/opt/amnezia/awg/clientsTable"); string(now) != string(tbl) {
				t.Errorf("clientsTable изменена")
			}
		})
	}
}

// TestOldWriterMissingTableRestoredEmpty — различение: test -f «no» —
// таблицы не было, контроль выполняется, возвращается пустая.
func TestOldWriterMissingTableRestoredEmpty(t *testing.T) {
	f := emptyFake(t, false)
	f.env.RaceRounds = 2
	if _, _, err := f.env.oldWriterRace(); err != nil {
		t.Fatalf("таблицы нет — контроль обязан выполниться: %v", err)
	}
	if now, _ := f.exec.File("/opt/amnezia/awg/clientsTable"); string(now) != "[]" {
		t.Errorf("clientsTable после контроля %q, ждали []", now)
	}
}

// TestOldWriterRestoreInCleanup — SEC W-R4: возврат К4 зарегистрирован в
// Cleanup ДО первой прежней записи (прерывание посреди контроля его
// выполнит) и выполняется один раз: RunCleanups после шага ничего не пишет.
func TestOldWriterRestoreInCleanup(t *testing.T) {
	f := emptyFake(t, false)
	f.env.RaceRounds = 2
	orig := f.env.RemoteIn
	registered := -1
	f.env.RemoteIn = func(cmd string, stdin []byte) (string, error) {
		if registered < 0 {
			f.env.cleanMu.Lock()
			registered = len(f.env.cleanups)
			f.env.cleanMu.Unlock()
		}
		return orig(cmd, stdin)
	}
	if _, _, err := f.env.oldWriterRace(); err != nil {
		t.Fatal(err)
	}
	if registered != 1 {
		t.Fatalf("уборок к первой прежней записи: %d, ждали ровно 1", registered)
	}
	n := len(f.exec.Commands())
	if errs := f.env.RunCleanups(); len(errs) != 0 {
		t.Fatal(errs)
	}
	if got := len(f.exec.Commands()); got != n {
		t.Errorf("RunCleanups после шага выполнил %d команд, ждали 0 — возврат повторился", got-n)
	}
}
