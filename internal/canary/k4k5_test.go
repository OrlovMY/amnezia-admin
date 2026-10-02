package canary

// Прогоны 02.10 на тестовом сервере:
//   - К4: контроль «прежняя запись без замка» падал «Process exited with
//     status 1» на amnezia-awg2 И на amnezia-wireguard. Контроль играет
//     старую версию сам (`cat > P.tmp && mv P.tmp P` по SSH), v0.2.0 в нём
//     не участвует. Два таких писателя сталкиваются на общем P.tmp: mv
//     второго не находит файла. Это и есть гонка v0.2.0, а канарейка
//     принимала её за поломку контроля (и вывод команды выбрасывала).
//   - К5: обрыв через фиксированные 300 мс приходился на подключение, а
//     не на запись под замком.

import (
	"errors"
	"strings"
	"testing"
	"time"

	"amnezia-admin/internal/writeoutcome"
)

// TestK4TmpCollisionIsRace — доезд: fakesrv делит прежнюю запись на
// `cat > P.tmp` и `mv`, как настоящий сервер; столкновения на общем .tmp —
// воспроизведённая гонка (ПРОЙДЕН), в отчёте — число и текст mv.
func TestK4TmpCollisionIsRace(t *testing.T) {
	f := emptyFake(t, false)
	f.env.NewBin = serialFake(t, newCLI(t))
	f.env.RaceRounds = 3
	f.exec.LegacyTmpSplit = true
	f.exec.LegacyTmpGap = 80 * time.Millisecond
	r := f.env.race()
	if r.Status != Pass {
		t.Fatalf("К4 со столкновениями на .tmp: %s — %s", r.Status, r.Detail)
	}
	if !strings.Contains(r.Detail, "упало на общем .tmp") || !strings.Contains(r.Detail, "can't rename") {
		t.Errorf("в отчёте нет столкновений и текста mv: %s", r.Detail)
	}
}

// TestK4OtherFailureNotRace — различение: прежняя запись упала НЕ на .tmp
// (permission denied) — это не гонка: К4 НЕ ПРОВЕРЕНО, в тексте — вывод
// команды, ключ замаскирован.
func TestK4OtherFailureNotRace(t *testing.T) {
	for _, c := range []struct {
		name string
		nth  int // какая по счёту прежняя запись падает (1 — одиночная до гонки)
		want string
	}{
		{"одиночная до гонки", 1, "даже без гонки"},
		{"посреди гонки", 4, "прежняя запись не выполнилась"},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := emptyFake(t, false)
			f.env.NewBin = serialFake(t, newCLI(t))
			f.env.RaceRounds = 2
			orig := f.env.RemoteIn
			n := 0
			f.env.RemoteIn = func(cmd string, stdin []byte) (string, error) {
				if strings.Contains(cmd, "cat > ") {
					n++
					if n == c.nth {
						return "sh: can't create /opt/amnezia/awg/wg0.conf.tmp: Permission denied vpn://СЕКРЕТНЫЙ-КЛЮЧ", errors.New("Process exited with status 1")
					}
				}
				return orig(cmd, stdin)
			}
			r := f.env.race()
			if r.Status != NotChecked {
				t.Fatalf("К4: %s — %s", r.Status, r.Detail)
			}
			for _, w := range []string{c.want, "Permission denied", "status 1"} {
				if !strings.Contains(r.Detail, w) {
					t.Errorf("нет %q: %s", w, r.Detail)
				}
			}
			if strings.Contains(r.Detail, "СЕКРЕТНЫЙ") {
				t.Errorf("ключ в тексте: %s", r.Detail)
			}
		})
	}
}

// TestIsTmpCollision — таблица: только «mv не нашёл P.tmp».
// TestIsTmpCollision — таблица: только сообщение mv о пропавшем P.tmp
// одного из файлов записи (с LC_ALL=C).
func TestIsTmpCollision(t *testing.T) {
	const conf, tbl = "/opt/amnezia/awg/wg0.conf", "/opt/amnezia/awg/clientsTable"
	for s, want := range map[string]bool{
		"Process exited with status 1: mv: can't rename '/opt/amnezia/awg/wg0.conf.tmp': No such file or directory":    true,
		"Process exited with status 1: mv: cannot stat '/opt/amnezia/awg/clientsTable.tmp': No such file or directory": true,
		"Process exited with status 1: sh: can't create /opt/amnezia/awg/wg0.conf.tmp: No such file or directory":      false,
		"Process exited with status 1: cat: '/opt/amnezia/awg/wg0.conf.tmp': No such file or directory":                false,
		"Process exited with status 1: mv: can't rename '/opt/amnezia/awg/wg0.conf.tmp': Permission denied":            false,
		"Process exited with status 1: mv: can't rename '/opt/other/x.tmp': No such file or directory":                 false,
		"Process exited with status 1 (вывода нет)":                                                                    false,
	} {
		if got := isTmpCollision(errors.New(s), conf, tbl); got != want {
			t.Errorf("%q: %v, ждали %v", s, got, want)
		}
	}
}

// lslocksHook — lslocks и /proc/PID/cmdline на «хосте» fakesrv: держатели —
// записи, которые fakesrv держит под замком (LockHoldFor); foreign —
// вдобавок всегда есть чужой держатель 9999 (sleep).
func lslocksHook(f *fakeServer, foreign bool) {
	orig := f.env.Remote
	f.env.Remote = func(cmd string) (string, error) {
		held := f.exec.Held()
		if cmd == lslocksCmd {
			out := "rc=0\nCOMMAND PID TYPE PATH\n"
			if foreign {
				out += "sleep 9999 FLOCK /run/lock/\n"
			}
			for pid := range held {
				out += "flock " + pid + " FLOCK /run/lock/\n"
			}
			return out, nil
		}
		for pid, c := range held {
			if cmd == procCmdlineCmd(pid) {
				return c, nil
			}
		}
		if foreign && cmd == procCmdlineCmd("9999") {
			return "sleep 1000 ", nil
		}
		if strings.Contains(cmd, "/proc/") {
			return "", errors.New("Process exited with status 1")
		}
		return orig(cmd)
	}
}

// TestK5HitsWriteUnderLock — доезд: до записи под замком программа идёт
// дольше 300 мс, запись держит замок 1,5 с, замок взаимоисключающий.
// Обрыв по нашему держателю попадает с первой попытки; вторая запись
// ЖДЁТ (измерено) и проходит.
func TestK5HitsWriteUnderLock(t *testing.T) {
	f := emptyFake(t, false)
	f.env.NewBin = newCLI(t)
	f.exec.CommandDelay = 150 * time.Millisecond
	f.exec.LockHoldFor = 1500 * time.Millisecond
	f.exec.LockHoldAbort = true
	lslocksHook(f, false)
	r := f.env.breakWrite()
	if r.Status != Pass {
		t.Fatalf("К5: %s — %s", r.Status, r.Detail)
	}
	for _, w := range []string{"попыток 1 из 5, застали нашу запись под замком: 1", "ждала:", "исход: ждёт"} {
		if !strings.Contains(r.Detail, w) {
			t.Errorf("нет %q: %s", w, r.Detail)
		}
	}
}

// TestK5ForeignHolder — различение (тест AU-LOGIC High-1): чужой держатель
// есть всегда, наша запись замок не держит — НЕ ПРОВЕРЕНО «замок держит
// чужой», а не ПРОЙДЕН.
func TestK5ForeignHolder(t *testing.T) {
	f := emptyFake(t, false)
	f.env.NewBin = newCLI(t)
	lslocksHook(f, true) // LockHoldFor = 0
	r := f.env.breakWrite()
	if r.Status != NotChecked || !strings.Contains(r.Detail, "замок держит чужой") {
		t.Fatalf("К5 с чужим держателем: %s — %s", r.Status, r.Detail)
	}
}

// TestK5MissesReportAttempts — записи под замком не видно ни разу — все
// k5Attempts попыток, НЕ ПРОВЕРЕНО, число попыток в отчёте.
func TestK5MissesReportAttempts(t *testing.T) {
	f := emptyFake(t, false)
	f.env.NewBin = newCLI(t)
	lslocksHook(f, false) // LockHoldFor = 0: держателя не бывает
	r := f.env.breakWrite()
	if r.Status != NotChecked {
		t.Fatalf("К5: %s — %s", r.Status, r.Detail)
	}
	if !strings.Contains(r.Detail, "попыток 5 из 5, застали нашу запись под замком: 0") || !strings.Contains(r.Detail, "ни одна попытка") {
		t.Errorf("отчёт: %s", r.Detail)
	}
}

// TestJudgeK5Second — решение ядра 02.10: исходы второй записи и
// «изменили» без изменения оборванной записи (и без сведений о нём);
// «ждёт» — только при измеренном ожидании.
func TestJudgeK5Second(t *testing.T) {
	chg, _ := writeoutcome.TextFor(writeoutcome.Changed)
	bsy, _ := writeoutcome.TextFor(writeoutcome.Busy)
	changed := cliRun{code: 1, title: chg.Title}
	for _, c := range []struct {
		name   string
		r      cliRun
		landed landedState
		waited bool
		want   Status
		text   string
	}{
		{"ждёт, измерено", cliRun{}, landedNo, true, Pass, "исход: ждёт"},
		{"код 0, не измерено", cliRun{}, landedNo, false, Pass, "не измерено"},
		{"занято", cliRun{code: 1, title: bsy.Title}, landedNo, false, Pass, "занято"},
		{"оборванная завершилась → CAS", changed, landedYes, false, Pass, "сверено по содержимому"},
		{"CAS без изменения оборванной", changed, landedNo, false, Fail, "необъясним"},
		{"CAS, завершение не узнать", changed, landedUnknown, false, NotChecked, "узнать не удалось"},
		{"иной отказ", cliRun{code: 1, title: "что-то ещё"}, landedYes, true, Fail, "не прошла"},
	} {
		got, why := judgeK5Second(c.r, c.landed, c.waited)
		if got != c.want || !strings.Contains(why, c.text) {
			t.Errorf("%s: %s (%s), ждали %s с %q", c.name, got, why, c.want, c.text)
		}
	}
}

// TestK5CutWriteLanded — доезд исхода «оборванная завершилась → CAS»:
// fakesrv доводит удержанную запись до конца (без LockHoldAbort).
func TestK5CutWriteLanded(t *testing.T) {
	f := emptyFake(t, false)
	f.env.NewBin = newCLI(t)
	f.exec.CommandDelay = 150 * time.Millisecond
	f.exec.LockHoldFor = 1500 * time.Millisecond
	lslocksHook(f, false)
	r := f.env.breakWrite()
	if r.Status != Pass || !strings.Contains(r.Detail, "оборванная запись завершилась") {
		t.Fatalf("К5: %s — %s", r.Status, r.Detail)
	}
}

// TestK5ForeignAppearsLater — различение по принадлежности: до запуска
// замок свободен, чужой держатель появляется ПОСЛЕ запуска первой записи,
// наша запись замок не держит — НЕ ПРОВЕРЕНО «замок держит чужой», а не
// попадание.
func TestK5ForeignAppearsLater(t *testing.T) {
	f := emptyFake(t, false)
	f.env.NewBin = newCLI(t)
	f.exec.CommandDelay = 100 * time.Millisecond
	calls := 0
	inner := f.env.Remote
	f.env.Remote = func(cmd string) (string, error) {
		if cmd == lslocksCmd {
			calls++
			if calls == 1 {
				return "rc=0\nCOMMAND PID TYPE PATH\n", nil
			}
			return "rc=0\nCOMMAND PID TYPE PATH\nsleep 9999 FLOCK /run/lock/\n", nil
		}
		if cmd == procCmdlineCmd("9999") {
			return "sleep 1000 ", nil
		}
		return inner(cmd)
	}
	r := f.env.breakWrite()
	if r.Status != NotChecked || !strings.Contains(r.Detail, "замок держит чужой") {
		t.Fatalf("К5 с чужим держателем после запуска: %s — %s", r.Status, r.Detail)
	}
}
