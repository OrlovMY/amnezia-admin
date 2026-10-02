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
	"amnezia-admin/internal/fakesrv"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
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
	f.exec.Configure(func(s *fakesrv.Server) { s.LegacyTmpSplit = true })
	f.exec.Configure(func(s *fakesrv.Server) { s.LegacyTmpGap = 80 * time.Millisecond })
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
			var n atomic.Int32 // прежние записи идут из двух горутин
			f.env.RemoteIn = func(cmd string, stdin []byte) (string, error) {
				if strings.Contains(cmd, "cat > ") {
					if int(n.Add(1)) == c.nth {
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
		})
	}
}

// TestIsTmpCollision — таблица: только «mv не нашёл P.tmp».
// TestIsTmpCollision — таблица: только сообщение mv о пропавшем P.tmp
// одного из файлов записи (с LC_ALL=C).
func TestIsTmpCollision(t *testing.T) {
	const conf, tbl = "/opt/amnezia/awg/wg0.conf", "/opt/amnezia/awg/clientsTable"
	for s, want := range map[string]bool{
		"Process exited with status 1: mv: can't rename '/opt/amnezia/awg/wg0.conf.tmp': No such file or directory":            true,
		"Process exited with status 1: mv: cannot stat '/opt/amnezia/awg/clientsTable.tmp': No such file or directory":         true,
		"Process exited with status 1: sh: can't create /opt/amnezia/awg/wg0.conf.tmp: No such file or directory":              false,
		"Process exited with status 1: cat: '/opt/amnezia/awg/wg0.conf.tmp': No such file or directory":                        false,
		"Process exited with status 1: mv: can't rename '/opt/amnezia/awg/wg0.conf.tmp': Permission denied":                    false,
		"Process exited with status 1: mv: can't rename '/opt/other/x.tmp': No such file or directory":                         false,
		"Process exited with status 1: команда x: mv: can't rename '/opt/amnezia/awg/wg0.conf.tmp': No such file or directory": false,
		"Process exited with status 1: sh: cat: /opt/amnezia/awg/wg0.conf.tmp: No such file or directory":                      false,
		"Process exited with status 1": false,
	} {
		exit, out, _ := strings.Cut(s, ": ")
		if got := isTmpCollision(&legacyErr{exit: exit, out: out}, conf, tbl); got != want {
			t.Errorf("%q: %v, ждали %v", s, got, want)
		}
	}
}

// TestMaskBoundary — QA-01 Н1: Detail, собранный боевым путём из
// err.Error() (stderr прежней записи с ключом vpn://, PEM приватного ключа
// и паролем), до вывода не доходит: граница печати — Masker.Writer, как в
// cmd/canary-a3b. В самом Detail маскировки нет (она одна, на границе).
func TestMaskBoundary(t *testing.T) {
	const pw = "s3cr3t-пароль"
	pem := "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\n-----END OPENSSH PRIVATE KEY-----"
	f := emptyFake(t, false)
	f.env.NewBin = serialFake(t, newCLI(t))
	f.env.RaceRounds = 2
	orig := f.env.RemoteIn
	f.env.RemoteIn = func(cmd string, stdin []byte) (string, error) {
		if strings.Contains(cmd, "cat > ") {
			return "sh: Permission denied vpn://AAAA-ключ " + pem + " password " + pw, errors.New("Process exited with status 1")
		}
		return orig(cmd, stdin)
	}
	r := f.env.race()
	if !strings.Contains(r.Detail, "Permission denied") {
		t.Fatalf("stderr не дошёл до Detail: %s", r.Detail)
	}
	var buf strings.Builder
	out := NewMasker(pw).Writer(&buf)
	fmt.Fprintf(out, "[%s] %s %s — %s\n", r.Status, r.ID, r.Name, r.Detail)
	got := buf.String()
	for _, s := range []string{"AAAA", "b3BlbnNzaC1rZXktdjEAAAAA", "BEGIN OPENSSH", pw} {
		if strings.Contains(got, s) {
			t.Errorf("в выводе секрет %q: %s", s, got)
		}
	}
	if !strings.Contains(got, "Permission denied") {
		t.Errorf("вывод замаскирован целиком: %s", got)
	}
}

// TestMaskerTable — шаблоны маскировщика.
func TestMaskerTable(t *testing.T) {
	m := NewMasker("пароль-1234")
	for in, bad := range map[string]string{
		"ключ vpn://QQQQ конец":                                                "QQQQ",
		"-----BEGIN RSA PRIVATE KEY-----\nZZZZ\n-----END RSA PRIVATE KEY-----": "ZZZZ",
		"оборванный -----BEGIN EC PRIVATE KEY----- YYYY":                       "YYYY",
		"PrivateKey = XXXX=": "XXXX",
		"pw пароль-1234 тут": "пароль-1234",
	} {
		if got := m.Mask(in); strings.Contains(got, bad) {
			t.Errorf("%q → %q", in, got)
		}
	}
}

// locksOut — ответ «хоста» на lslocksCmdlineCmd: держатели /run/lock
// (pid, командная строка; "" — процесс вышел до чтения /proc) одной
// командой, как у настоящего sh.
func locksOut(hs ...[2]string) string {
	out := "rc=0\nCOMMAND PID TYPE PATH\n"
	for _, h := range hs {
		out += "flock " + h[0] + " FLOCK /run/lock/\n"
	}
	out += "CMDLINES\n"
	for _, h := range hs {
		// как tr '\0\n' '  ': аргументы и переводы строк — пробелы
		out += "CMDLINE " + h[0] + " " + strings.ReplaceAll(h[1], "\n", " ") + "\n"
	}
	return out
}

// lslocksHook — lslocks на «хосте» fakesrv: держатели — записи, которые
// fakesrv держит под замком (LockHoldFor), их командные строки — в том же
// ответе; foreign — вдобавок всегда есть чужой держатель 9999 (sleep).
// Отдельное чтение /proc/PID/cmdline (второй командой) всегда неудачно:
// живой прогон 02.10 — процесс успевал выйти между двумя командами.
func lslocksHook(f *fakeServer, foreign bool) {
	orig := f.env.Remote
	f.env.Remote = func(cmd string) (string, error) {
		if cmd == lslocksCmdlineCmd {
			var hs [][2]string
			if foreign {
				hs = append(hs, [2]string{"9999", "sleep 1000"})
			}
			for pid, c := range f.exec.Held() {
				hs = append(hs, [2]string{pid, c})
			}
			return locksOut(hs...), nil
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
	f.exec.Configure(func(s *fakesrv.Server) { s.CommandDelay = 150 * time.Millisecond })
	f.exec.Configure(func(s *fakesrv.Server) { s.LockHoldFor = 1500 * time.Millisecond })
	f.exec.Configure(func(s *fakesrv.Server) { s.LockHoldAbort = true })
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
	f.exec.Configure(func(s *fakesrv.Server) { s.CommandDelay = 150 * time.Millisecond })
	f.exec.Configure(func(s *fakesrv.Server) { s.LockHoldFor = 1500 * time.Millisecond })
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
	f.exec.Configure(func(s *fakesrv.Server) { s.CommandDelay = 100 * time.Millisecond })
	calls := 0
	inner := f.env.Remote
	f.env.Remote = func(cmd string) (string, error) {
		if cmd == lslocksCmdlineCmd {
			calls++
			if calls == 1 {
				return locksOut(), nil
			}
			return locksOut([2]string{"9999", "sleep 1000"}), nil
		}
		return inner(cmd)
	}
	r := f.env.breakWrite()
	if r.Status != NotChecked || !strings.Contains(r.Detail, "замок держит чужой") {
		t.Fatalf("К5 с чужим держателем после запуска: %s — %s", r.Status, r.Detail)
	}
}

// TestK5WaitNotMeasured — доезд «код 0, ожидание не измерено» (AU-LOGIC
// Medium-2): замок стенда не взаимоисключающий, держатели перекрываются —
// вторая запись проходит, но «ждала» не утверждается.
func TestK5WaitNotMeasured(t *testing.T) {
	f := emptyFake(t, false)
	f.env.NewBin = newCLI(t)
	f.exec.Configure(func(s *fakesrv.Server) { s.CommandDelay = 150 * time.Millisecond })
	f.exec.Configure(func(s *fakesrv.Server) { s.LockHoldFor = 1500 * time.Millisecond })
	f.exec.Configure(func(s *fakesrv.Server) { s.LockHoldAbort = true })
	f.exec.Configure(func(s *fakesrv.Server) { s.LockShared = true })
	lslocksHook(f, false)
	r := f.env.breakWrite()
	if r.Status != Pass || !strings.Contains(r.Detail, "ждала ли она замка, не измерено") || strings.Contains(r.Detail, "исход: ждёт") {
		t.Fatalf("К5: %s — %s", r.Status, r.Detail)
	}
}

// TestK5LabelWrongSum — тест аудитора (Low-2): после запуска у замка
// держатель с меткой записи, но с чужой суммой — не попадание: НЕ
// ПРОВЕРЕНО «держатель замка не опознан» (Low-3), а не «чужой».
func TestK5LabelWrongSum(t *testing.T) {
	f := emptyFake(t, false)
	f.env.NewBin = newCLI(t)
	f.exec.Configure(func(s *fakesrv.Server) { s.CommandDelay = 100 * time.Millisecond })
	calls := 0
	inner := f.env.Remote
	f.env.Remote = func(cmd string) (string, error) {
		if cmd == lslocksCmdlineCmd {
			calls++
			if calls == 1 {
				return locksOut(), nil
			}
			return locksOut([2]string{"7777", "flock -w 15 -E 4 /run/lock/ docker exec -i amnezia-awg timeout 50 sh -c x amnezia-admin-apply /opt/amnezia/awg " + strings.Repeat("ab", 32) + " absent wg0.conf"}), nil
		}
		return inner(cmd)
	}
	r := f.env.breakWrite()
	if r.Status != NotChecked || !strings.Contains(r.Detail, "держатель замка не опознан") || strings.Contains(r.Detail, "чужой") {
		t.Fatalf("К5: %s — %s", r.Status, r.Detail)
	}
}

// TestK5HolderGoneRetries — держатель вышел раньше, чем прочиталась его
// командная строка (в одной команде строка CMDLINE пуста): это «не
// опознан», попытка повторяется, а не ПРОЙДЕН и не остановка К5.
func TestK5HolderGoneRetries(t *testing.T) {
	f := emptyFake(t, false)
	f.env.NewBin = newCLI(t)
	f.exec.Configure(func(s *fakesrv.Server) { s.LockHoldFor = 300 * time.Millisecond })
	inner := f.env.Remote
	f.env.Remote = func(cmd string) (string, error) {
		if cmd == lslocksCmdlineCmd {
			var hs [][2]string
			for pid := range f.exec.Held() {
				hs = append(hs, [2]string{pid, ""}) // /proc уже пуст
			}
			return locksOut(hs...), nil
		}
		return inner(cmd)
	}
	r := f.env.breakWrite()
	if r.Status != NotChecked || !strings.Contains(r.Detail, "попыток 5 из 5") || !strings.Contains(r.Detail, "не прочитана (процесс вышел или /proc скрыт)") {
		t.Fatalf("К5: %s — %s", r.Status, r.Detail)
	}
}

// TestK5BusyBeforeAttempt — QA-01 Н5, таблица предусловия: держатель есть
// до попытки — «чужой» только при прочитанной строке без метки; строка не
// прочитана или с меткой — «занят до попытки».
func TestK5BusyBeforeAttempt(t *testing.T) {
	for _, c := range []struct {
		name, cmd, want, not string
	}{
		{"строка не прочитана", "", "замок занят до попытки", "чужой"},
		{"метка записи", "flock /run/lock/ docker exec -i c sh -c x amnezia-admin-apply", "замок занят до попытки", "чужой"},
		{"чужой процесс", "sleep 1000", "замок держит чужой", "занят до попытки"},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := emptyFake(t, false)
			f.env.NewBin = "не-вызывается"
			f.env.Remote = func(cmd string) (string, error) {
				if cmd == lslocksCmdlineCmd {
					return locksOut([2]string{"321", c.cmd}), nil
				}
				return "", errors.New("не ждали: " + cmd)
			}
			a := f.env.killUnderLock("canary-k5a-1")
			if !strings.Contains(a.stop, c.want) || strings.Contains(a.stop, c.not) {
				t.Errorf("%q", a.stop)
			}
		})
	}
}

// TestJudgeK5Freed — решение ядра 02.10: застали нашу запись, после обрыва
// замок свободен. Код 0 и исход оборванной известен — ПРОЙДЕН; не известен
// — НЕ ПРОВЕРЕНО; иной код — как judgeK5Second.
func TestJudgeK5Freed(t *testing.T) {
	chg, _ := writeoutcome.TextFor(writeoutcome.Changed)
	for _, c := range []struct {
		name   string
		r      cliRun
		landed landedState
		want   Status
	}{
		{"код 0, оборванная не выполнена", cliRun{}, landedNo, Pass},
		{"код 0, оборванная завершилась", cliRun{}, landedYes, Pass},
		{"код 0, исход оборванной не узнать", cliRun{}, landedUnknown, NotChecked},
		{"изменили, оборванной нет", cliRun{code: 1, title: chg.Title}, landedNo, Fail},
		{"иной отказ", cliRun{code: 1, title: "что-то"}, landedNo, Fail},
	} {
		if got, _ := judgeK5Freed(c.r, c.landed, false); c.r.code == 0 && got == Pass {
			t.Errorf("%s: свобода замка во время второй не подтверждена, а ПРОЙДЕН", c.name)
		}
		if got, why := judgeK5Freed(c.r, c.landed, true); got != c.want {
			t.Errorf("%s: %s (%s), ждали %s", c.name, got, why, c.want)
		}
	}
}

// TestK5FreedRightAfterCut — доезд: нашу запись застали под замком, обрыв
// клиента на «хосте» прерывает её и отпускает замок (fakesrv
// LockReleaseOnDisconnect — настоящий освобождённый замок, не сокрытие в
// ответе lslocks) — ПРОЙДЕН «замок освободился сразу после обрыва;
// ожидание не потребовалось».
func TestK5FreedRightAfterCut(t *testing.T) {
	f := emptyFake(t, false)
	f.env.NewBin = newCLI(t)
	f.exec.Configure(func(s *fakesrv.Server) {
		s.CommandDelay = 100 * time.Millisecond
		s.LockHoldFor = 1500 * time.Millisecond
		s.LockReleaseOnDisconnect = true
	})
	inner := f.env.Remote
	f.env.Remote = func(cmd string) (string, error) {
		if cmd == lslocksCmdlineCmd {
			var hs [][2]string
			for pid, c := range f.exec.Held() {
				hs = append(hs, [2]string{pid, c})
			}
			return locksOut(hs...), nil
		}
		return inner(cmd)
	}
	r := f.env.breakWrite()
	if r.Status != Pass || !strings.Contains(r.Detail, "замок освободился сразу после обрыва; ожидание не потребовалось") {
		t.Fatalf("К5: %s — %s", r.Status, r.Detail)
	}
}

// TestK5ForeignAfterCut — тест аудитора (раунд 4 High-3): нашу запись
// застали, а после обрыва у замка только чужой 9999 (sleep) — не ПРОЙДЕН
// «ожидание не потребовалось».
func TestK5ForeignAfterCut(t *testing.T) {
	f := emptyFake(t, false)
	f.env.NewBin = newCLI(t)
	f.exec.Configure(func(s *fakesrv.Server) {
		s.CommandDelay = 100 * time.Millisecond
		s.LockHoldFor = 1500 * time.Millisecond
		s.LockHoldAbort = true
	})
	var mu sync.Mutex
	hit := false
	inner := f.env.Remote
	f.env.Remote = func(cmd string) (string, error) {
		if cmd == lslocksCmdlineCmd {
			mu.Lock()
			defer mu.Unlock()
			held := f.exec.Held()
			if !hit && len(held) > 0 {
				hit = true
				var hs [][2]string
				for pid, c := range held {
					hs = append(hs, [2]string{pid, c})
				}
				return locksOut(hs...), nil
			}
			if hit {
				return locksOut([2]string{"9999", "sleep 1000"}), nil
			}
			return locksOut(), nil
		}
		return inner(cmd)
	}
	r := f.env.breakWrite()
	if r.Status == Pass || strings.Contains(r.Detail, "ожидание не потребовалось") ||
		!(strings.Contains(r.Detail, "после обрыва у замка был не наш держатель") || strings.Contains(r.Detail, "замок держит чужой")) {
		// не наш держатель после обрыва — новая попытка (а её предусловие
		// видит чужого), а не путь «замок свободен»
		t.Fatalf("К5 с чужим держателем после обрыва: %s — %s", r.Status, r.Detail)
	}
}
