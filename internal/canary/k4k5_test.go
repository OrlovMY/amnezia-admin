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
func TestIsTmpCollision(t *testing.T) {
	for s, want := range map[string]bool{
		"Process exited with status 1: mv: can't rename '/opt/amnezia/awg/wg0.conf.tmp': No such file or directory":    true,
		"Process exited with status 1: mv: cannot stat '/opt/amnezia/awg/clientsTable.tmp': No such file or directory": true,
		"Process exited with status 1: sh: can't create /opt/x.tmp: Permission denied":                                 false,
		"Process exited with status 1 (вывода нет)":                                                                    false,
		"Process exited with status 1: mv: can't rename '/opt/x.tmp': Permission denied":                               false,
	} {
		if got := isTmpCollision(errors.New(s)); got != want {
			t.Errorf("%q: %v, ждали %v", s, got, want)
		}
	}
}

// TestMaskKeys — граница печати маскирует ключ и PrivateKey.
func TestMaskKeys(t *testing.T) {
	got := oneLine("ошибка vpn://AAAA-секрет и PrivateKey = BBBB=")
	if strings.Contains(got, "AAAA") || strings.Contains(got, "BBBB") || !strings.Contains(got, "vpn://***") {
		t.Errorf("не замаскировано: %q", got)
	}
}

// lslocksHook — lslocks на «хосте» fakesrv: держатель /run/lock есть, пока
// fakesrv держит запись под замком (LockHoldFor).
func lslocksHook(f *fakeServer) {
	orig := f.env.Remote
	f.env.Remote = func(cmd string) (string, error) {
		if cmd == lslocksCmd {
			out := "rc=0\nCOMMAND PID TYPE PATH\n"
			if f.exec.LockHeld() {
				out += "flock 4242 FLOCK /run/lock/\n"
			}
			return out, nil
		}
		return orig(cmd)
	}
}

// TestK5HitsWriteUnderLock — доезд: до записи под замком программа идёт
// дольше 300 мс (задержка каждой команды), запись держит замок 1,5 с.
// Обрыв по факту появления держателя попадает с первой попытки; прежний
// фиксированный обрыв через 300 мс сюда не попадал.
func TestK5HitsWriteUnderLock(t *testing.T) {
	f := emptyFake(t, false)
	f.env.NewBin = newCLI(t)
	f.exec.CommandDelay = 150 * time.Millisecond
	f.exec.LockHoldFor = 1500 * time.Millisecond
	f.exec.LockHoldAbort = true
	lslocksHook(f)
	r := f.env.breakWrite()
	if r.Status != Pass {
		t.Fatalf("К5: %s — %s", r.Status, r.Detail)
	}
	if !strings.Contains(r.Detail, "попыток 1 из 5, застали запись под замком: 1") {
		t.Errorf("число попыток не в отчёте: %s", r.Detail)
	}
}

// TestK5MissesReportAttempts — различение: записи под замком не видно ни
// разу — все k5Attempts попыток, НЕ ПРОВЕРЕНО, число попыток в отчёте.
func TestK5MissesReportAttempts(t *testing.T) {
	f := emptyFake(t, false)
	f.env.NewBin = newCLI(t)
	lslocksHook(f) // LockHoldFor = 0: держателя не бывает
	r := f.env.breakWrite()
	if r.Status != NotChecked {
		t.Fatalf("К5: %s — %s", r.Status, r.Detail)
	}
	if !strings.Contains(r.Detail, "попыток 5 из 5, застали запись под замком: 0") || !strings.Contains(r.Detail, "ни одна попытка") {
		t.Errorf("отчёт: %s", r.Detail)
	}
}
