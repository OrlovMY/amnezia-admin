package core

import (
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Аудит AU PR 5, раунд 3.

// M1: VPN поднят — три состояния; доезд — через ответы awg show / pidof+ss
// / ip_forward на поддельном сервере.
func TestInstallVPNUpStates(t *testing.T) {
	type tc struct {
		name string
		set  func(f *instFake)
		ctr  int
		want CompatState
		text string
	}
	cases := []tc{
		{"awg show отказал — интерфейса нет", func(f *instFake) { f.fail = "vpn:amnezia-awg2" }, 0, CompatMismatch, "VPN не поднялся"},
		{"awg слушает не тот порт", func(f *instFake) { f.out["vpn:amnezia-awg2"] = "51999\n" }, 0, CompatMismatch, "VPN не поднялся"},
		{"awg show без ответа", func(f *instFake) { f.drop = "vpn:amnezia-awg2" }, 0, CompatUnknown, "работа VPN не измерена"},
		{"xray не запущен", func(f *instFake) { f.out["vpn:amnezia-xray"] = "PID=no\nLISTEN=no\n" }, 1, CompatMismatch, "процесс xray не запущен"},
		{"xray порт не слушается", func(f *instFake) { f.out["vpn:amnezia-xray"] = "PID=yes\nLISTEN=no\n" }, 1, CompatMismatch, "не слушается"},
		{"нечем измерить порт", func(f *instFake) { f.out["vpn:amnezia-xray"] = "PID=yes\nLISTEN=unknown\n" }, 1, CompatUnknown, "работа VPN не измерена"},
		{"ip_forward = 0", func(f *instFake) { f.out["ipfwd"] = "0\n" }, 0, CompatMismatch, "ip_forward = 0"},
		{"ip_forward не распознан", func(f *instFake) { f.out["ipfwd"] = "\n" }, 0, CompatUnknown, "работа VPN не измерена"},
	}
	for _, c := range cases {
		f := newInstFake()
		c.set(f)
		res, _ := instRun(t, f)
		r := res.Containers[c.ctr]
		if r.VPN != c.want {
			t.Errorf("%s: VPN=%d, ждали %d (%s)", c.name, r.VPN, c.want, r.VPNWhy)
		}
		if res.ReadyForRestore() || !res.Stop || !strings.Contains(res.StopReason, c.text) {
			t.Errorf("%s: стоп %v %q", c.name, res.Stop, res.StopReason)
		}
		if strings.Contains(strings.Join(res.Lines(), "\n"), "можно переносить") {
			t.Errorf("%s: «можно переносить» без поднятого VPN", c.name)
		}
	}
	f := newInstFake()
	res, _ := instRun(t, f)
	if !res.ReadyForRestore() {
		t.Fatalf("исправный сервер: %v", res.Lines())
	}
	all := strings.Join(res.Lines(), "\n")
	for _, w := range []string{"; VPN поднят", "по семейству параметров, порту и подсети, VPN поднят — можно переносить"} {
		if !strings.Contains(all, w) {
			t.Errorf("нет %q:\n%s", w, all)
		}
	}
	// Различение в подписи: не поднят ≠ не измерен.
	down := InstallContainerResult{Outcome: InstallInstalled, Measured: CompatMatch, VPN: CompatMismatch, VPNWhy: "x"}
	unk := InstallContainerResult{Outcome: InstallInstalled, Measured: CompatMatch}
	if down.Verdict() == unk.Verdict() || !strings.Contains(unk.Verdict(), "не измерена") {
		t.Errorf("подписи: %q / %q", down.Verdict(), unk.Verdict())
	}
}

// M1: ReadyForRestore требует поднятый VPN (различение на уровне типа).
func TestInstallReadyNeedsVPN(t *testing.T) {
	ok := InstallContainerResult{Outcome: InstallInstalled, Measured: CompatMatch, VPN: CompatMatch}
	for _, v := range []CompatState{CompatUnknown, CompatMismatch} {
		bad := ok
		bad.VPN = v
		r := InstallResult{Containers: []InstallContainerResult{ok, bad}, Measure: &CompatReport{}}
		if r.ReadyForRestore() {
			t.Errorf("VPN=%d — готово к переносу", v)
		}
	}
	if !(InstallResult{Containers: []InstallContainerResult{ok}, Measure: &CompatReport{}}).ReadyForRestore() {
		t.Error("всё поднято — не готово")
	}
}

// M2: шаг без ответа дольше срока — «неизвестно» с подсказкой, установка не
// висит; дальше на сессии ничего не выполняется.
func TestInstallStepTimeout(t *testing.T) {
	old := instStepTimeout
	instStepTimeout = 50 * time.Millisecond
	defer func() { instStepTimeout = old }()
	f := newInstFake()
	f.drop = "build:amnezia-awg2"
	f.block = make(chan struct{})
	defer close(f.block)
	done := make(chan InstallResult, 1)
	go func() { r, _ := instRun(t, f); done <- r }()
	var res InstallResult
	select {
	case res = <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("установка зависла на молчащем шаге")
	}
	r := res.Containers[0]
	if r.Outcome != InstallOutcomeUnknown || !strings.Contains(r.Reason, "ответа нет за") || !strings.Contains(r.Reason, "docker ps -a") {
		t.Errorf("исход: %s — %s", r.Verdict(), r.Reason)
	}
	if res.ReadyForRestore() || !res.Stop {
		t.Error("не остановлено")
	}
	// Аудит L5: после срыва к серверу не обращаемся — молчащий шаг последний.
	f.mu.Lock()
	defer f.mu.Unlock()
	for i, c := range f.calls {
		if c.key == f.drop && i != len(f.calls)-1 {
			t.Errorf("после срыва ушло ещё %d команд(ы), первая: %s", len(f.calls)-1-i, f.calls[i+1].key)
		}
	}
}

// M2: keepalive — три пропуска подряд закрывают связь; ответы — нет.
//
// Такт и срок ответа подаёт тест (keepaliveLoop), а не настоящие часы:
// прежний вариант на 5 мс тикере под -race на медленной машине принимал
// мгновенный ответ за «ответа нет» (срок истекал раньше, чем горутина
// send успевала ответить), и «пропуски не подряд» закрывали связь.
func TestInstallKeepalive(t *testing.T) {
	const (
		ok     = "ok"
		fail   = "err"
		silent = "silent"
	)
	// run прогоняет шаги по одному такту на шаг; возвращает номер шага
	// (с 1), на котором связь закрыта, или 0.
	// kills — сколько раз вызван kill: после закрытия цикл обязан выйти
	// (аудит L1), повторный kill на боевом пути — дефект.
	run := func(steps ...string) (killedAt, kills int) {
		tick := make(chan time.Time) // без буфера: приём такта = прошлый шаг обработан
		done := make(chan struct{})
		finished := make(chan struct{})
		release := make(chan struct{})
		fired := make(chan time.Time)
		close(fired)
		// Шаг определяется порядковым номером вызова. Горутины send разных
		// тактов сами по себе могут стартовать в любом порядке, поэтому
		// следующий такт подаём только после того, как send текущего
		// взял свой номер (started).
		var sends, deadlines atomic.Int32
		started := make(chan struct{})
		step := func(n int32) string {
			if int(n) < len(steps) {
				return steps[n]
			}
			return "" // страж: не отвечает и срок не истекает
		}
		send := func() error {
			n := sends.Add(1) - 1
			started <- struct{}{}
			switch step(n) {
			case ok:
				return nil
			case fail:
				return errors.New("нет")
			}
			<-release
			return errors.New("поздно")
		}
		deadline := func() <-chan time.Time {
			if step(deadlines.Add(1)-1) == silent {
				return fired
			}
			return nil // срок не истекает: ждём настоящего ответа send
		}
		go func() {
			defer close(finished)
			keepaliveLoop(send, func() { killedAt = int(deadlines.Load()); kills++ }, 3, tick, deadline, done)
		}()
		for i := 0; i <= len(steps); i++ { // последний такт — страж
			select {
			case tick <- time.Time{}:
				<-started
			case <-finished:
				i = len(steps) + 1
			}
		}
		close(done)
		<-finished
		close(release)
		return killedAt, kills
	}
	cases := []struct {
		name  string
		steps []string
		want  int
	}{
		{"ошибки закрывают", []string{fail, fail, fail, ok}, 3},
		{"молчание закрывает", []string{silent, silent, silent, ok}, 3},
		{"живая связь", []string{ok, ok, ok, ok, ok, ok}, 0},
		{"пропуски не подряд", []string{fail, fail, ok, fail, fail, ok, silent, fail, ok}, 0},
		{"сброс счёта после ответа", []string{fail, fail, ok, fail, silent, fail}, 6},
		// После закрытия ещё два пропуска: цикл, продолживший работу после
		// kill, вызвал бы kill снова на шагах 4 и 5.
		{"после закрытия — выход", []string{fail, fail, fail, fail, fail}, 3},
	}
	for _, c := range cases {
		got, kills := run(c.steps...)
		if got != c.want {
			t.Errorf("%s: связь закрыта на шаге %d, ждали %d", c.name, got, c.want)
		}
		wantKills := 0
		if c.want > 0 {
			wantKills = 1
		}
		if kills != wantKills {
			t.Errorf("%s: kill вызван %d раз, ждали %d — после закрытия цикл обязан выйти", c.name, kills, wantKills)
		}
	}
}

// keepalive с настоящими часами: проводка тикера и срока доходит до
// keepaliveLoop. Исход не зависит от скорости: ошибки и молчание —
// пропуск при любом раскладе планировщика.
func TestInstallKeepaliveWired(t *testing.T) {
	for name, send := range map[string]func() error{
		"ошибки":   func() error { return errors.New("нет") },
		"молчание": func() error { time.Sleep(time.Second); return nil },
	} {
		killed := make(chan struct{})
		var once atomic.Bool
		stop := keepalive(send, func() {
			if once.CompareAndSwap(false, true) {
				close(killed)
			}
		}, 5*time.Millisecond, 3)
		select {
		case <-killed:
		case <-time.After(time.Minute):
			t.Errorf("%s: связь не закрыта", name)
		}
		stop()
	}
}

// L1: исход install_docker.sh — по факту, вывод — в причину, apt занят —
// подсказка.
func TestInstallDockerOutcomeByFact(t *testing.T) {
	f := newInstFake()
	f.out["install_docker"] = "E: Could not get lock /var/lib/dpkg/lock-frontend. It is held by process 1234 (unattended-upgr)\nLinux 6.8\n"
	f.dockerBroken = true
	res, _ := instRun(t, f)
	for _, w := range []string{"не установлен", "Could not get lock", "дождитесь"} {
		if !strings.Contains(res.StopReason, w) {
			t.Errorf("нет %q: %s", w, res.StopReason)
		}
	}
}

// L2: sudo с паролем — прямая причина, до записи.
func TestInstallNeedsRootOrSudo(t *testing.T) {
	f := newInstFake()
	f.fail = "sudocheck"
	res, _ := instRun(t, f)
	if !strings.Contains(res.Refused, "нужен root или sudo без пароля") {
		t.Errorf("%q", res.Refused)
	}
	if w := installWrites(f.keys()); len(w) != 0 {
		t.Errorf("запись: %v", w)
	}
}

// L3: образ после отката измеряется; остался — назван.
func TestInstallRollbackImageMeasured(t *testing.T) {
	f := newInstFake()
	f.measureConf = strings.Replace(awg2Conf, "ListenPort = 51820", "ListenPort = 51821", 1)
	f.out["remove:amnezia-awg2"] = "" // скрипт «выполнен», но ничего не удалил
	res, _ := instRun(t, f)
	r := res.Containers[0]
	if r.Rollback != RollbackFailed || !strings.Contains(strings.Join(r.RollbackLeft, ","), "образ amnezia-awg2") {
		t.Errorf("откат: %d %v", r.Rollback, r.RollbackLeft)
	}
}

// L4: метка «ключей нет» — понятная причина.
func TestInstallXRayKeysMissingReason(t *testing.T) {
	f := newInstFake()
	f.fail = "server.json:amnezia-xray"
	f.failBody = xrayKeysMissing + "\n"
	res, _ := instRun(t, f)
	if !strings.Contains(res.Containers[1].Reason, "ключи XRay не сгенерированы") {
		t.Errorf("%q", res.Containers[1].Reason)
	}
}
