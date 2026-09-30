package canary

// Проверка САМОЙ канарейки (PR-4, п. 3 задания): она не имеет права молча
// пройти. Против fakesrv (эфемерный порт 127.0.0.1) шаги, которые fakesrv
// честно смоделировать не может (ls -ld /run/lock, busybox, lslocks, время
// docker exec, wg-quick в контейнере…), обязаны давать НЕ ПРОВЕРЕНО, итог —
// не ПРОЙДЕН. Разбор ответов сервера — таблицами на подставных ответах.

import (
	"crypto/sha256"
	"debug/buildinfo"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime/debug"
	"strings"
	"sync"
	"testing"
	"time"

	"amnezia-admin/core"
	"amnezia-admin/internal/fakesrv"
)

var (
	buildOnce sync.Once
	cliPath   string
	buildErr  error
)

// newCLI — собранная из этого дерева консольная версия (как у владельца «новая»).
func newCLI(t *testing.T) string {
	t.Helper()
	buildOnce.Do(func() {
		dir, err := os.MkdirTemp("", "canary-cli")
		if err != nil {
			buildErr = err
			return
		}
		cliPath = filepath.Join(dir, "amnezia-admin")
		if os.PathSeparator == '\\' {
			cliPath += ".exe"
		}
		out, err := exec.Command("go", "build", "-o", cliPath, "amnezia-admin/cmd/cli").CombinedOutput()
		if err != nil {
			buildErr = errors.New(string(out))
		}
	})
	if buildErr != nil {
		t.Fatalf("сборка cmd/cli: %v", buildErr)
	}
	return cliPath
}

type fakeServer struct {
	exec *fakesrv.Server
	env  *Env
}

// emptyFake — fakesrv по SSH на 127.0.0.1:0 без клиентов (wg0.conf только с
// [Interface], clientsTable нет), Env настроен как у владельца.
func emptyFake(t *testing.T, withClients bool) *fakeServer {
	t.Helper()
	const user, pw = "root", "canary-test-pw"
	hk, err := fakesrv.NewHostKey()
	if err != nil {
		t.Fatal(err)
	}
	fs := fakesrv.New()
	if !withClients {
		wg, _ := fs.File("/opt/amnezia/awg/wg0.conf")
		iface := string(wg)[:strings.Index(string(wg), "[Peer]")]
		fs.SetFile("/opt/amnezia/awg/wg0.conf", []byte(iface))
		fs.DeleteFile("/opt/amnezia/awg/clientsTable")
		// работающий сервер — тоже без peer'ов (П0 смотрит и его)
		if _, err := fs.Run("docker exec amnezia-awg bash -c 'wg syncconf wg0 <(wg-quick strip /opt/amnezia/awg/wg0.conf)'", nil); err != nil {
			t.Fatal(err)
		}
	}
	ln, err := fakesrv.ListenSSH("127.0.0.1:0", user, pw, hk, fs)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	host, port, _ := net.SplitHostPort(ln.Addr())
	raw, _ := json.Marshal(map[string]any{"hostName": host, "userName": user, "password": pw, "port": port})
	key := "vpn://" + base64.RawURLEncoding.EncodeToString(raw)
	cfg, err := core.DecodeVpnKey(key)
	if err != nil {
		t.Fatal(err)
	}
	creds, _ := core.CredsFromConfig(cfg)
	sess, err := core.ConnectWithHostKey(creds, core.HostKeyPolicy{
		KnownHostsPath: filepath.Join(t.TempDir(), "kh"), ExpectedFingerprint: ln.Fingerprint()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(sess.Close)
	ctr := &core.Container{Name: "amnezia-awg", Dir: "/opt/amnezia/awg", Proto: "AmneziaWG", Managed: true}
	return &fakeServer{exec: fs, env: &Env{
		Remote: func(cmd string) (string, error) {
			s, err := sess.Client.NewSession()
			if err != nil {
				return "", err
			}
			defer s.Close()
			out, err := s.CombinedOutput(cmd)
			return string(out), err
		},
		Sess: sess, Ctr: ctr,
		KeyEnv:  []string{"AMNEZIA_KEY=" + key},
		HostKey: ln.Fingerprint(),
		Ask:     func(string) Answer { return AnswerSkip },
		Out:     io.Discard,
	}}
}

// TestRefusesServerWithClients — на сервере есть клиенты → СТОП до любой
// записи: ни одной команды записи, итог НЕ ПРОЙДЕН.
func TestRefusesServerWithClients(t *testing.T) {
	f := emptyFake(t, true)
	f.env.NewBin = "не-вызывается"
	rs, err := Run(f.env)
	if !errors.Is(err, ErrStop) {
		t.Fatalf("ожидался СТОП, получено %v", err)
	}
	if len(rs) != 2 || rs[0].ID != "П2" || rs[1].ID != "П0" || rs[1].Status != Fail {
		t.Fatalf("после П0 выполнялось ещё что-то: %+v", rs)
	}
	for _, c := range f.exec.Commands() {
		if strings.Contains(c, "flock -w") || strings.Contains(c, "exec -i") {
			t.Fatalf("на сервере с клиентами была запись: %.80s", c)
		}
	}
	if st, _ := Summary(rs, err); st != Fail {
		t.Fatalf("итог при СТОП: %v", st)
	}
}

// TestFakesrvIsNeverPass — прогон ЦЕЛИКОМ против fakesrv. fakesrv не
// исполняет ls -ld, busybox, lslocks, date/docker exec — эти шаги обязаны
// быть НЕ ПРОВЕРЕНО, предусловия не подтверждены — запись не выполняется, и
// все шаги записи тоже НЕ ПРОВЕРЕНО. Итог — НЕ ПРОВЕРЕНО, не ПРОЙДЕН.
func TestFakesrvIsNeverPass(t *testing.T) {
	f := emptyFake(t, false)
	f.env.NewBin = newCLI(t)
	f.env.RaceRounds = 2
	rs, err := Run(f.env)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	passed := map[string]bool{}
	for _, r := range rs {
		if r.Status == Pass {
			passed[r.ID] = true
		}
	}
	// ПРОЙДЕН законен только для П0: сервер действительно пуст.
	for id := range passed {
		if id != "П0" {
			t.Errorf("шаг %s «пройден» на fakesrv, который его не моделирует", id)
		}
	}
	for _, id := range []string{"П2", "К2.1", "К2.2", "К2.3", "К2.4", "К2.9", "К3", "К4", "К5", "К6", "К7", "PR4.1", "PR4.2", "PR4.4"} {
		found := false
		for _, r := range rs {
			if r.ID == id {
				found = true
				if r.Status != NotChecked {
					t.Errorf("шаг %s: %s, ожидалось НЕ ПРОВЕРЕНО (%s)", id, r.Status, r.Detail)
				}
			}
		}
		if !found {
			t.Errorf("шаг %s не выполнен и не отмечен", id)
		}
	}
	if st, line := Summary(rs, nil); st != NotChecked {
		t.Fatalf("итог на fakesrv: %s", line)
	}
	// Предусловия не подтверждены — на сервер НЕ ушло ни одной записи.
	for _, c := range f.exec.Commands() {
		if strings.Contains(c, "flock -w") {
			t.Fatalf("запись выполнялась при неподтверждённых предусловиях: %.80s", c)
		}
	}
}

// TestK3OnFakesrv — шаг, который fakesrv моделирует (запись через настоящую
// собранную программу и SSH), проходит; но без ответа человека о
// приложении Amnezia и подключении — НЕ ПРОВЕРЕНО, а не ПРОЙДЕН.
func TestK3OnFakesrv(t *testing.T) {
	for _, c := range []struct {
		ans  Answer
		want Status
	}{{AnswerYes, Pass}, {AnswerSkip, NotChecked}, {AnswerNo, Fail}} {
		f := emptyFake(t, false)
		f.env.NewBin = newCLI(t)
		f.env.docker = "docker"
		f.env.Ask = func(string) Answer { return c.ans }
		if r := f.env.k3(); r.Status != c.want {
			t.Errorf("ответ %v: %s (%s), ожидалось %s", c.ans, r.Status, r.Detail, c.want)
		}
	}
}

// TestRaceNeedsControl — К4: новая версия без потерь, но контроль на
// v0.2.0 не выполнен → НЕ ПРОВЕРЕНО, а не ПРОЙДЕН.
func TestRaceNeedsControl(t *testing.T) {
	f := emptyFake(t, false)
	f.env.NewBin = serialFake(t, newCLI(t))
	f.env.RaceRounds = 2
	r := f.env.race()
	if r.Status != NotChecked || !strings.Contains(r.Detail, "(потеряно 0)") || !strings.Contains(r.Detail, "v0.2.0 не выполнен") {
		t.Fatalf("К4 без контроля: %s — %s", r.Status, r.Detail)
	}
}

// TestParseTable — разбор ответов сервера: верное — ПРОЙДЕН, неверное —
// НЕ ПРОЙДЕН, неразобранное или невыполненное — НЕ ПРОВЕРЕНО.
func TestParseTable(t *testing.T) {
	type c struct {
		name string
		out  string
		err  error
		fn   func(*Env) Result
		want Status
	}
	lock := func(e *Env) Result { return e.lockDir() }
	bb := func(e *Env) Result { return e.busybox() }
	to := func(e *Env) Result { return e.timeoutSyntax() }
	ll := func(e *Env) Result { return e.lslocks() }
	tm := func(e *Env) Result { return e.execTiming() }
	cases := []c{
		{"/run/lock верный", "drwxrwxrwt 3 root root 60 Oct 1 /run/lock", nil, lock, Pass},
		{"/run/lock без sticky", "drwxrwxrwx 3 root root 60 Oct 1 /run/lock", nil, lock, Fail},
		{"/run/lock не root", "drwxrwxrwt 3 user user 60 Oct 1 /run/lock", nil, lock, Fail},
		{"/run/lock мусор", "x", nil, lock, NotChecked},
		{"/run/lock ошибка", "", errors.New("exit 1"), lock, NotChecked},
		{"busybox 1.36", "BusyBox v1.36.1 (2023-11-07) multi-call binary.", nil, bb, Pass},
		{"busybox 1.29", "BusyBox v1.29.3 (2019) multi-call binary.", nil, bb, Fail},
		{"busybox нет", "NO-BUSYBOX\n", nil, bb, Pass},
		{"busybox мусор", "что-то", nil, bb, NotChecked},
		{"busybox ошибка", "", errors.New("нет контейнера"), bb, NotChecked},
		{"timeout rc=0", "rc=0", nil, to, Pass},
		{"timeout rc=1", "rc=1", nil, to, Fail},
		{"timeout нет rc", "что-то", nil, to, NotChecked},
		{"lslocks нет держателя", "rc=0\nCOMMAND PID TYPE PATH\n", nil, ll, Pass},
		{"lslocks держатель каталога", "rc=0\nCOMMAND PID TYPE PATH\nflock 123 FLOCK /run/lock/\n", nil, ll, Fail},
		{"lslocks держатель каталога без /", "rc=0\nCOMMAND PID TYPE PATH\nflock 123 FLOCK /run/lock\n", nil, ll, Fail},
		{"lslocks чужой файл внутри /run/lock", "rc=0\nCOMMAND PID TYPE PATH\nfoo 9 FLOCK /run/lock/foo.lock\n", nil, ll, Pass},
		{"lslocks упал (раунд 2, QA блокер 2а)", "rc=1\nlslocks: unknown column: PATH\n", nil, ll, NotChecked},
		{"lslocks без заголовка PATH", "rc=0\nCOMMAND PID\n", nil, ll, NotChecked},
		{"lslocks нет утилиты", "NO-LSLOCKS", nil, ll, NotChecked},
		{"время 0.3 с", "300000000", nil, tm, Pass},
		{"время 12 с", "12000000000", nil, tm, Fail},
		{"время мусор", "abc", nil, tm, NotChecked},
	}
	for _, x := range cases {
		e := &Env{Remote: func(string) (string, error) { return x.out, x.err }, Ctr: &core.Container{Name: "amnezia-awg", Dir: "/opt/amnezia/awg"}, docker: "docker"}
		if got := x.fn(e); got.Status != x.want {
			t.Errorf("%s: %s (%s), ожидалось %s", x.name, got.Status, got.Detail, x.want)
		}
	}
}

// TestSummary — итог ПРОЙДЕН только без НЕ ПРОЙДЕН и НЕ ПРОВЕРЕНО.
func TestSummary(t *testing.T) {
	p := Result{Status: Pass}
	cases := []struct {
		rs   []Result
		err  error
		want Status
	}{
		{[]Result{p, p}, nil, Pass},
		{[]Result{p, {Status: NotChecked}}, nil, NotChecked},
		{[]Result{p, {Status: Fail}, {Status: NotChecked}}, nil, Fail},
		{[]Result{}, nil, NotChecked},
		{[]Result{p}, ErrStop, Fail},
	}
	for i, c := range cases {
		if got, line := Summary(c.rs, c.err); got != c.want {
			t.Errorf("случай %d: %s — %s", i, got, line)
		}
	}
}

// TestMain — тестовый бинарник служит и подставной «программой» для К4:
// копия с именем fakecli-fail падает на любом вызове, fakecli-ok «успешно»
// ничего не делает.
func TestMain(m *testing.M) {
	base := filepath.Base(os.Args[0])
	switch {
	case strings.HasPrefix(base, "fakecli-fail"):
		os.Exit(1)
	case strings.HasPrefix(base, "fakecli-ok"):
		os.Exit(0)
	case strings.HasPrefix(base, "fakecli-unknown"):
		os.Stderr.WriteString("Неизвестно, записаны ли изменения\n")
		os.Exit(1)
	case strings.HasPrefix(base, "fakecli-busy-code2"):
		// заголовок «занято», но код выхода не тот — не «занято»
		os.Stderr.WriteString("Не записано: сервер занят\n")
		os.Exit(2)
	case strings.HasPrefix(base, "fakecli-changed-code2"):
		// заголовок «изменили», но код выхода не тот — не «изменили»
		os.Stderr.WriteString("Не записано: сервер изменили в другом месте\n")
		os.Exit(2)
	case strings.HasPrefix(base, "fakecli-serial"):
		os.Exit(serialCLI())
	}
	os.Exit(m.Run())
}

// serialCLI — настоящая программа, но вызовы идут по одному (замок —
// файл рядом): гонки нет, каждое добавление записывается. Нужна, чтобы
// ветви «новая версия записала всё» доезжали настоящими процессами.
func serialCLI() int {
	self, _ := os.Executable()
	real, err := os.ReadFile(self + ".real")
	if err != nil {
		return 97
	}
	// .norekey рядом — rekey «готово» без действия (TestK3RekeyMustChangeKey)
	if _, err := os.Stat(self + ".norekey"); err == nil && len(os.Args) > 1 && os.Args[1] == "rekey" {
		return 0
	}
	lock := self + ".lock"
	for {
		f, err := os.OpenFile(lock, os.O_CREATE|os.O_EXCL, 0o600)
		if err == nil {
			f.Close()
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	defer os.Remove(lock)
	cmd := exec.Command(string(real), os.Args[1:]...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return ee.ExitCode()
		}
		return 98
	}
	return 0
}

func serialFake(t *testing.T, real string) string {
	p := fakeCLI(t, "fakecli-serial")
	if err := os.WriteFile(p+".real", []byte(real), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func fakeCLI(t *testing.T, name string) string {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(self)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), name)
	if os.PathSeparator == '\\' {
		p += ".exe"
	}
	if err := os.WriteFile(p, data, 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestTableMissingPeersPresentStops — раунд 2 (SEC S1), ДОЕЗД через Run:
// clientsTable нет, а peer'ы в wg0.conf есть (или только в работающем
// сервере) — это НЕ «пустой сервер»: СТОП без единой записи.
func TestTableMissingPeersPresentStops(t *testing.T) {
	for _, c := range []struct {
		name    string
		clients bool
		prep    func(*fakesrv.Server)
	}{
		{"таблицы нет, [Peer] в wg0.conf есть", true, func(s *fakesrv.Server) { s.DeleteFile("/opt/amnezia/awg/clientsTable") }},
		{"таблицы нет, работающий сервер пуст, [Peer] только в wg0.conf", false, func(s *fakesrv.Server) {
			wg, _ := s.File("/opt/amnezia/awg/wg0.conf")
			s.SetFile("/opt/amnezia/awg/wg0.conf", append(wg, []byte("\n[Peer]\nPublicKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\nAllowedIPs = 10.8.1.9/32\n")...))
		}},
		{"файлы пусты, peer'ы в работающем сервере", true, func(s *fakesrv.Server) {
			wg, _ := s.File("/opt/amnezia/awg/wg0.conf")
			s.SetFile("/opt/amnezia/awg/wg0.conf", []byte(string(wg)[:strings.Index(string(wg), "[Peer]")]))
			s.DeleteFile("/opt/amnezia/awg/clientsTable")
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := emptyFake(t, c.clients)
			c.prep(f.exec)
			f.env.NewBin = "не-вызывается"
			rs, err := Run(f.env)
			if !errors.Is(err, ErrStop) || len(rs) != 2 || rs[1].ID != "П0" || rs[1].Status == Pass {
				t.Fatalf("ожидался СТОП на П0: err=%v, %+v", err, rs)
			}
			for _, cmd := range f.exec.Commands() {
				if strings.Contains(cmd, "flock -w") {
					t.Fatalf("запись на сервере с клиентами: %.80s", cmd)
				}
			}
		})
	}
}

// TestSudoPasswordOnlyInStdin — раунд 2 (SEC S2): пароль временного
// пользователя уходит только через stdin, в тексте ни одной команды его нет;
// пользователь «до нас» — отказ без удаления.
func TestSudoPasswordOnlyInStdin(t *testing.T) {
	const pw = "0123456789abcdef0123456789abcdef"
	var cmds []string
	var stdins []string
	remote := func(cmd string, stdin []byte) (string, error) {
		cmds = append(cmds, cmd)
		stdins = append(stdins, string(stdin))
		return "DONE", nil
	}
	env, undo, err := NewSudoKeyMaker(remote, "203.0.113.10", "22", func() (string, error) { return pw, nil })()
	if err != nil {
		t.Fatal(err)
	}
	if err := undo(); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(cmds, "\n")
	if strings.Contains(joined, pw) {
		t.Errorf("пароль в тексте команды: %s", joined)
	}
	if !strings.Contains(strings.Join(stdins, ""), TempUser+":"+pw) {
		t.Errorf("пароль не передан через stdin chpasswd")
	}
	if len(env) != 1 || strings.Contains(env[0], pw) == false && !strings.HasPrefix(env[0], "AMNEZIA_KEY=vpn://") {
		t.Errorf("окружение ключа не собрано: %v", env)
	}
	// пользователь уже есть — не наш: отказ, удаления НЕТ
	cmds = nil
	exists := func(cmd string, stdin []byte) (string, error) {
		cmds = append(cmds, cmd)
		return "EXISTS\nDONE", nil
	}
	if _, _, err := NewSudoKeyMaker(exists, "h", "22", func() (string, error) { return pw, nil })(); err == nil {
		t.Fatal("пользователь до нас — ожидался отказ")
	}
	for _, c := range cmds {
		if strings.Contains(c, "userdel") {
			t.Errorf("удалён пользователь, существовавший до нас: %s", c)
		}
	}
}

// TestRaceNewMustWriteAll — раунд 2 (QA блокер 1): новая версия не записала
// ничего (каждый add падает), v0.2.0 «говорит готово» — К4 НЕ ПРОЙДЕН, а не
// ПРОЙДЕН «без потерь».
func TestRaceNewMustWriteAll(t *testing.T) {
	f := emptyFake(t, false)
	f.env.NewBin = fakeCLI(t, "fakecli-fail")
	f.env.OldBin = fakeCLI(t, "fakecli-ok")
	f.env.RaceRounds = 2
	r := f.env.race()
	if r.Status != Fail || !strings.Contains(r.Detail, "есть исходы, кроме") || !strings.Contains(r.Detail, "код 1 «» × 4") {
		t.Fatalf("К4 при новой версии без записей: %s — %s", r.Status, r.Detail)
	}
}

// TestRaceControlWithoutLossNotChecked — QA п. 10: контроль «v0.2.0» (здесь
// та же новая версия) потери не показал — К4 НЕ ПРОВЕРЕНО.
func TestRaceControlWithoutLossNotChecked(t *testing.T) {
	f := emptyFake(t, false)
	f.env.NewBin = serialFake(t, newCLI(t))
	f.env.OldBin = f.env.NewBin
	f.env.RaceRounds = 2
	r := f.env.race()
	if r.Status != NotChecked || !strings.Contains(r.Detail, "потери НЕ показал") {
		t.Fatalf("К4 с контролем без потери: %s — %s", r.Status, r.Detail)
	}
}

// TestGateIncludesToolsAndTiming — раунд 2 (QA блокер 2б): все прочие
// предусловия ПРОЙДЕНЫ, но на хосте нет flock (К2.5) — записи не идут, К3–К7
// НЕ ПРОВЕРЕНО. Подставной сервер отвечает на каждую команду предусловий.
func TestGateIncludesToolsAndTiming(t *testing.T) {
	for _, broken := range []string{"К2.5", "К2.6", "К2.9"} {
		t.Run(broken, func(t *testing.T) {
			f := emptyFake(t, false)
			real := f.env.Remote
			f.env.Remote = scriptedPre(real, broken)
			f.env.NewBin = "не-вызывается"
			rs, err := Run(f.env)
			if err != nil {
				t.Fatal(err)
			}
			seen := map[string]Status{}
			for _, r := range rs {
				seen[r.ID] = r.Status
				if r.ID == broken && r.Status != Fail {
					t.Errorf("%s: %s, ожидалось НЕ ПРОЙДЕН (%s)", r.ID, r.Status, r.Detail)
				}
				for _, w := range []string{"К3", "К4", "К5", "К6", "К7", "PR4.1", "PR4.2", "PR4.4"} {
					if r.ID == w && (r.Status != NotChecked || !strings.Contains(r.Detail, "предусловие К2")) {
						t.Errorf("%s выполнялся при непройденном %s: %s — %s", w, broken, r.Status, r.Detail)
					}
				}
			}
			// все прочие предусловия ПРОЙДЕНЫ — шлюз закрыт именно сломанным
			for _, id := range []string{"П0", "П1", "К2.1", "К2.2", "К2.3", "К2.4", "К2.5", "К2.6", "К2.9"} {
				if id != broken && seen[id] != Pass {
					t.Errorf("предусловие %s: %s — сценарий не изолирует %s", id, seen[id], broken)
				}
			}
			if seen[broken] != Fail {
				t.Errorf("%s нет в выводе или не НЕ ПРОЙДЕН: %v", broken, seen[broken])
			}
			if _, ok := seen["К3"]; !ok {
				t.Errorf("К3 нет в выводе — шлюз не проверен")
			}
		})
	}
}

// TestRaceRealCASPass — раунд 3, ГЛАВНЫЙ ПУТЬ настоящей гонкой на fakesrv:
// настоящая новая версия, два писателя одновременно; часть «готово», часть
// «изменили в другом месте», потерь 0 → К4 ПРОЙДЕН (контроль: подставная
// «v0.2.0» говорит «готово», не записав, — потеря есть). Гонка случайна:
// до пяти прогонов, пока не случится хотя бы один отказ CAS; каждый прогон
// обязан быть ПРОЙДЕН.
func TestRaceRealCASPass(t *testing.T) {
	cli := newCLI(t)
	old := fakeCLI(t, "fakecli-ok")
	re := regexp.MustCompile(`«изменили в другом месте» (\d+)`)
	sawCAS := false
	for try := 0; try < 5 && !sawCAS; try++ {
		f := emptyFake(t, false)
		f.env.NewBin, f.env.OldBin, f.env.RaceRounds = cli, old, 3
		r := f.env.race()
		if r.Status != Pass {
			t.Fatalf("прогон %d: %s — %s", try, r.Status, r.Detail)
		}
		if m := re.FindStringSubmatch(r.Detail); m != nil && m[1] != "0" {
			sawCAS = true
			t.Logf("гонка: %s", r.Detail)
		}
	}
	if !sawCAS {
		t.Fatal("за пять прогонов ни одного отказа CAS — путь «часть CAS» не проверен")
	}
}

// TestRaceNewLostDone — «готово», а записи нет → НЕ ПРОЙДЕН (доезд: процесс
// говорит «готово», на fakesrv ничего не записано).
func TestRaceNewLostDone(t *testing.T) {
	f := emptyFake(t, false)
	f.env.NewBin, f.env.OldBin, f.env.RaceRounds = fakeCLI(t, "fakecli-ok"), fakeCLI(t, "fakecli-ok"), 2
	r := f.env.race()
	if r.Status != Fail || !strings.Contains(r.Detail, "из «готово» пропало 4") {
		t.Fatalf("К4: %s — %s", r.Status, r.Detail)
	}
}

// TestRaceNewUnknownOutcome — исход, не «изменили» и не «занято», → НЕ
// ПРОЙДЕН; заголовок «занято» с чужим кодом выхода — тоже не «занято».
func TestRaceNewUnknownOutcome(t *testing.T) {
	for _, name := range []string{"fakecli-unknown", "fakecli-busy-code2", "fakecli-changed-code2"} {
		f := emptyFake(t, false)
		f.env.NewBin, f.env.OldBin, f.env.RaceRounds = fakeCLI(t, name), fakeCLI(t, "fakecli-ok"), 2
		r := f.env.race()
		if r.Status != Fail || !strings.Contains(r.Detail, "есть исходы, кроме") {
			t.Errorf("%s: %s — %s", name, r.Status, r.Detail)
		}
	}
}

// TestJudgeNewTable — приговор по учтённым исходам, в том числе «сумма не
// сходится» (боевым путём не возникает — только таблицей).
func TestJudgeNewTable(t *testing.T) {
	d := func(n int) []string { return make([]string, n) }
	for _, c := range []struct {
		name string
		st   raceStats
		ok   bool
		why  string
	}{
		{"часть готово, часть CAS и занято", raceStats{attempts: 4, done: d(2), changed: 1, busy: 1}, true, ""},
		{"всё готово", raceStats{attempts: 4, done: d(4)}, true, ""},
		{"ни одного готово", raceStats{attempts: 4, changed: 4}, false, "ни одного «готово»"},
		{"готово пропало", raceStats{attempts: 4, done: d(4), lost: 1}, false, "пропало 1"},
		{"иной исход", raceStats{attempts: 4, done: d(3), other: map[string]int{"код 1 «Записано частично»": 1}}, false, "есть исходы, кроме"},
		{"сумма не сходится", raceStats{attempts: 4, done: d(2), changed: 1}, false, "учтены не для всех"},
		{"попыток меньше", raceStats{attempts: 3, done: d(3)}, false, "учтены не для всех"},
	} {
		r, ok := judgeNew(c.st, 4)
		if ok != c.ok || (!ok && (r.Status != Fail || !strings.Contains(r.Detail, c.why))) {
			t.Errorf("%s: ok=%v %s — %s", c.name, ok, r.Status, r.Detail)
		}
	}
}

// TestClassifyRace — вид исхода по коду выхода и заголовку дословно.
func TestClassifyRace(t *testing.T) {
	var st raceStats
	classifyRace(&st, 1, "Не записано: сервер изменили в другом месте")
	classifyRace(&st, 1, "Не записано: сервер занят")
	classifyRace(&st, 2, "Не записано: сервер занят")
	classifyRace(&st, 2, "Не записано: сервер изменили в другом месте")
	classifyRace(&st, 1, "Не записано: сервер занят, кажется")
	classifyRace(&st, 1, "")
	if st.changed != 1 || st.busy != 1 || st.otherCount() != 4 {
		t.Errorf("изменили=%d занято=%d иные=%d, ожидалось 1/1/4", st.changed, st.busy, st.otherCount())
	}
}

// TestWgWrapperRealShell — раунд 4 (M1): обёртка wg исполняется настоящим
// POSIX sh так же, как в контейнере (`sh -c '<команда>'`): syncconf → код 1
// и настоящий wg НЕ вызывается; прочие подкоманды уходят настоящему wg с
// аргументами как есть. В команде нет одинарных кавычек (она едет внутри
// '…' на хосте). Без sh (Windows без Git) — тест падает, а не пропускается:
// в CI (Linux) sh есть.
func TestWgWrapperRealShell(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Fatalf("sh не найден — обёртку проверить нечем: %v", err)
	}
	dir := t.TempDir()
	p := filepath.ToSlash(filepath.Join(dir, "wg"))
	log := filepath.ToSlash(filepath.Join(dir, "called"))
	real := "#!/bin/sh\necho \"$@\" >> " + log + "\necho real-ok\n"
	if err := os.WriteFile(p+".canary-orig", []byte(real), 0o755); err != nil {
		t.Fatal(err)
	}
	cmd := wgWrapper(p)
	if strings.Contains(cmd, "'") {
		t.Fatalf("в команде одинарная кавычка — сломает sh -c '…': %s", cmd)
	}
	if out, err := exec.Command(sh, "-c", cmd).CombinedOutput(); err != nil {
		t.Fatalf("установка обёртки: %v %s", err, out)
	}
	if out, err := exec.Command(sh, p, "syncconf", "wg0", "/dev/null").CombinedOutput(); err == nil {
		t.Errorf("syncconf прошёл через обёртку: %s", out)
	}
	if b, _ := os.ReadFile(log); len(b) != 0 {
		t.Errorf("настоящий wg вызван на syncconf: %q", b)
	}
	out, err := exec.Command(sh, p, "show", "wg0", "dump").CombinedOutput()
	if err != nil || !strings.Contains(string(out), "real-ok") {
		t.Fatalf("wg show не дошёл до настоящего wg: %v %s", err, out)
	}
	if b, _ := os.ReadFile(log); strings.TrimSpace(string(b)) != "show wg0 dump" {
		t.Errorf("аргументы переданы не как есть: %q", b)
	}
}

// scriptedPre — подставной сервер: все предусловия К2/П1 ПРОЙДЕН, кроме
// broken ("" — ничего не сломано); прочее — настоящему fakesrv.
func scriptedPre(real func(string) (string, error), broken string) func(string) (string, error) {
	return func(cmd string) (string, error) {
		switch {
		case strings.Contains(cmd, "ls -ld /run/lock"):
			return "drwxrwxrwt 3 root root 60 Oct 1 /run/lock", nil
		case strings.Contains(cmd, "busybox"):
			return "BusyBox v1.36.1 (2023) multi-call binary.", nil
		case strings.Contains(cmd, `timeout 50 sh -c true; echo "rc=$?"`):
			return "rc=0", nil
		case strings.Contains(cmd, "timeout --help"):
			return "Usage: timeout", nil
		case strings.Contains(cmd, "lslocks"):
			return "rc=0\nCOMMAND PID TYPE PATH\n", nil
		case strings.Contains(cmd, "echo DONE") && strings.Contains(cmd, "id "+TempUser):
			return "DONE", nil
		case strings.Contains(cmd, "canary-orig"):
			return "DONE", nil
		case strings.Contains(cmd, "for t in flock"):
			if broken == "К2.5" {
				return "MISSING flock\nDONE", nil
			}
			return "/usr/bin/flock\n/usr/bin/timeout\nDONE", nil
		case strings.Contains(cmd, "for t in sha256sum"):
			if broken == "К2.6" {
				return "MISSING base64\nDONE", nil
			}
			return "/bin/sha256sum\nDONE", nil
		case strings.Contains(cmd, "date +%s%N"):
			if broken == "К2.9" {
				return "12000000000", nil
			}
			return "100000000", nil
		}
		return real(cmd)
	}
}

// TestRollbackModelOnFakesrv — раунд 4 (M1): МОДЕЛЬ шага PR4.1 на fakesrv.
// Установка обёртки wg моделируется хуком FailSyncconf (syncconf падает,
// рантайм не тронут — ровно то, что делает обёртка), возврат wg — снятием
// хука. Всё остальное — настоящее: новая версия CLI по SSH, ядро,
// restore, таблица исходов. Остаток PR4.4 (canary-perm) перед шагом есть —
// шаг обязан его убрать.
func TestRollbackModelOnFakesrv(t *testing.T) {
	for _, c := range []struct {
		name    string
		install bool
		busy    bool
		want    Status
		why     string
	}{
		{"обёртка действует: откат ядра, «изменения отменены»", true, false, Pass, "изменения отменены"},
		{"обёртка не действует: запись проходит — НЕ ПРОЙДЕН", false, false, Fail, "добавление прошло"},
		{"иной исход («занято») — НЕ ПРОЙДЕН, хотя файлы и сервер прежние", true, true, Fail, "исход не"},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := emptyFake(t, false)
			f.env.NewBin = newCLI(t)
			f.env.docker = "docker"
			if r := f.env.cli(f.env.NewBin, f.env.KeyEnv, "add", "-name", "canary-perm"); r.code != 0 {
				t.Fatalf("остаток PR4.4: %d %s", r.code, r.title)
			}
			real := f.env.Remote
			restored := false
			sum := func(path string) string {
				b, _ := f.exec.File(path)
				h := sha256.Sum256(b)
				return hex.EncodeToString(h[:]) + "  " + path
			}
			f.env.Remote = func(cmd string) (string, error) {
				switch {
				case strings.HasSuffix(cmd, "sh -c 'command -v wg'"):
					return "/usr/bin/wg\n", nil
				case strings.HasSuffix(cmd, "sh -c 'mv /usr/bin/wg /usr/bin/wg.canary-orig'"):
					return "", nil
				case strings.Contains(cmd, "syncconf ] &&"):
					if c.install {
						f.exec.FailSyncconf = errors.New("exit status 1; stderr: canary: syncconf disabled")
					}
					f.exec.LockBusy = c.busy
					return "", nil
				case strings.HasSuffix(cmd, "sh -c 'mv -f /usr/bin/wg.canary-orig /usr/bin/wg'"):
					f.exec.FailSyncconf = nil
					f.exec.LockBusy = false
					restored = true
					return "", nil
				case strings.Contains(cmd, "sha256sum "):
					return sum("/opt/amnezia/awg/wg0.conf") + "\n" + sum("/opt/amnezia/awg/clientsTable") + "\n", nil
				}
				return real(cmd)
			}
			r := f.env.rollback()
			if r.Status != c.want || !strings.Contains(r.Detail, c.why) {
				t.Fatalf("PR4.1: %s — %s", r.Status, r.Detail)
			}
			if !restored {
				t.Errorf("wg не возвращён")
			}
			m, err := f.env.names()
			if err != nil {
				t.Fatal(err)
			}
			if _, ok := m["canary-perm"]; ok {
				t.Errorf("остаток PR4.4 не убран перед откатом")
			}
			if _, ok := m["canary-rb0"]; !ok {
				t.Errorf("опорного canary-rb0 нет")
			}
			if _, ok := m["canary-rb"]; ok != !c.install {
				t.Errorf("canary-rb: есть=%v при действующей обёртке=%v", ok, c.install)
			}
		})
	}
}

// TestJudgeBuildTable — П2 (раунд 4, M2): ПРОЙДЕН только при чистой сборке
// -new той же ревизии, что канарейка, и тексте команды записи в -new.
func TestJudgeBuildTable(t *testing.T) {
	bi := func(rev, mod string) *debug.BuildInfo {
		b := &debug.BuildInfo{}
		if rev != "" {
			b.Settings = append(b.Settings, debug.BuildSetting{Key: "vcs.revision", Value: rev})
		}
		if mod != "" {
			b.Settings = append(b.Settings, debug.BuildSetting{Key: "vcs.modified", Value: mod})
		}
		return b
	}
	const script = "umask 077\nСКРИПТ"
	bin := []byte("...." + script + "....")
	for _, c := range []struct {
		name string
		ni   *debug.BuildInfo
		si   *debug.BuildInfo
		sok  bool
		bin  []byte
		want Status
		why  string
	}{
		{"чисто, та же ревизия, текст есть", bi("abc", "false"), bi("abc", "false"), true, bin, Pass, "найден дословно"},
		{"-new не прочитана", nil, bi("abc", "false"), true, bin, NotChecked, "не прочитаны"},
		{"-new без ревизии", bi("", ""), bi("abc", "false"), true, bin, NotChecked, "неизвестна"},
		{"-new из изменённого дерева", bi("abc", "true"), bi("abc", "false"), true, bin, NotChecked, "ИЗМЕНЁННОГО"},
		{"канарейка без сведений", bi("abc", "false"), nil, false, bin, NotChecked, "ревизия канарейки"},
		{"канарейка из изменённого дерева", bi("abc", "false"), bi("abc", "true"), true, bin, NotChecked, "ревизия канарейки"},
		{"разные ревизии", bi("abc", "false"), bi("def", "false"), true, bin, NotChecked, "РАЗНЫХ"},
		{"текста команды в -new нет", bi("abc", "false"), bi("abc", "false"), true, []byte("umask 077"), NotChecked, "не найден"},
	} {
		r := judgeBuild(c.ni, nil, c.si, c.sok, c.bin, script)
		if r.Status != c.want || !strings.Contains(r.Detail, c.why) || !strings.Contains(r.Detail, "sha256(CASWriteScript") {
			t.Errorf("%s: %s — %s", c.name, r.Status, r.Detail)
		}
	}
}

// TestBuildCheckRealBinary — П2 доездом: сведения читаются из настоящей
// сборки cmd/cli, текст core.CASWriteScript в ней находится дословно.
// Чистое дерево — ПРОЙДЕН; изменённое — НЕ ПРОВЕРЕНО (оба исхода — по факту
// сборки, а не присваиванием).
func TestBuildCheckRealBinary(t *testing.T) {
	bin := newCLI(t)
	ni, err := buildinfo.ReadFile(bin)
	if err != nil {
		t.Fatal(err)
	}
	rev, mod := vcsOf(ni)
	if rev == "" || mod == "" {
		t.Fatalf("сборка без vcs.revision/vcs.modified: %q %q", rev, mod)
	}
	e := &Env{NewBin: bin, SelfBuild: func() (*debug.BuildInfo, bool) { return ni, true }}
	r := e.buildCheck()
	switch mod {
	case "false":
		if r.Status != Pass {
			t.Errorf("чистая сборка: %s — %s", r.Status, r.Detail)
		}
	default:
		if r.Status != NotChecked || !strings.Contains(r.Detail, "ИЗМЕНЁННОГО") {
			t.Errorf("изменённое дерево: %s — %s", r.Status, r.Detail)
		}
	}
	// чужой бинарь (тестовый) — текста команды записи в нём... есть (core
	// импортирован), поэтому различение по ревизии: канарейка «другая».
	e.SelfBuild = func() (*debug.BuildInfo, bool) {
		return &debug.BuildInfo{Settings: []debug.BuildSetting{{Key: "vcs.revision", Value: "0000"}, {Key: "vcs.modified", Value: "false"}}}, true
	}
	if r := e.buildCheck(); r.Status == Pass {
		t.Errorf("разные ревизии дали ПРОЙДЕН: %s", r.Detail)
	}
}

// TestCleanupFailureInSummary — раунд 4 (L2): неубранные canary-* — шаг «У»
// НЕ ПРОЙДЕН, а не строка в журнале. Доезд через Run: шлюз открыт
// (подставные предусловия), после П0 на сервер добавлен canary-left, затем
// замок «занят» — удалить его нельзя.
func TestCleanupFailureInSummary(t *testing.T) {
	f := emptyFake(t, false)
	cli := newCLI(t)
	real := f.env.Remote
	pre := scriptedPre(real, "")
	planted := false
	f.env.Remote = func(cmd string) (string, error) {
		if !planted && strings.Contains(cmd, "lslocks") {
			planted = true
			if r := f.env.cli(cli, f.env.KeyEnv, "add", "-name", "canary-left"); r.code != 0 {
				t.Errorf("canary-left: %d %s", r.code, r.title)
			}
			f.exec.LockBusy = true
		}
		return pre(cmd)
	}
	f.env.NewBin = fakeCLI(t, "fakecli-fail")
	f.env.RaceRounds = 1
	rs, err := Run(f.env)
	if err != nil {
		t.Fatal(err)
	}
	var u *Result
	for i := range rs {
		if rs[i].ID == "У" {
			u = &rs[i]
		}
	}
	if u == nil || u.Status != Fail || !strings.Contains(u.Detail, "canary-left") {
		t.Fatalf("уборка: %+v", u)
	}
	if st, _ := Summary(rs, nil); st != Fail {
		t.Errorf("итог при неубранных canary-*: %s", st)
	}
}

// TestK3RekeyMustChangeKey — раунд 4 (L1): «перевыпуск», не сменивший ключ,
// — НЕ ПРОЙДЕН. Новая версия подменена обёрткой, которая на rekey отвечает
// «готово», ничего не делая; прочее — настоящей программе.
func TestK3RekeyMustChangeKey(t *testing.T) {
	f := emptyFake(t, false)
	f.env.NewBin = serialFake(t, newCLI(t))
	if err := os.WriteFile(f.env.NewBin+".norekey", nil, 0o600); err != nil {
		t.Fatal(err)
	}
	f.env.docker = "docker"
	f.env.Ask = func(string) Answer { return AnswerYes }
	r := f.env.k3()
	if r.Status != Fail || !strings.Contains(r.Detail, "перевыпустить") {
		t.Fatalf("К3 при пустом перевыпуске: %s — %s", r.Status, r.Detail)
	}
}

// TestIsBusy — «занято» в К5 так же, как в К4 (раунд 4, L3): код 1 и
// заголовок дословно.
func TestIsBusy(t *testing.T) {
	const b = "Не записано: сервер занят"
	for _, c := range []struct {
		r    cliRun
		want bool
	}{
		{cliRun{code: 1, title: b, errText: b + "\n…"}, true},
		{cliRun{code: 2, title: b, errText: b}, false},
		{cliRun{code: 1, title: b + ", кажется", errText: b}, false},
		{cliRun{code: 1, title: "Неизвестно, записаны ли изменения", errText: "… сервер занят …"}, false},
	} {
		if got := isBusy(c.r); got != c.want {
			t.Errorf("%+v: %v, ожидалось %v", c.r, got, c.want)
		}
	}
}
