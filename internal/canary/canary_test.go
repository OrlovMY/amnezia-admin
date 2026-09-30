package canary

// Проверка САМОЙ канарейки (PR-4, п. 3 задания): она не имеет права молча
// пройти. Против fakesrv (эфемерный порт 127.0.0.1) шаги, которые fakesrv
// честно смоделировать не может (ls -ld /run/lock, busybox, lslocks, время
// docker exec, wg-quick в контейнере…), обязаны давать НЕ ПРОВЕРЕНО, итог —
// не ПРОЙДЕН. Разбор ответов сервера — таблицами на подставных ответах.

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

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
	if len(rs) != 1 || rs[0].ID != "П0" || rs[0].Status != Fail {
		t.Fatalf("после П0 выполнялось ещё что-то: %+v", rs)
	}
	for _, c := range f.exec.Commands() {
		if strings.Contains(c, "flock") || strings.Contains(c, "exec -i") {
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
	for _, id := range []string{"К2.1", "К2.2", "К2.3", "К2.4", "К2.9", "К3", "К4", "К5", "К6", "К7", "PR4.1", "PR4.2", "PR4.4"} {
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
		if strings.Contains(c, "flock") {
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
	f.env.NewBin = newCLI(t)
	f.env.RaceRounds = 2
	r := f.env.race()
	if r.Status != NotChecked || !strings.Contains(r.Detail, "потерь 0") {
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
		{"lslocks нет держателя", "NO-HOLDER", nil, ll, Pass},
		{"lslocks держатель", "flock 123 /run/lock", nil, ll, Fail},
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
