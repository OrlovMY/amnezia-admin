package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"amnezia-admin/core"
)

const (
	thHost = "203.0.113.9"
	thPw   = "Canary-Pw-7f3e9a!"
)

// thRec — поддельный runner с записью команд (предпроверка — healthyProvCLI).
type thRec struct {
	mu   sync.Mutex
	f    provCLIFake
	cmds []string
}

func (r *thRec) Run(cmd string, stdin []byte) (string, error) {
	r.mu.Lock()
	r.cmds = append(r.cmds, cmd)
	r.mu.Unlock()
	return r.f.Run(cmd, stdin)
}

func thBackup() *core.Backup {
	return &core.Backup{
		IssuedAddress: core.IssuedAddress{Value: thHost, Kind: "ip"},
		Containers: []core.BackupContainer{
			{Name: "amnezia-awg2", Status: core.CtrSaved, Version: "2", VersionState: core.VersionKnown, Port: "51820", Subnet: "10.8.1.0/24"},
			{Name: "amnezia-openvpn", Status: core.CtrNotIncluded, Reason: "OpenVPN копией не поддерживается"},
		},
	}
}

func thParams() map[string]any {
	return map[string]any{"port": "51820", "transport_proto": "udp", "subnet_address": "10.8.1.0", "subnet_cidr": "24",
		"Jc": "4", "Jmin": "10", "Jmax": "50", "S1": "20", "S2": "30", "S3": "15", "S4": "25",
		"H1": "1", "H2": "2", "H3": "3", "H4": "4"}
}

// thEnv — все швы режима -to-host; по умолчанию — путь к успеху.
type thEnv struct {
	t         *testing.T
	dst       *thRec
	backup    *core.Backup
	keyAuth   bool // вход ключом ПК (пароль не спрашивался)
	connErr   error
	installed int
	migrated  int
	migCode   int
	install   core.InstallResult
	verifyErr error
	verifySeq []error // ответы проверки по очереди, затем verifyErr
	verifyN   int
	pwAsked   int
	pwAnswer  string
	keyDir    string
}

func newTHEnv(t *testing.T) *thEnv {
	e := &thEnv{t: t, dst: &thRec{f: healthyProvCLI()}, backup: thBackup(), pwAnswer: thPw, keyDir: t.TempDir()}
	// маркер незавершённой операции — свой у каждого теста: оставленный
	// одним тестом не должен останавливать следующий
	mkPath := filepath.Join(t.TempDir(), "marker.json")
	oldMk := core.OpMarkerPath
	core.OpMarkerPath = func() (string, error) { return mkPath, nil }
	t.Cleanup(func() { core.OpMarkerPath = oldMk })
	e.install = core.InstallResult{
		Containers: []core.InstallContainerResult{{Container: "amnezia-awg2", Outcome: core.InstallInstalled, Measured: core.CompatMatch, VPN: core.CompatMatch}},
		Measure:    &core.CompatReport{},
	}
	d0, d1, d2, d3, d4, d5, d6, d7, d8 := migrateDial, toHostConnectNew, toHostCollect, toHostInstall, toHostMigrate, toHostKeyContainers, toHostVerify, toHostPassword, toHostKeyDir
	d9 := toHostResolve
	t.Cleanup(func() {
		migrateDial, toHostConnectNew, toHostCollect, toHostInstall, toHostMigrate, toHostKeyContainers, toHostVerify, toHostPassword, toHostKeyDir = d0, d1, d2, d3, d4, d5, d6, d7, d8
		toHostResolve = d9
	})
	migrateDial = func(c *core.ServerCreds, _ core.HostKeyPolicy) (*core.Session, error) {
		s := core.NewSessionWithRunner(provCLIFake{}, c)
		s.HostKeyFingerprint = "SHA256:src"
		return s, nil
	}
	toHostConnectNew = func(host, port, user string, src core.AuthSource, _ core.HostKeyPolicy) (*core.Session, core.KeyAttempt, error) {
		if e.connErr != nil {
			return nil, core.KeyAttempt{Outcome: core.KeysRejected}, e.connErr
		}
		att := core.KeyAttempt{Outcome: core.KeysAccepted}
		if !e.keyAuth {
			att.Outcome = core.KeysRejected
			if src.Password == nil {
				return nil, att, &core.AuthError{Keys: att, Err: errors.New("отказ")}
			}
			b, err := src.Password(att)
			if err != nil || len(b) == 0 {
				return nil, att, &core.AuthError{Keys: att, Err: errors.New("нет пароля")}
			}
			clear(b) // как ядро: срез обнуляется после попытки
		}
		s := core.NewSessionWithRunner(e.dst, &core.ServerCreds{Host: host, Port: port, User: user})
		s.HostKeyFingerprint = "SHA256:dst"
		return s, att, nil
	}
	toHostCollect = func(context.Context, *core.Session, time.Time, core.ProgressFunc) (*core.Backup, error) {
		return e.backup, nil
	}
	toHostInstall = func(*core.Session, core.InstallPlan, core.InstallOptions) core.InstallResult {
		e.installed++
		return e.install
	}
	toHostMigrate = func(context.Context, io.Reader, io.Writer, io.Writer, bool, *core.Session, *core.Session, migrateFlags, time.Time) int {
		e.migrated++
		return e.migCode
	}
	toHostKeyContainers = func(*core.Session, []string) ([]core.AdminKeyContainer, []string, error) {
		return []core.AdminKeyContainer{{Name: "amnezia-awg2", Protocol: thParams()}}, nil, nil
	}
	toHostVerify = func(core.AdminKey, core.AdminKeyInput, string, string) error {
		e.verifyN++
		if len(e.verifySeq) > 0 {
			x := e.verifySeq[0]
			e.verifySeq = e.verifySeq[1:]
			return x
		}
		return e.verifyErr
	}
	toHostResolve = func(string) ([]net.IP, error) { return nil, errors.New("в тесте DNS нет") }
	toHostPassword = func(io.Writer, string) ([]byte, error) {
		e.pwAsked++
		return []byte(e.pwAnswer), nil
	}
	toHostKeyDir = func() (string, error) { return e.keyDir, nil }
	return e
}

func (e *thEnv) run(tty bool, stdin string, mf migrateFlags) (int, string, string) {
	var out, errOut bytes.Buffer
	o := toHostOpts{srcKey: thSrcKey(e.t), host: thHost, port: "22", user: "root", knownHostsPath: filepath.Join(e.t.TempDir(), "kh"), mf: mf, noAgent: true}
	code := runMigrateToHost(context.Background(), strings.NewReader(stdin), &out, &errOut, tty, o, time.Unix(1700000000, 0))
	return code, out.String(), errOut.String()
}

func thSrcKey(t *testing.T) string {
	k, err := core.BuildAdminKey(core.AdminKeyInput{Host: "198.51.100.7", Port: 22, User: "root", Password: core.NewSecret([]byte("Src-Canary-Pw")), PasswordConsent: true})
	if err != nil {
		t.Fatal(err)
	}
	return k.Reveal()
}

func (e *thEnv) keyFiles() []string {
	m, _ := filepath.Glob(filepath.Join(e.keyDir, "*"))
	return m
}

// leaks — сторож печати: ни пароль, ни ключ vpn:// целиком или куском.
func leaks(text, pw, key string) []string {
	var bad []string
	if pw != "" && strings.Contains(text, pw) {
		bad = append(bad, "пароль")
	}
	if key != "" {
		if strings.Contains(text, key) {
			bad = append(bad, "ключ целиком")
		}
		body := strings.TrimPrefix(key, "vpn://")
		for i := 0; i+24 <= len(body); i += 8 {
			if strings.Contains(text, body[i:i+24]) {
				bad = append(bad, "кусок ключа")
				break
			}
		}
	}
	return bad
}

// Канарейка сторожа: сам сторож обязан ловить утечку.
func TestToHostLeakGuardCanary(t *testing.T) {
	key := "vpn://" + strings.Repeat("AbCdEfGh", 10)
	if len(leaks("x "+thPw+" y", thPw, key)) == 0 || len(leaks("x "+key+" y", thPw, key)) == 0 ||
		len(leaks("ключ: "+key[10:50], thPw, key)) == 0 {
		t.Fatal("сторож печати не ловит утечку — канарейка не сработала")
	}
	if len(leaks("чисто", thPw, key)) != 0 {
		t.Fatal("сторож ложно срабатывает")
	}
}

// Полный путь: пароль вводится один раз, ключ — только в файл 0600, в
// выводе нет ни пароля, ни ключа.
func TestToHostApplyIssuesKeyFileOnly(t *testing.T) {
	e := newTHEnv(t)
	code, out, errOut := e.run(true, "y\ny\n", migrateFlags{apply: true, noPw: true})
	if code != 0 || e.installed != 1 || e.migrated != 1 {
		t.Fatalf("код %d, установка %d, перенос %d\n%s\n%s", code, e.installed, e.migrated, out, errOut)
	}
	if e.pwAsked != 1 {
		t.Fatalf("пароль спрошен %d раз, ждали 1", e.pwAsked)
	}
	files := e.keyFiles()
	if len(files) != 1 {
		t.Fatalf("файлов ключа %d\n%s", len(files), out)
	}
	data, _ := os.ReadFile(files[0])
	key := strings.TrimSpace(string(data))
	if !strings.HasPrefix(key, "vpn://") {
		t.Fatalf("в файле не ключ: %d байт", len(data))
	}
	cfg, err := core.DecodeVpnKey(key)
	if err != nil {
		t.Fatal(err)
	}
	if cr, _ := core.CredsFromConfig(cfg); cr == nil || cr.Password != thPw || cr.Host != thHost {
		t.Fatal("ключ несёт не тот вход")
	}
	if runtime.GOOS != "windows" {
		if fi, _ := os.Stat(files[0]); fi.Mode().Perm() != 0o600 {
			t.Fatalf("права %v", fi.Mode().Perm())
		}
	}
	if bad := append(leaks(out+errOut, thPw, key), leaks(out+errOut, "Src-Canary-Pw", thSrcKey(t))...); len(bad) > 0 {
		t.Fatalf("утечка в выводе: %v", bad)
	}
	if !strings.Contains(out, files[0]) || !strings.Contains(out, "Ключ проверен") {
		t.Fatalf("не напечатан путь/итог проверки:\n%s", out)
	}
}

// Согласие на пароль в ключе: без «y» ключ не пишется; -yes согласия не
// даёт; без терминала ключ не выдаётся.
func TestToHostKeyConsent(t *testing.T) {
	for _, c := range []struct {
		name  string
		tty   bool
		stdin string
		mf    migrateFlags
	}{
		{"ответ n", true, "n\ny\n", migrateFlags{apply: true, noPw: true}},
		{"пустой ответ", true, "\ny\n", migrateFlags{apply: true, noPw: true}},
		{"-yes без терминала", false, "", migrateFlags{apply: true, noPw: true, yes: true}},
		// M2: «y» в stdin без терминала согласием не считается.
		{"-yes без терминала, в stdin y", false, "y\ny\ny\n", migrateFlags{apply: true, noPw: true, yes: true}},
	} {
		e := newTHEnv(t)
		if !c.tty {
			e.keyAuth = true // без терминала пароль не спросить
		}
		code, out, _ := e.run(c.tty, c.stdin, c.mf)
		if code != 0 || e.migrated != 1 {
			t.Fatalf("%s: код %d, перенос %d\n%s", c.name, code, e.migrated, out)
		}
		if n := len(e.keyFiles()); n != 0 {
			t.Fatalf("%s: без согласия записан ключ (%d файлов)", c.name, n)
		}
		if !strings.Contains(out, "выдан не будет") {
			t.Fatalf("%s: не сказано, что ключ не выдан:\n%s", c.name, out)
		}
	}
}

// Вход ключом ПК: пароль для ключа спрашивается отдельно; пусто — честный
// отказ, а не ключ без пароля.
func TestToHostKeyAuthAsksPasswordForKey(t *testing.T) {
	e := newTHEnv(t)
	e.keyAuth, e.pwAnswer = true, ""
	code, out, _ := e.run(true, "y\ny\n", migrateFlags{apply: true, noPw: true})
	if code != 0 || e.pwAsked != 1 || len(e.keyFiles()) != 0 || !strings.Contains(out, "ароль не введён") {
		t.Fatalf("код %d, спрошен %d, файлов %d\n%s", code, e.pwAsked, len(e.keyFiles()), out)
	}
	if !strings.Contains(out, "по ключу ПК") {
		t.Fatalf("исход входа не напечатан:\n%s", out)
	}
	e2 := newTHEnv(t)
	e2.keyAuth = true
	if code, out, _ := e2.run(true, "y\ny\n", migrateFlags{apply: true, noPw: true}); code != 0 || len(e2.keyFiles()) != 1 {
		t.Fatalf("с паролем для ключа: код %d, файлов %d\n%s", code, len(e2.keyFiles()), out)
	}
}

// Сухой прогон: на новый сервер — только команды предпроверки, ни установки,
// ни переноса, ни файла ключа.
func TestToHostDryRunWritesNothing(t *testing.T) {
	e := newTHEnv(t)
	code, out, errOut := e.run(true, "", migrateFlags{})
	if code != 0 || e.installed != 0 || e.migrated != 0 || len(e.keyFiles()) != 0 || e.pwAsked != 1 {
		t.Fatalf("код %d, установка %d, перенос %d, файлов %d\n%s\n%s", code, e.installed, e.migrated, len(e.keyFiles()), out, errOut)
	}
	tags := []string{core.ProvOSTag, core.ProvKernelTag, core.DiagHostTag, core.ProvSudoTag, core.ProvDockerTag, core.ProvCtrTag, core.ProvPortsTag, core.ProvDiskTag, core.ProvDiskAtTag}
	if len(e.dst.cmds) == 0 {
		t.Fatal("предпроверка не выполнялась — тест ничего не доказывает")
	}
	for _, c := range e.dst.cmds {
		ok := false
		for _, tg := range tags {
			ok = ok || strings.Contains(c, tg)
		}
		if !ok {
			t.Fatalf("в сухом прогоне на сервер ушла не проверочная команда: %.80q", c)
		}
	}
	if !strings.Contains(out, "сухой прогон") || !strings.Contains(out, "Установка изменит") {
		t.Fatalf("нет плана/превью:\n%s", out)
	}
	if bad := leaks(out+errOut, thPw, ""); len(bad) > 0 {
		t.Fatalf("утечка: %v", bad)
	}
}

// План: Verdict()+Reason, а не String() состояния; Skipped — контейнер и
// причина целиком; оговорка NeedsMeasurement рядом с готовностью.
func TestToHostPlanPrinting(t *testing.T) {
	e := newTHEnv(t)
	_, out, _ := e.run(true, "", migrateFlags{})
	plan := core.PlanInstall(e.backup, nil)
	it := plan.Items[0]
	if !strings.Contains(out, "amnezia-awg2: "+it.Verdict()) || it.Reason == "" || !strings.Contains(out, it.Reason) {
		t.Fatalf("нет Verdict/Reason:\n%s", out)
	}
	if strings.Contains(out, "amnezia-awg2: "+it.Compat.String()) {
		t.Fatalf("напечатан String() состояния вместо Verdict():\n%s", out)
	}
	// В разделе ПЛАНА (до строки готовности), а не только в перечне
	// InstallPreview, который тоже их называет.
	planPart, _, _ := strings.Cut(out, "Готовность:")
	if !strings.Contains(planPart, "Не ставится: amnezia-openvpn — OpenVPN копией не поддерживается") {
		t.Fatalf("Skipped не назван целиком:\n%s", out)
	}
	if plan.NeedsMeasurement() && !strings.Contains(out, "подтвердится только измерением") {
		t.Fatalf("готовность без оговорки NeedsMeasurement:\n%s", out)
	}
}

// Коды выхода: 0 / 1 нельзя / 2 использование, подключение, не подтверждено
// / 4 неизвестно, остановлено проверкой.
func TestToHostExitCodes(t *testing.T) {
	ap := migrateFlags{apply: true, noPw: true}
	cases := []struct {
		name  string
		mod   func(*thEnv)
		tty   bool
		stdin string
		mf    migrateFlags
		code  int
		want  string
		inst  int
	}{
		{"сухой прогон", func(*thEnv) {}, true, "", migrateFlags{}, 0, "сухой прогон", 0},
		{"успех", func(*thEnv) {}, true, "y\ny\n", ap, 0, "записан", 1},
		{"вход не удался", func(e *thEnv) { e.connErr = errors.New("connection refused") }, true, "", ap, 2, "", 0},
		{"не чистый", func(e *thEnv) {
			e.dst.f[core.ProvDockerTag] = "DOCKER=yes\nSRVRC=0\nSRV=27.1.1\nEND\n"
			e.dst.f[core.ProvCtrTag] = "RC=0\nN=amnezia-awg2|\nEND\n"
		}, true, "", ap, 1, "не чистый", 0},
		{"порт копии занят", func(e *thEnv) {
			e.dst.f[core.ProvPortsTag] = "SSRC=0\nL=tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\nL=udp UNCONN 0 0 0.0.0.0:51820 0.0.0.0:*\nEND\n"
		}, true, "", ap, 1, "порт из копии", 0},
		{"предпроверка: неизвестно", func(e *thEnv) { delete(e.dst.f, core.ProvPortsTag) }, true, "", ap, 4, "узнать не удалось", 0},
		{"план: нельзя", func(e *thEnv) { e.backup.Containers[0].Version = "1.5" }, true, "", ap, 1, "НЕ готов", 0},
		{"план: неизвестно", func(e *thEnv) { e.backup.Containers[0].VersionState = "unknown" }, true, "", ap, 4, "НЕ готов", 0},
		{"адрес другой", func(e *thEnv) { e.backup.IssuedAddress = core.IssuedAddress{Value: "vpn.example.org", Kind: "name"} }, true, "", ap, 4, "-address-changes", 0},
		{"нет -yes без терминала", func(e *thEnv) { e.keyAuth = true }, false, "", ap, 2, "", 0},
		{"установка отклонена человеком", func(*thEnv) {}, true, "n\n", ap, 2, "Отменено", 0},
		{"установка не удалась", func(e *thEnv) { e.install.Containers[0].Measured = core.CompatMismatch }, true, "n\ny\n", ap, 1, "НЕ перенесены", 1},
		{"установка: не измерено", func(e *thEnv) { e.install.Measure = nil }, true, "n\ny\n", ap, 4, "НЕ перенесены", 1},
		{"перенос не весь", func(e *thEnv) { e.migCode = 1 }, true, "n\ny\n", ap, 1, "ПЕРЕНОС НЕ ЗАВЕРШЁН", 1},
		{"перенос остановлен", func(e *thEnv) { e.migCode = 4 }, true, "n\ny\n", ap, 4, "ПЕРЕНОС НЕ ЗАВЕРШЁН", 1},
		// L2: перенос сделан — исход ключа код не меняет.
		{"ключ не совпал", func(e *thEnv) { e.verifyErr = core.ErrAdminKeyMismatch }, true, "y\ny\n", ap, 0, "НЕ выдан", 1},
		{"ключ не проверен", func(e *thEnv) { e.verifyErr = errors.New("сеть") }, true, "y\ny\n", ap, 0, "проверить не удалось", 1},
		// H1а: без терминала и без выбора слоя автокопии — 2 ДО установки.
		{"нет -no-password без терминала", func(e *thEnv) { e.keyAuth = true }, false, "", migrateFlags{apply: true, yes: true}, 2, "Ничего не изменено", 0},
	}
	for _, c := range cases {
		e := newTHEnv(t)
		c.mod(e)
		code, out, errOut := e.run(c.tty, c.stdin, c.mf)
		if code != c.code || !strings.Contains(out+errOut, c.want) || e.installed != c.inst {
			t.Errorf("%s: код %d (ждали %d), установок %d (ждали %d)\n%s\n%s", c.name, code, c.code, e.installed, c.inst, out, errOut)
		}
	}
}

// Ошибки использования через run: -to-host с -to-key, пустой адрес, ключ
// вместо адреса, плохой порт — код 2, без подключения.
func TestToHostUsage(t *testing.T) {
	kh := filepath.Join(t.TempDir(), "kh")
	for _, args := range [][]string{
		{"migrate", "-key", "vpn://x", "-to-key", "vpn://y", "-to-host", thHost},
		{"migrate", "-key", "vpn://x", "-to-host", ""},
		{"migrate", "-key", "vpn://x", "-to-host", "vpn://AAAA"},
		{"migrate", "-key", "vpn://x", "-to-host", thHost, "-to-port", "0"},
		{"migrate", "-key", "vpn://x", "-to-host", "root@" + thHost},
	} {
		code, _, errOut := cliRun(t, kh, "", args...)
		if code != 2 {
			t.Errorf("%v: код %d\n%s", args[3:], code, errOut)
		}
		if strings.Contains(errOut, "vpn://AAAA") || strings.Contains(errOut, "vpn://y") {
			t.Errorf("%v: ключ в выводе", args[3:])
		}
	}
	if code, _, _ := cliRun(t, kh, "", "migrate", "-key", "vpn://x", "-to-key", "vpn://y", "-key-out", "f"); code != 1 {
		t.Errorf("-key-out без -to-host: код %d", code)
	}
}

// H1б: установка прошла, перенос остановлен — ключ всё равно выдан (при
// согласии), напечатаны состояние и точная команда продолжения с путём.
func TestToHostMigrateStoppedStillIssuesKey(t *testing.T) {
	e := newTHEnv(t)
	e.migCode = 4
	code, out, errOut := e.run(true, "y\ny\n", migrateFlags{apply: true, noPw: true})
	files := e.keyFiles()
	if code != 4 || len(files) != 1 {
		t.Fatalf("код %d, файлов %d\n%s\n%s", code, len(files), out, errOut)
	}
	if !strings.Contains(out, "Источник не изменён") || !strings.Contains(out, "-to-key-file "+shQuote(files[0])) ||
		!strings.Contains(out, "-to-key-file "+psQuote(files[0])) {
		t.Fatalf("нет состояния/команды продолжения:\n%s", out)
	}
	// Аудит AU-1 M1/M2: ключ — только файлом, без подстановок оболочки; все
	// флаги повтора.
	var hint []string
	for _, l := range strings.Split(out, "\n") {
		if strings.Contains(l, "amnezia-admin migrate") {
			hint = append(hint, l)
		}
	}
	if len(hint) != 2 {
		t.Fatalf("строк подсказки %d:\n%s", len(hint), out)
	}
	for _, bad := range []string{"$(cat", "Get-Content", "vpn://", "-to-key ", "-key vpn"} {
		if strings.Contains(strings.Join(hint, "\n"), bad) || strings.Contains(out, "$(cat") || strings.Contains(out, "Get-Content") {
			t.Fatalf("в подсказке %q:\n%s", bad, out)
		}
	}
	for _, need := range []string{"-replace-users", "-no-password", "-apply", "-key-file"} {
		if !strings.Contains(out, need) {
			t.Fatalf("в подсказке нет %s:\n%s", need, out)
		}
	}
	data, _ := os.ReadFile(files[0])
	if bad := leaks(out+errOut, thPw, strings.TrimSpace(string(data))); len(bad) > 0 {
		t.Fatalf("утечка: %v", bad)
	}
}

// H2: отказ входа по паролю из ключа — ключ НЕ пишется, причина названа,
// пароль спрашивается заново (до 3 попыток); сеть — ключ пишется с
// оговоркой. Различение двух исходов.
func TestToHostKeyAuthRejected(t *testing.T) {
	// отвергнут, затем принят со второго пароля
	e := newTHEnv(t)
	e.verifySeq = []error{core.ErrAdminKeyAuthRejected}
	code, out, _ := e.run(true, "y\ny\n", migrateFlags{apply: true, noPw: true})
	if code != 0 || len(e.keyFiles()) != 1 || e.pwAsked != 2 || e.verifyN != 2 || !strings.Contains(out, "PasswordAuthentication") {
		t.Fatalf("повтор: код %d, файлов %d, паролей %d, проверок %d\n%s", code, len(e.keyFiles()), e.pwAsked, e.verifyN, out)
	}
	// отвергнут всегда — 3 попытки, ключа нет
	e = newTHEnv(t)
	e.verifyErr = core.ErrAdminKeyAuthRejected
	code, out, _ = e.run(true, "y\ny\n", migrateFlags{apply: true, noPw: true})
	if code != 0 || len(e.keyFiles()) != 0 || e.verifyN != toHostKeyAttempts || strings.Contains(out, "проверить не удалось") {
		t.Fatalf("отказ: код %d, файлов %d, проверок %d\n%s", code, len(e.keyFiles()), e.verifyN, out)
	}
	// сеть — «не удалось проверить», ключ записан
	e = newTHEnv(t)
	e.verifyErr = errors.New("connection refused")
	if _, out, _ := e.run(true, "y\ny\n", migrateFlags{apply: true, noPw: true}); len(e.keyFiles()) != 1 || !strings.Contains(out, "проверить не удалось") {
		t.Fatalf("сеть: файлов %d\n%s", len(e.keyFiles()), out)
	}
}

// M1: после неудачной установки названо, что осталось на сервере, и что
// источник не тронут.
func TestToHostInstallFailedSaysWhatsLeft(t *testing.T) {
	e := newTHEnv(t)
	e.install = core.InstallResult{Containers: []core.InstallContainerResult{{Container: "amnezia-awg2", Outcome: core.InstallInstalled,
		Measured: core.CompatMismatch, Rollback: core.RollbackFailed, RollbackLeft: []string{"amnezia-awg2"}}}, Measure: &core.CompatReport{}}
	code, out, _ := e.run(true, "n\ny\n", migrateFlags{apply: true, noPw: true})
	if code != 1 || !strings.Contains(out, "осталось: amnezia-awg2") || !strings.Contains(out, "Источник не изменён") {
		t.Fatalf("код %d\n%s", code, out)
	}
}

// L2: -key-out не записался — ключ пишется в каталог по умолчанию, путь
// напечатан.
func TestToHostKeyOutFallback(t *testing.T) {
	e := newTHEnv(t)
	var outB, errB bytes.Buffer
	o := toHostOpts{srcKey: thSrcKey(t), host: thHost, port: "22", user: "root", knownHostsPath: filepath.Join(t.TempDir(), "kh"),
		mf: migrateFlags{apply: true, noPw: true}, noAgent: true, keyOut: filepath.Join(t.TempDir(), "нет-каталога", "k.txt")}
	code := runMigrateToHost(context.Background(), strings.NewReader("y\ny\n"), &outB, &errB, true, o, time.Unix(1700000000, 0))
	files := e.keyFiles()
	if code != 0 || len(files) != 1 || !strings.Contains(outB.String(), files[0]) {
		t.Fatalf("код %d, файлов %d\n%s\n%s", code, len(files), outB.String(), errB.String())
	}
}

// Ревью PR #70-2 L2: путь с апострофом экранируется для sh и PowerShell.
func TestToHostContinueHintQuoting(t *testing.T) {
	p := "/home/o'brien/k ey.txt"
	o := toHostOpts{srcKeyFile: "C:\\Users\\d'Arc\\src.txt", mf: migrateFlags{pwFile: "/x/it's.pw", skipXRay: true}}
	sh, ps := continueHint(o, p, true)
	if !strings.Contains(sh, `-to-key-file '/home/o'\''brien/k ey.txt'`) || !strings.Contains(ps, `-to-key-file '/home/o''brien/k ey.txt'`) {
		t.Fatalf("экранирование пути ключа:\nsh: %s\nps: %s", sh, ps)
	}
	if !strings.Contains(sh, `-password-file '/x/it'\''s.pw'`) || !strings.Contains(ps, `-key-file 'C:\Users\d''Arc\src.txt'`) {
		t.Fatalf("экранирование прочих путей:\nsh: %s\nps: %s", sh, ps)
	}
	for _, f := range []string{"-address-changes", "-replace-users", "-skip-xray", "-apply"} {
		if !strings.Contains(sh, f) || !strings.Contains(ps, f) {
			t.Fatalf("нет %s: %s", f, sh)
		}
	}
}

// Аудит AU-1 M1: -key-file / -to-key-file — ключ из файла, взаимоисключение
// с -key / -to-key, содержимое не в тексте ошибки.
func TestKeyFileFlags(t *testing.T) {
	dir := t.TempDir()
	kh := filepath.Join(dir, "kh")
	kf := filepath.Join(dir, "k.txt")
	if err := os.WriteFile(kf, []byte("  vpn://AAAA-not-a-key\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if k, err := readKeyFile(kf, io.Discard); err != nil || k != "vpn://AAAA-not-a-key" {
		t.Fatalf("readKeyFile: %q %v", k, err)
	}
	for _, c := range []struct {
		args []string
		code int
	}{
		{[]string{"migrate", "-key-file", kf, "-key", "vpn://x", "-to-host", thHost}, 1},
		{[]string{"migrate", "-key-file", kf, "-to-key-file", kf, "-to-key", "vpn://y"}, 1},
		{[]string{"migrate", "-key-file", kf, "-to-key-file", kf, "-to-host", thHost}, 2},
		{[]string{"migrate", "-key-file", filepath.Join(dir, "нет.txt"), "-to-host", thHost}, 1},
	} {
		code, out, errOut := cliRun(t, kh, "", c.args...)
		if code != c.code || strings.Contains(out+errOut, "AAAA-not-a-key") {
			t.Errorf("%v: код %d (ждали %d)\n%s%s", c.args, code, c.code, out, errOut)
		}
	}
}

// Аудит AU-1 M3: перенос сделан, ключа нет — совет, как управлять дальше.
func TestToHostNoKeyAdvice(t *testing.T) {
	e := newTHEnv(t)
	code, out, _ := e.run(true, "n\ny\n", migrateFlags{apply: true, noPw: true})
	if code != 0 || len(e.keyFiles()) != 0 || !strings.Contains(out, "Команды amnezia-admin работают только по ключу") {
		t.Fatalf("код %d\n%s", code, out)
	}
}

// Аудит AU-1 L1/L2/L4: на Windows не обещаем 0600; совет о файле ключа;
// vpn:// в -to-host — свой текст.
func TestToHostKeyFileTexts(t *testing.T) {
	txt := keyFilePermText(filepath.Join(t.TempDir(), "k"))
	if runtime.GOOS == "windows" {
		if strings.Contains(txt, "права 0600 —") || !strings.Contains(txt, "по правам каталога") {
			t.Fatalf("Windows: %s", txt)
		}
	} else if !strings.Contains(txt, "0600") {
		t.Fatalf("unix: %s", txt)
	}
	e := newTHEnv(t)
	_, out, _ := e.run(true, "y\ny\n", migrateFlags{apply: true, noPw: true})
	if !strings.Contains(out, "удалите файл") {
		t.Fatalf("нет совета о файле ключа:\n%s", out)
	}
	code, _, errOut := cliRun(t, filepath.Join(t.TempDir(), "kh"), "", "migrate", "-key", "vpn://x", "-to-host", "vpn://AAAA")
	if code != 2 || !strings.Contains(errOut, "-to-key-file") {
		t.Fatalf("vpn:// в -to-host: %d %s", code, errOut)
	}
}

// TestToHostOpMarker — маркер незавершённой операции (аудит AU GUI-TO-HOST
// M1): измеренный итог его снимает, неизвестный — оставляет; следующий
// migrate о нём говорит. Подмены: снимать всегда / не писать — роняют.
func TestToHostOpMarker(t *testing.T) {
	ap := migrateFlags{apply: true, noPw: true}
	for _, c := range []struct {
		name string
		set  func(*thEnv)
		keep bool
	}{
		{"перенесено", func(*thEnv) {}, false},
		{"установка не удалась (измерено)", func(e *thEnv) { e.install.Containers[0].Measured = core.CompatMismatch }, false},
		{"установка не измерена", func(e *thEnv) { e.install.Measure = nil }, true},
		{"перенос не весь (измерено)", func(e *thEnv) { e.migCode = 1 }, false},
		{"перенос: неизвестно", func(e *thEnv) { e.migCode = 4 }, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "m.json")
			old := core.OpMarkerPath
			core.OpMarkerPath = func() (string, error) { return p, nil }
			t.Cleanup(func() { core.OpMarkerPath = old })
			e := newTHEnv(t)
			c.set(e)
			e.run(true, "n\ny\n", ap)
			m, err := core.ReadOpMarker()
			if err != nil || (m != nil) != c.keep {
				t.Fatalf("маркер %v, ошибка %v (ждали оставлен=%v)", m, err, c.keep)
			}
			var buf strings.Builder
			printOpMarker(&buf)
			if c.keep != strings.Contains(buf.String(), "не завершена") {
				t.Errorf("напоминание: %q", buf.String())
			}
		})
	}
}

// TestToHostOpMarkerPending — прежний маркер молча не перезаписывается:
// есть / повреждён → отказ до установки с причиной, маркер не тронут;
// нет → установка идёт (тест доезда через run).
func TestToHostOpMarkerPending(t *testing.T) {
	for _, c := range []struct {
		name, body string
		refuse     bool
	}{
		{"нет маркера", "", false},
		{"есть маркер", `{"target":"192.0.2.77","started":"2026-11-06T10:00:00Z","step":"установка"}`, true},
		{"повреждён", "{", true},
	} {
		t.Run(c.name, func(t *testing.T) {
			e := newTHEnv(t)
			p, _ := core.OpMarkerPath()
			if c.body != "" {
				if err := os.WriteFile(p, []byte(c.body), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			code, out, errOut := e.run(true, "n\ny\n", migrateFlags{apply: true, noPw: true})
			if c.refuse {
				if code != 1 || e.installed != 0 || !strings.Contains(errOut, "сначала проверьте") || !strings.Contains(errOut, p) {
					t.Fatalf("код %d, установок %d\n%s\n%s", code, e.installed, out, errOut)
				}
				if b, _ := os.ReadFile(p); string(b) != c.body {
					t.Error("прежний маркер изменён")
				}
				return
			}
			if code != 0 || e.installed != 1 {
				t.Fatalf("без маркера: код %d, установок %d\n%s", code, e.installed, errOut)
			}
		})
	}
}

// shQuote / psQuote — для сверки вывода в тестах (сама команда — core).
func shQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }
func psQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }
