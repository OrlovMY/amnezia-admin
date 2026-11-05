package main

import (
	"bytes"
	"context"
	"errors"
	"io"
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
	pwAsked   int
	pwAnswer  string
	keyDir    string
}

func newTHEnv(t *testing.T) *thEnv {
	e := &thEnv{t: t, dst: &thRec{f: healthyProvCLI()}, backup: thBackup(), pwAnswer: thPw, keyDir: t.TempDir()}
	e.install = core.InstallResult{
		Containers: []core.InstallContainerResult{{Container: "amnezia-awg2", Outcome: core.InstallInstalled, Measured: core.CompatMatch, VPN: core.CompatMatch}},
		Measure:    &core.CompatReport{},
	}
	d0, d1, d2, d3, d4, d5, d6, d7, d8 := migrateDial, toHostConnectNew, toHostCollect, toHostInstall, toHostMigrate, toHostKeyContainers, toHostVerify, toHostPassword, toHostKeyDir
	t.Cleanup(func() {
		migrateDial, toHostConnectNew, toHostCollect, toHostInstall, toHostMigrate, toHostKeyContainers, toHostVerify, toHostPassword, toHostKeyDir = d0, d1, d2, d3, d4, d5, d6, d7, d8
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
	toHostVerify = func(core.AdminKey, core.AdminKeyInput, string, string) error { return e.verifyErr }
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
		{"ответ n", true, "y\nn\n", migrateFlags{apply: true, noPw: true}},
		{"пустой ответ", true, "y\n\n", migrateFlags{apply: true, noPw: true}},
		{"-yes без терминала", false, "", migrateFlags{apply: true, noPw: true, yes: true}},
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
		if !strings.Contains(out, "Ключ vpn:// не выдан") {
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
	if code != 0 || e.pwAsked != 1 || len(e.keyFiles()) != 0 || !strings.Contains(out, "пароль не введён") {
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
		{"установка не удалась", func(e *thEnv) { e.install.Containers[0].Measured = core.CompatMismatch }, true, "y\n", ap, 1, "НЕ перенесены", 1},
		{"установка: не измерено", func(e *thEnv) { e.install.Measure = nil }, true, "y\n", ap, 4, "НЕ перенесены", 1},
		{"перенос не весь", func(e *thEnv) { e.migCode = 1 }, true, "y\n", ap, 1, "не выдан", 1},
		{"ключ не совпал", func(e *thEnv) { e.verifyErr = core.ErrAdminKeyMismatch }, true, "y\ny\n", ap, 1, "", 1},
		{"ключ не проверен", func(e *thEnv) { e.verifyErr = errors.New("сеть") }, true, "y\ny\n", ap, 4, "проверить не удалось", 1},
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
