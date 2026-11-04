package main

import (
	"bytes"
	"errors"
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"amnezia-admin/core"
	"amnezia-admin/internal/fakesrv"
)

const migAwg = "/opt/amnezia/awg/"

// migPair — два настоящих SSH-фейка: источник и цель. known_hosts общий
// (оба отпечатка известны), withTarget=false — отпечаток цели НЕ известен.
type migEnv struct {
	keySrc, keyDst string
	kh             string
	src, dst       *fakesrv.Server
}

func newMigEnv(t *testing.T, withTarget bool) *migEnv {
	t.Helper()
	keyA, khA, srcExec := setupFakeSSHForRunWithExec(t)
	keyB, khB, tgtExec := setupFakeSSHForRunWithExec(t)
	srcExec.SetFile(migAwg+"wireguard_psk.key", []byte("OLD-PSK\n"))
	tgtExec.SetFile(migAwg+"wireguard_psk.key", []byte("NEW-PSK\n"))
	if withTarget {
		a, _ := os.ReadFile(khA)
		b, _ := os.ReadFile(khB)
		if err := os.WriteFile(khA, append(append(a, '\n'), b...), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return &migEnv{keySrc: keyA, keyDst: keyB, kh: khA, src: srcExec, dst: tgtExec}
}

func (e *migEnv) run(t *testing.T, stdin string, extra ...string) (int, string, string) {
	t.Helper()
	args := append([]string{"migrate", "-key", e.keySrc, "-to-key", e.keyDst}, extra...)
	return cliRun(t, e.kh, stdin, args...)
}

func backupsListing(t *testing.T) map[string]bool {
	t.Helper()
	dir, err := userBackupsDir()
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]bool{}
	_ = filepath.Walk(dir, func(p string, fi os.FileInfo, err error) error {
		if err == nil && !fi.IsDir() {
			out[p] = true
		}
		return nil
	})
	return out
}

func newFiles(before, after map[string]bool) []string {
	var out []string
	for p := range after {
		if !before[p] {
			out = append(out, p)
		}
	}
	return out
}

func noSecrets(t *testing.T, what string, e *migEnv, texts ...string) {
	t.Helper()
	priv := serverPriv(t, e.src)
	all := strings.Join(texts, "\n")
	for _, s := range []string{priv, serverPriv(t, e.dst), "OLD-PSK", "NEW-PSK", "[Interface]", "fakepw-run-e2e-test", e.keySrc, e.keyDst} {
		if strings.Contains(all, s) {
			t.Errorf("%s: секрет %.12q… в выводе", what, s)
		}
	}
}

// TestCLIMigrateEndToEnd — полный переезд через run(): цель стала как
// источник; отпечаток цели напечатан ДО записи; сказано, что на диск записана
// автокопия ЦЕЛИ и где; на диске появился ровно один новый файл — автокопия
// цели (не источника), во временном каталоге процесса ничего нет; источник
// не менялся и не писался; секретов в выводе нет. Подмена — запись копии
// источника на диск в runMigrate/ядре — роняет тест.
func TestCLIMigrateEndToEnd(t *testing.T) {
	e := newMigEnv(t, true)
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)
	t.Setenv("TEMP", tmp)
	t.Setenv("TMP", tmp)
	srcPriv := serverPriv(t, e.src)
	dstConfBefore, _ := e.dst.File(migAwg + "wg0.conf")
	before := backupsListing(t)
	code, out, errOut := e.run(t, "", "-client-host", "keep-ip", "-no-password", "-apply", "-yes", "-replace-users", "-address-changes")
	if code != 0 {
		t.Fatalf("код %d\n%s\n%s", code, out, errOut)
	}
	for _, n := range []string{"wg0.conf", "clientsTable", "wireguard_psk.key"} {
		a, _ := e.src.File(migAwg + n)
		b, _ := e.dst.File(migAwg + n)
		if !bytes.Equal(a, b) {
			t.Errorf("%s на цели не равен источнику", n)
		}
	}
	if flocks(e.src) != 0 {
		t.Errorf("на источнике %d команд записи", flocks(e.src))
	}
	if got, _ := e.src.File(migAwg + "wireguard_psk.key"); string(got) != "OLD-PSK\n" {
		t.Error("источник изменён")
	}
	// отпечаток цели — до записи
	fi, ri := strings.Index(out, "Цель (сюда будет записано)"), strings.Index(out, "восстановлен")
	if fi < 0 || !strings.Contains(out[fi:], "ключ хоста SHA256:") || ri < 0 || fi > ri {
		t.Errorf("отпечаток цели не показан до записи:\n%s", out)
	}
	// сказано про автокопию ЦЕЛИ и путь
	nf := newFiles(before, backupsListing(t))
	if len(nf) != 1 {
		t.Fatalf("новых файлов на диске %d: %v", len(nf), nf)
	}
	if !strings.Contains(out, "Автокопия НОВОГО сервера") || !strings.Contains(out, nf[0]) || !strings.Contains(out, "Источник на диск не записывался") {
		t.Errorf("про автокопию цели:\n%s", out)
	}
	ac, err := core.ReadBackupFile(nf[0], core.PlainLayer{})
	if err != nil {
		t.Fatal(err)
	}
	var acConf []byte
	for _, c := range ac.Containers {
		for _, f := range c.Files {
			if c.Name == "amnezia-awg" && f.Name == "wg0.conf" {
				acConf = f.Data.Bytes()
			}
		}
	}
	if !bytes.Equal(acConf, dstConfBefore) {
		t.Error("автокопия — не прежнее состояние цели")
	}
	raw, _ := os.ReadFile(nf[0])
	if bytes.Contains(raw, []byte(srcPriv)) || bytes.Contains(raw, []byte("OLD-PSK")) {
		t.Error("секрет источника в файле на диске")
	}
	if f := dirFilesCLI(tmp); len(f) != 0 {
		t.Errorf("во временном каталоге файлы: %v", f)
	}
	noSecrets(t, "переезд", e, out, errOut)
}

func dirFilesCLI(dir string) []string {
	var out []string
	_ = filepath.Walk(dir, func(p string, fi os.FileInfo, err error) error {
		if err == nil && !fi.IsDir() {
			out = append(out, p)
		}
		return nil
	})
	return out
}

// TestCLIMigratePreview — без -apply: ничего не записано ни на сервер, ни на
// диск; напечатан предпросмотр.
func TestCLIMigratePreview(t *testing.T) {
	e := newMigEnv(t, true)
	before := backupsListing(t)
	code, out, errOut := e.run(t, "", "-client-host", "keep-ip")
	if code != 0 || !strings.Contains(out, "это предпросмотр") && !strings.Contains(out, "Это предпросмотр") {
		t.Fatalf("код %d\n%s\n%s", code, out, errOut)
	}
	if flocks(e.dst) != 0 || flocks(e.src) != 0 || len(newFiles(before, backupsListing(t))) != 0 {
		t.Error("предпросмотр что-то записал")
	}
	noSecrets(t, "предпросмотр", e, out, errOut)
}

// TestCLIMigrateStops — СТОП до записи: «не совпало» и «узнать не удалось»
// различаются в выводе; код 4; на цель и на диск ничего.
func TestCLIMigrateStops(t *testing.T) {
	cases := []struct {
		name  string
		setup func(e *migEnv)
		want  string
		not   string
	}{
		{"порт не совпал", func(e *migEnv) {
			b, _ := e.dst.File(migAwg + "wg0.conf")
			e.dst.SetFile(migAwg+"wg0.conf", []byte(strings.Replace(string(b), "ListenPort = 51820", "ListenPort = 40000", 1)))
		}, "порт: НЕ совпадает", "узнать не удалось"},
		{"версию цели узнать не удалось", func(e *migEnv) {
			e.dst.FailRead = map[string]error{migAwg + "wg0.conf": os.ErrPermission}
		}, "протокол и версия: узнать не удалось", "НЕ совпадает"},
		{"источник не прочитан целиком", func(e *migEnv) {
			e.src.FailRead = map[string]error{migAwg + "clientsTable": os.ErrPermission}
		}, "контейнер: узнать не удалось", "НЕ совпадает"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newMigEnv(t, true)
			c.setup(e)
			before := backupsListing(t)
			code, out, errOut := e.run(t, "", "-client-host", "keep-ip", "-no-password", "-apply", "-yes", "-replace-users", "-address-changes")
			if code != 4 || !strings.Contains(out, "ПЕРЕЕЗД ОСТАНОВЛЕН") || !strings.Contains(out, c.want) || strings.Contains(out, c.not) {
				t.Fatalf("код %d\n%s\n%s", code, out, errOut)
			}
			if flocks(e.dst) != 0 || len(newFiles(before, backupsListing(t))) != 0 {
				t.Error("при СТОП что-то записано")
			}
			noSecrets(t, c.name, e, out, errOut)
		})
	}
}

// TestCLIMigrateSameServer — один и тот же сервер: одинаковые ключи (до
// подключения), один сервер под двумя сессиями (по отпечатку ключа хоста).
// Отказ, код 4, записей нет.
func TestCLIMigrateSameServer(t *testing.T) {
	keyA, khA, exec := setupFakeSSHForRunWithExec(t)
	var o, er bytes.Buffer
	code := runMigrateCmd(context.Background(), strings.NewReader(""), &o, &er, false, keyA, keyA, "", "", khA, "", false, migrateFlags{apply: true, yes: true, noPw: true}, time.Now())
	if code != 4 || !strings.Contains(er.String(), "один и тот же сервер") {
		t.Fatalf("одинаковые ключи: код %d\n%s", code, er.String())
	}
	o.Reset()
	er.Reset()
	s1, s2 := cliSession(t, keyA, khA), cliSession(t, keyA, khA)
	code = runMigrate(context.Background(), strings.NewReader(""), &o, &er, false, s1, s2, migrateFlags{apply: true, yes: true, noPw: true, addrOK: true, replaceUsers: true}, time.Now())
	if code != 4 || !strings.Contains(er.String(), "один и тот же сервер") || flocks(exec) != 0 {
		t.Fatalf("один сервер, две сессии: код %d записей %d\n%s\n%s", code, flocks(exec), o.String(), er.String())
	}
}

// TestCLIMigrateNeedsExplicitTargetFingerprint — без терминала неизвестный
// ключ хоста цели без -to-hostkey — отказ (код 2), как у остальных команд;
// с верным -to-hostkey — предпросмотр идёт.
func TestCLIMigrateNeedsExplicitTargetFingerprint(t *testing.T) {
	e := newMigEnv(t, false)
	code, out, errOut := e.run(t, "", "-client-host", "keep-ip")
	if code != 2 || !strings.Contains(errOut, "-to-hostkey") || flocks(e.dst) != 0 {
		t.Fatalf("код %d\n%s\n%s", code, out, errOut)
	}
}

// TestCLIMigrateNonTTYNeedsChoices — без терминала нужны -yes и выбор
// пароля автокопии цели: без них код 2 и записей нет.
func TestCLIMigrateNonTTYNeedsChoices(t *testing.T) {
	e := newMigEnv(t, true)
	before := backupsListing(t)
	code, out, errOut := e.run(t, "", "-client-host", "keep-ip", "-apply", "-replace-users", "-address-changes")
	if code != 2 || !strings.Contains(errOut, "-password-file") || flocks(e.dst) != 0 {
		t.Fatalf("без выбора пароля: код %d\n%s\n%s", code, out, errOut)
	}
	code, out, errOut = e.run(t, "", "-client-host", "keep-ip", "-no-password", "-apply", "-replace-users", "-address-changes")
	if code != 2 || !strings.Contains(errOut, "-yes") || flocks(e.dst) != 0 {
		t.Fatalf("без -yes: код %d\n%s\n%s", code, out, errOut)
	}
	code, out, _ = e.run(t, "", "-client-host", "keep-ip", "-no-password", "-apply", "-yes", "-address-changes")
	if code != 2 || !strings.Contains(out, replaceUsersRefuse) || flocks(e.dst) != 0 {
		t.Fatalf("без -replace-users: код %d\n%s", code, out)
	}
	code, out, _ = e.run(t, "", "-no-password", "-apply", "-yes", "-replace-users")
	if code != 4 || !strings.Contains(out, "адрес другой или не проверен") || !strings.Contains(out, migrateUnknownAddrHint) || flocks(e.dst) != 0 {
		t.Fatalf("без -address-changes: код %d\n%s", code, out)
	}
	if len(newFiles(before, backupsListing(t))) != 0 {
		t.Error("отказы что-то записали на диск")
	}
}

// TestCLIMigrateTargetDrop — обрыв записи на цели на втором контейнере:
// третье состояние в выводе, код 1; первый контейнер назван перенесённым.
func TestCLIMigrateTargetDrop(t *testing.T) {
	e := newMigEnv(t, true)
	for _, s := range []*fakesrv.Server{e.src, e.dst} {
		s.Names = append(s.Names, "amnezia-wireguard")
		conf, _ := s.File(migAwg + "wg0.conf")
		tbl, _ := s.File(migAwg + "clientsTable")
		s.SetFile("/opt/amnezia/wireguard/wg0.conf", conf)
		s.SetFile("/opt/amnezia/wireguard/clientsTable", tbl)
	}
	e.dst.WriteFault = map[int]fakesrv.WriteFault{2: {Code: 255, Written: true}}
	code, out, errOut := e.run(t, "", "-client-host", "keep-ip", "-no-password", "-apply", "-yes", "-replace-users", "-address-changes")
	if code != 1 || !strings.Contains(out, "НЕИЗВЕСТНО, ЧТО ЗАПИСАНО на новом сервере: amnezia-wireguard") ||
		!strings.Contains(out, "amnezia-awg: восстановлен") || strings.Contains(out, "amnezia-wireguard: восстановлен") {
		t.Fatalf("код %d\n%s\n%s", code, out, errOut)
	}
	noSecrets(t, "обрыв", e, out, errOut)
}

// TestCLIMigrateTTY — терминал: вопросы по порядку (пароль автокопии «нет»,
// замена «y», пользователи цели — слово «записать»); не то слово — отмена
// без записи.
func TestCLIMigrateTTY(t *testing.T) {
	e := newMigEnv(t, true)
	s1, s2 := cliSession(t, e.keySrc, e.kh), cliSession(t, e.keyDst, e.kh)
	s1.ClientHostDecided = true
	var o, er bytes.Buffer
	f := migrateFlags{apply: true, addrOK: true}
	code := runMigrate(context.Background(), strings.NewReader("n\ny\nнет\n"), &o, &er, true, s1, s2, f, time.Now())
	if code != 2 || flocks(e.dst) != 0 || !strings.Contains(o.String(), "Всё равно записать?") {
		t.Fatalf("не то слово: код %d записей %d\n%s\n%s", code, flocks(e.dst), o.String(), er.String())
	}
	o.Reset()
	s1, s2 = cliSession(t, e.keySrc, e.kh), cliSession(t, e.keyDst, e.kh)
	s1.ClientHostDecided = true
	code = runMigrate(context.Background(), strings.NewReader("n\ny\nзаписать\n"), &o, &er, true, s1, s2, f, time.Now())
	if code != 0 || flocks(e.dst) == 0 || !strings.Contains(o.String(), "amnezia-awg: восстановлен") {
		t.Fatalf("«записать»: код %d записей %d\n%s\n%s", code, flocks(e.dst), o.String(), er.String())
	}
}

// TestMigrateCLIErrorsMasked — в migrate.go ни одна ошибка не печатается
// напрямую: только через backupErr или core.MaskText. Подсадка
// «fmt.Fprintln(errOut, err)» роняет сторож.
func TestMigrateCLIErrorsMasked(t *testing.T) {
	src, err := os.ReadFile("migrate.go")
	if err != nil {
		t.Fatal(err)
	}
	re := regexp.MustCompile(`fmt\.Fprint\w*\([^\n]*\berr\b`)
	n := 0
	for i, l := range strings.Split(string(src), "\n") {
		if strings.Contains(l, "fmt.Fprint") {
			n++
		}
		if re.MatchString(l) && !strings.Contains(l, "MaskText(") && !strings.Contains(l, "errText(") {
			t.Errorf("migrate.go:%d: ошибка печатается в обход маскировки: %s", i+1, strings.TrimSpace(l))
		}
	}
	if n < 10 {
		t.Fatalf("сторож ничего не видит: строк вывода %d", n)
	}
}

// TestCLIMigrateKeyNeverInOutput — ключ из -key/-to-key не появляется ни в
// выводе, ни в ошибке, даже если ошибка подключения несёт его целиком
// (шов migrateDial; граница маскировки — core.MaskText).
// Подмена: убрать правило vpn:// из core.maskFreeText — роняет.
func TestCLIMigrateKeyNeverInOutput(t *testing.T) {
	keyA, khA, _ := setupFakeSSHForRunWithExec(t)
	keyB, _, _ := setupFakeSSHForRunWithExec(t)
	old := migrateDial
	t.Cleanup(func() { migrateDial = old })
	for _, which := range []string{"источник", "цель"} {
		n := 0
		migrateDial = func(c *core.ServerCreds, p core.HostKeyPolicy) (*core.Session, error) {
			n++
			if (which == "источник") == (n == 1) {
				return nil, errors.New("dial " + keyA + " и " + keyB + " отказ")
			}
			return old(c, p)
		}
		var o, er bytes.Buffer
		code := runMigrateCmd(context.Background(), strings.NewReader(""), &o, &er, false, keyA, keyB, "", "", khA, "", false, migrateFlags{}, time.Now())
		all := o.String() + er.String()
		if code == 0 || !strings.Contains(all, "отказ") {
			t.Fatalf("%s: ошибка не дошла до вывода (код %d): %s", which, code, all)
		}
		for _, k := range []string{keyA, keyB} {
			body := strings.TrimPrefix(k, "vpn://")
			if strings.Contains(all, body[:24]) {
				t.Errorf("%s: ключ в выводе: %s", which, all)
			}
		}
	}
}
