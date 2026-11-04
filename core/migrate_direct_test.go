package core

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"amnezia-admin/internal/fakesrv"
)

const (
	migSrcHost = "203.0.113.1"
	migDstHost = "198.51.100.9"
)

func migSessions(src, tgt *fakesrv.Server) (*Session, *Session) {
	s := NewSessionWithRunner(src, &ServerCreds{Host: migSrcHost})
	s.ClientHostDecided = true
	return s, NewSessionWithRunner(tgt, &ServerCreds{Host: migDstHost})
}

func migOpts() MigrationOptions {
	return MigrationOptions{ToolVersion: "t", Now: backupNow, Resolve: okResolver}
}

// migApply — параметры записи: автокопия цели в dir, адрес подтверждён
// (у пары разные адреса).
func migApply(dir string) MigrateOptions {
	return MigrateOptions{
		RestoreOptions:   RestoreOptions{AutoCopyDir: dir, ToolVersion: "t", Now: backupNow, Resolve: okResolver, Layer: PlainLayer{}, TargetConfirmed: true},
		AddressConfirmed: true,
	}
}

func migPrepare(t *testing.T, src, tgt *fakesrv.Server) (*Migration, *Session) {
	t.Helper()
	t.Cleanup(SetXRayWaits(0, 0))
	ss, ts := migSessions(src, tgt)
	m, err := PrepareMigration(context.Background(), ss, ts, migOpts())
	if err != nil {
		t.Fatal(err)
	}
	if m.Compat.Stop || m.Plan == nil {
		t.Fatalf("СТОП: %+v", m.Compat.Rows)
	}
	return m, ts
}

// dirFiles — все файлы каталога (рекурсивно).
func dirFiles(t *testing.T, dir string) []string {
	t.Helper()
	var out []string
	_ = filepath.Walk(dir, func(p string, fi os.FileInfo, err error) error {
		if err == nil && !fi.IsDir() {
			out = append(out, p)
		}
		return nil
	})
	return out
}

// TestMigrateNoSourceOnDisk — канарейка «ни байта источника на диск»:
// после полного переезда на диске (каталог автокопии и временный каталог
// процесса) единственный файл — автокопия ЦЕЛИ: читается как копия сервера
// цели, а секреты источника (ключ сервера, PSK, содержимое конфигурации) не
// встречаются ни в одном файле. Источник при этом не изменён и не писался.
// Подмена: PrepareMigration вызывает WriteBackupFile(источник) — роняет тест
// (лишний файл, копия не цели, секрет источника в файле).
func TestMigrateNoSourceOnDisk(t *testing.T) {
	src, tgt := migrationPair(t)
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)
	t.Setenv("TEMP", tmp)
	t.Setenv("TMP", tmp)
	srcWg, _ := src.File(awgDir + "/wg0.conf")
	srcPriv := parseWgConf(string(srcWg)).iface["PrivateKey"]
	if len(srcPriv) < 20 {
		t.Fatalf("тест ничего не значит: ключ %q", srcPriv)
	}
	srcBefore := map[string][]byte{}
	for _, n := range []string{"wg0.conf", "clientsTable", keyPub, keyPsk} {
		srcBefore[n], _ = src.File(awgDir + "/" + n)
	}

	m, ts := migPrepare(t, src, tgt)
	dir := t.TempDir()
	auto, outs, err := m.Apply(migApply(dir))
	if err != nil || len(outs) != 1 || outs[0].State != RestoreDone {
		t.Fatalf("переезд: %v %+v", err, outs)
	}
	// на цели — как на источнике
	for n, want := range srcBefore {
		if got, _ := tgt.File(awgDir + "/" + n); !bytes.Equal(got, want) {
			t.Errorf("%s на цели не равен источнику", n)
		}
	}
	// источник не менялся и не писался
	for n, want := range srcBefore {
		if got, _ := src.File(awgDir + "/" + n); !bytes.Equal(got, want) {
			t.Errorf("%s источника изменён", n)
		}
	}
	if n := writesOf(src); n != 0 {
		t.Errorf("на источнике %d команд записи", n)
	}
	// на диске — только автокопия цели
	files := append(dirFiles(t, dir), dirFiles(t, tmp)...)
	if len(files) != 1 || files[0] != auto {
		t.Fatalf("на диске должна быть одна автокопия цели %s, а есть: %v", auto, files)
	}
	if !strings.Contains(filepath.Base(auto), migDstHost) || strings.Contains(filepath.Base(auto), migSrcHost) {
		t.Errorf("имя автокопии не цели: %s", auto)
	}
	ac, err := ReadBackupFile(auto, PlainLayer{})
	if err != nil {
		t.Fatal(err)
	}
	if ac.Server.Host != migDstHost {
		t.Errorf("автокопия не цели: хост %q", ac.Server.Host)
	}
	raw, _ := os.ReadFile(auto)
	for _, secret := range []string{srcPriv, "OLD-PSK", "OLD-PUB"} {
		if bytes.Contains(raw, []byte(secret)) {
			t.Errorf("секрет источника %q в файле на диске", secret)
		}
	}
	if f := fileOfB(ctrOf(t, ac, "amnezia-awg"), "wg0.conf"); bytes.Equal(f.Data.Bytes(), srcBefore["wg0.conf"]) {
		t.Error("автокопия содержит конфигурацию источника, а не цели")
	}
	_ = ts
}

// TestMigrateStopTable — три состояния различаются: «совпало» — план есть;
// «не совпало» (порт, версия) и «узнать не удалось» (цель или источник не
// прочитаны) — СТОП до записи с разными строками проверки; запись на цель
// отказана ядром, автокопии и записей нет. Подмена «Stop только для
// Mismatch» или «Unknown → Match» в CheckTarget роняет таблицу.
func TestMigrateStopTable(t *testing.T) {
	awg2 := func() *fakesrv.Server { return fakesrv.NewAWG2() }
	cases := []struct {
		name   string
		mk     func(t *testing.T) (src, tgt *fakesrv.Server)
		ctr    string
		what   string
		want   CompatState
		stop   bool
		inText string
	}{
		{"всё совпало", func(t *testing.T) (*fakesrv.Server, *fakesrv.Server) { return migrationPair(t) },
			"amnezia-awg", "порт", CompatMatch, false, ""},
		{"порт не совпал", func(t *testing.T) (*fakesrv.Server, *fakesrv.Server) {
			s, d := migrationPair(t)
			setIface(t, d, awgDir+"/wg0.conf", "ListenPort", "40000")
			return s, d
		}, "amnezia-awg", "порт", CompatMismatch, true, "с портом 51820"},
		{"версия не совпала", func(t *testing.T) (*fakesrv.Server, *fakesrv.Server) {
			s, d := awg2(), awg2()
			b, _ := d.File(awgDir + "/awg0.conf")
			d.SetFile(awgDir+"/awg0.conf", []byte(strings.Replace(string(b), "S3 = 15\n", "S3 = 15\nRekeyAfterTime = 120\n", 1))) // у цели версия 3.1
			return s, d
		}, "amnezia-awg2", "протокол и версия", CompatMismatch, true, "ту же версию"},
		{"версию цели узнать не удалось", func(t *testing.T) (*fakesrv.Server, *fakesrv.Server) {
			s, d := migrationPair(t)
			d.FailRead = map[string]error{awgDir + "/wg0.conf": errors.New("cat: Input/output error")}
			return s, d
		}, "amnezia-awg", "протокол и версия", CompatUnknown, true, "определить не удалось"},
		{"источник не прочитан целиком", func(t *testing.T) (*fakesrv.Server, *fakesrv.Server) {
			s, d := migrationPair(t)
			s.FailRead = map[string]error{awgDir + "/clientsTable": errors.New("cat: Permission denied")}
			return s, d
		}, "amnezia-awg", "контейнер", CompatUnknown, true, "не сохранён"},
	}
	var matchState, mismatchState, unknownState CompatState
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			src, tgt := c.mk(t)
			t.Cleanup(SetXRayWaits(0, 0))
			ss, ts := migSessions(src, tgt)
			m, err := PrepareMigration(context.Background(), ss, ts, migOpts())
			if err != nil {
				t.Fatalf("подготовка: %v", err)
			}
			row, ok := rowOf(m.Compat, c.ctr, c.what)
			if !ok || row.State != c.want || !strings.Contains(row.Text, c.inText) {
				t.Fatalf("строка %+v (есть=%v), ждали %v с «%s»; все: %+v", row, ok, c.want, c.inText, m.Compat.Rows)
			}
			if m.Compat.Stop != c.stop || (m.Plan == nil) != c.stop {
				t.Fatalf("СТОП=%v план=%v, ждали СТОП=%v", m.Compat.Stop, m.Plan != nil, c.stop)
			}
			switch c.want {
			case CompatMatch:
				matchState = row.State
			case CompatMismatch:
				mismatchState = row.State
			default:
				unknownState = row.State
			}
			if !c.stop {
				return
			}
			dir := t.TempDir()
			if _, _, err := m.Apply(migApply(dir)); !errors.Is(err, ErrRestoreStopped) {
				t.Fatalf("запись при СТОП: %v", err)
			}
			if n := writesOf(tgt); n != 0 {
				t.Errorf("записей на цель: %d", n)
			}
			if f := dirFiles(t, dir); len(f) != 0 {
				t.Errorf("файлы на диске при СТОП: %v", f)
			}
		})
	}
	if unknownState == mismatchState || unknownState == matchState || mismatchState == matchState {
		t.Errorf("три состояния не различаются: %v %v %v", matchState, mismatchState, unknownState)
	}
}

// TestMigrateSourceUnreadable — источник не отвечает вовсе: ошибка, а не
// пустой «успех»; цель не трогается.
func TestMigrateSourceUnreadable(t *testing.T) {
	src, tgt := migrationPair(t)
	src.FailDockerPS = errors.New("ssh: connection lost")
	ss, ts := migSessions(src, tgt)
	m, err := PrepareMigration(context.Background(), ss, ts, migOpts())
	if err == nil || m != nil || !strings.Contains(err.Error(), "источник не прочитан") {
		t.Fatalf("ждали отказ: %v", err)
	}
	if len(tgt.Commands()) != 0 {
		t.Errorf("цель тронута: %v", tgt.Commands())
	}
}

// TestMigrateTargetDropUnknown — обрыв связи с целью на второй записи
// после записи файлов: первый контейнер перенесён, второй — «неизвестно,
// что записано» (не «восстановлен», не «ничего не записано»). Тест
// различения — тот же сбой, но «ничего не записано» (запись не дошла): в
// выводе нет раздела «НЕИЗВЕСТНО». Подмена classify: «неопознанное →
// RestoreDone/RestoreNotWritten» роняет тест.
func TestMigrateTargetDropUnknown(t *testing.T) {
	addWG := func(s *fakesrv.Server) {
		s.Names = append(s.Names, "amnezia-wireguard")
		conf, _ := s.File(awgDir + "/wg0.conf")
		tbl, _ := s.File(awgDir + "/clientsTable")
		s.SetFile("/opt/amnezia/wireguard/wg0.conf", conf)
		s.SetFile("/opt/amnezia/wireguard/clientsTable", tbl)
	}
	run := func(t *testing.T, f fakesrv.WriteFault) (outs []RestoreOutcome, lines string) {
		src, tgt := migrationPair(t)
		addWG(src)
		addWG(tgt)
		m, _ := migPrepare(t, src, tgt)
		if len(m.Plan.Items) != 2 {
			t.Fatalf("контейнеров в плане %d", len(m.Plan.Items))
		}
		tgt.WriteFault = map[int]fakesrv.WriteFault{2: f}
		auto, outs, err := m.Apply(migApply(t.TempDir()))
		if err != nil {
			t.Fatal(err)
		}
		return outs, strings.Join(MigrationOutcomeLines(auto, false, outs), "\n")
	}
	outs, lines := run(t, fakesrv.WriteFault{Code: 255, Written: true})
	if outs[0].State != RestoreDone || outs[1].State != RestoreUnknown {
		t.Fatalf("исходы: %v / %v", outs[0].State, outs[1].State)
	}
	if !strings.Contains(lines, "НЕИЗВЕСТНО, ЧТО ЗАПИСАНО на новом сервере: amnezia-wireguard") ||
		!strings.Contains(lines, "ПЕРЕНЕСЕНО ЧАСТИЧНО") || !strings.Contains(lines, "состояние неизвестно") {
		t.Errorf("третье состояние не названо:\n%s", lines)
	}
	outs, lines = run(t, fakesrv.WriteFault{Code: 3})
	if outs[1].State != RestoreNotWritten || strings.Contains(lines, "НЕИЗВЕСТНО, ЧТО ЗАПИСАНО") {
		t.Errorf("«ничего не записано» выдано за неизвестное: %v\n%s", outs[1].State, lines)
	}
}

// TestMigrateSameServer — таблица «один ли сервер»: да / нет / узнать не
// удалось; «да» и «не удалось» — отказ без единой команды на любом из
// серверов. Подмена SameServer: «Unknown → No» или «порт разный → No»
// роняет таблицу.
func TestMigrateSameServer(t *testing.T) {
	mk := func(host, port, fp string) *Session {
		s := NewSessionWithRunner(fakesrv.New(), &ServerCreds{Host: host, Port: port})
		s.HostKeyFingerprint = fp
		return s
	}
	noHost := func(string) ([]net.IP, error) { return nil, errors.New("no such host") }
	cases := []struct {
		name string
		a, b *Session
		want SameServerVerdict
	}{
		{"один ключ хоста, один адрес, разные порты", mk(migSrcHost, "22", "SHA256:x"), mk(migSrcHost, "2222", "SHA256:x"), SameYes},
		{"один ключ хоста, адреса разные (клон) — не знаем", mk(migSrcHost, "22", "SHA256:x"), mk(migDstHost, "22", "SHA256:x"), SameUnknown},
		{"тот же адрес и порт", mk(migSrcHost, "22", ""), mk(migSrcHost, "", ""), SameYes},
		{"разные адреса", mk(migSrcHost, "22", ""), mk(migDstHost, "22", ""), SameNo},
		{"разные ключи хоста", mk(migSrcHost, "22", "SHA256:x"), mk(migSrcHost, "2222", "SHA256:y"), SameNo},
		{"тот же адрес, порты разные, ключей нет — не знаем", mk(migSrcHost, "22", ""), mk(migSrcHost, "2222", ""), SameUnknown},
		{"имя не разрешилось, ключей нет — не знаем", mk("gone.example", "22", ""), mk(migDstHost, "22", ""), SameUnknown},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, why := SameServer(c.a, c.b, noHost)
			if got != c.want || why == "" {
				t.Fatalf("%v (%s), ждали %v", got, why, c.want)
			}
			opt := migOpts()
			opt.Resolve = noHost
			m, err := PrepareMigration(context.Background(), c.a, c.b, opt)
			if c.want == SameNo {
				// разные серверы: подготовка идёт дальше (здесь — читает fakesrv.New)
				if errors.Is(err, ErrSameServer) {
					t.Fatalf("разные серверы отвергнуты: %v", err)
				}
				return
			}
			if !errors.Is(err, ErrSameServer) || m != nil {
				t.Fatalf("ждали отказ ErrSameServer: %v", err)
			}
			if n := len(c.a.r.(*fakesrv.Server).Commands()) + len(c.b.r.(*fakesrv.Server).Commands()); n != 0 {
				t.Errorf("при отказе выполнено команд: %d", n)
			}
		})
	}
}

// TestMigrateAddressConfirmInCore — ядро само не пишет при «адрес другой»
// без отдельного подтверждения (проверка CLI обойдена).
func TestMigrateAddressConfirmInCore(t *testing.T) {
	src, tgt := migrationPair(t)
	m, _ := migPrepare(t, src, tgt)
	if !m.Compat.NeedAddressConfirm {
		t.Fatalf("тест ничего не значит: адрес %v", m.Compat.Address)
	}
	opt := migApply(t.TempDir())
	opt.AddressConfirmed = false
	if _, _, err := m.Apply(opt); !errors.Is(err, ErrRestoreStopped) || writesOf(tgt) != 0 {
		t.Fatalf("запись без подтверждения адреса: %v, записей %d", err, writesOf(tgt))
	}
}

// TestMigrateSecretsNotPrinted — по образцу TestBackupSecretsNotPrinted:
// ни один глагол fmt, ни одна строка итога/проверки, ни один текст ошибки
// не выдаёт секреты источника (ключ сервера, PSK, содержимое файлов).
func TestMigrateSecretsNotPrinted(t *testing.T) {
	src, tgt := migrationPair(t)
	srcWg, _ := src.File(awgDir + "/wg0.conf")
	priv := parseWgConf(string(srcWg)).iface["PrivateKey"]
	if len(priv) < 20 {
		t.Fatalf("тест ничего не значит: ключ %q", priv)
	}
	m, _ := migPrepare(t, src, tgt)
	var all []string
	c := ctrOf(t, m.Source(), "amnezia-awg")
	f := fileOfB(c, "wg0.conf")
	for _, v := range []any{m, *m, m.Source(), m.Plan, *m.Plan, m.Compat, c, f, f.Data} {
		all = append(all, fmt.Sprint(v), fmt.Sprintf("%+v", v), fmt.Sprintf("%#v", v), fmt.Sprintf("%s", v), fmt.Sprintf("%q", v), fmt.Sprintf("%x", v))
	}
	all = append(all, BackupSummaryLines(m.Source())...)
	all = append(all, CompatLines(m.Compat)...)
	all = append(all, RestorePlanLines(m.Plan)...)
	auto, outs, err := m.Apply(migApply(t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	all = append(all, MigrationOutcomeLines(auto, false, outs)...)
	// ошибки: источник, который не отвечает, с секретом в тексте ошибки
	src2, tgt2 := migrationPair(t)
	src2.FailRead = map[string]error{awgDir + "/clientsTable": errors.New("cat: denied; PrivateKey = " + priv)}
	ss, ts := migSessions(src2, tgt2)
	m2, err2 := PrepareMigration(context.Background(), ss, ts, migOpts())
	if err2 != nil {
		all = append(all, err2.Error())
	} else {
		all = append(all, CompatLines(m2.Compat)...)
		all = append(all, CompatStopLines(m2.Compat)...)
	}
	for _, v := range all {
		if strings.Contains(v, priv) || strings.Contains(v, "OLD-PSK") || strings.Contains(v, "[Interface]") {
			t.Fatalf("секрет в выводе: %.160s", v)
		}
	}
}
