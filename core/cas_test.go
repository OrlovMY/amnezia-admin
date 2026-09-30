package core

// CAS (Г4) после A3б: сверка внутри одной команды записи под замком
// (core/caswrite.go). Здесь — отказ «изменён другим» (прежние
// TestCASMismatchRefuses и NoSha256, перенесённые на новую команду) и три
// состояния, отличные и от «записано», и от «изменён другим»: T3 «занято»,
// T4 «неизвестно, записано ли», T5 «нет утилиты».

import (
	"bytes"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"amnezia-admin/internal/fakesrv"
)

// isCASWriteCmd — команда записи (apply или rollback).
func isCASWriteCmd(cmd string) bool {
	return strings.Contains(cmd, "flock -w 15 -E 4 /run/lock docker exec")
}

// snapshot — оба файла на сервере.
func snapshot(t *testing.T, srv *fakesrv.Server, c *Container) (wg, tbl []byte) {
	t.Helper()
	wg, _ = srv.File(c.Dir + "/wg0.conf")
	tbl, _ = srv.File(c.Dir + "/clientsTable")
	return wg, tbl
}

func assertUnchanged(t *testing.T, srv *fakesrv.Server, c *Container, wg, tbl []byte) {
	t.Helper()
	wg2, tbl2 := snapshot(t, srv, c)
	if !bytes.Equal(wg, wg2) || !bytes.Equal(tbl, tbl2) {
		t.Errorf("файлы на сервере изменились, хотя запись не должна была состояться")
	}
}

// assertOnly — err распознаётся ровно как want и ни как один другой исход.
func assertOnly(t *testing.T, err error, want error) {
	t.Helper()
	if err == nil {
		t.Fatalf("ждали отказ (%v), получили успех", want)
	}
	all := []error{ErrCASMismatch, ErrServerBusy, ErrServerToolMissing, ErrWriteUnknown, ErrRollbackForeign}
	for _, e := range all {
		if got := errors.Is(err, e); got != (e == want) {
			t.Errorf("errors.Is(err, %q) = %v, ждали %v; err: %v", e, got, e == want, err)
		}
	}
}

// TestCASMismatchRefuses — файл изменился между планом и применением:
// «изменён другим», ничего не записано, текст называет файл.
func TestCASMismatchRefuses(t *testing.T) {
	cases := []struct {
		name, file string
		mutate     func(srv *fakesrv.Server, c *Container)
	}{
		{"clientsTable изменилась", "clientsTable", func(srv *fakesrv.Server, c *Container) {
			tbl, _ := srv.File(c.Dir + "/clientsTable")
			srv.SetFile(c.Dir+"/clientsTable", append(append([]byte{}, tbl...), ' '))
		}},
		{"wg0.conf изменился", "wg0.conf", func(srv *fakesrv.Server, c *Container) {
			wg, _ := srv.File(c.Dir + "/wg0.conf")
			srv.SetFile(c.Dir+"/wg0.conf", append(append([]byte{}, wg...), '\n'))
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := fakesrv.New()
			sess := NewSessionWithRunner(srv, testCreds())
			c := awgContainer()
			plan, err := sess.PlanAddUser(c, "Carol")
			if err != nil {
				t.Fatalf("PlanAddUser: %v", err)
			}
			tc.mutate(srv, c)
			wg, tbl := snapshot(t, srv, c)

			_, err = sess.Apply(plan)
			assertOnly(t, err, ErrCASMismatch)
			if !strings.Contains(err.Error(), c.Dir+"/"+tc.file+" изменился с момента чтения") {
				t.Errorf("текст не называет %s: %v", tc.file, err)
			}
			if strings.Contains(err.Error(), ErrCASMismatch.Error()) {
				t.Errorf("текст содержит сырой текст сентинела: %v", err)
			}
			assertUnchanged(t, srv, c, wg, tbl)
		})
	}

	t.Run("clientsTable появилась, хотя при планировании отсутствовала", func(t *testing.T) {
		srv := fakesrv.New()
		c := awgContainer()
		srv.DeleteFile(c.Dir + "/clientsTable")
		sess := NewSessionWithRunner(srv, testCreds())
		plan, err := sess.PlanAddUser(c, "Carol")
		if err != nil {
			t.Fatalf("PlanAddUser: %v", err)
		}
		srv.SetFile(c.Dir+"/clientsTable", []byte("[]"))
		wg, tbl := snapshot(t, srv, c)

		_, err = sess.Apply(plan)
		assertOnly(t, err, ErrCASMismatch)
		assertUnchanged(t, srv, c, wg, tbl)
	})
}

// TestServerBusyIsThirdState — T3. Замок занят (код 4 flock) — «занято»: не
// «изменён другим», не успех, не «неизвестно»; ничего не записано.
func TestServerBusyIsThirdState(t *testing.T) {
	srv := fakesrv.New()
	srv.LockBusy = true
	sess := NewSessionWithRunner(srv, testCreds())
	c := awgContainer()
	wg, tbl := snapshot(t, srv, c)

	_, err := sess.AddUser(c, "Carol")
	assertOnly(t, err, ErrServerBusy)
	if !strings.Contains(err.Error(), "занят") {
		t.Errorf("текст не говорит «занят»: %v", err)
	}
	assertUnchanged(t, srv, c, wg, tbl)
}

// TestServerBusyOverRealSSH — T3, доезд: код 4 проходит настоящий SSH-канал
// (fakesrv.SSHServer на эфемерном порту) и распознаётся sshRunner'ом так же.
func TestServerBusyOverRealSSH(t *testing.T) {
	sshSrv, exec := newFakeSSHServer(t, "127.0.0.1:0")
	exec.LockBusy = true
	sess, err := ConnectWithHostKey(credsForFakeSSH(t, sshSrv), HostKeyPolicy{
		KnownHostsPath: filepath.Join(t.TempDir(), "known_hosts"),
		Prompt:         alwaysTrustPrompt,
	})
	if err != nil {
		t.Fatalf("ConnectWithHostKey: %v", err)
	}
	t.Cleanup(sess.Close)
	c := awgContainer()
	wg, tbl := snapshot(t, exec, c)

	_, err = sess.AddUser(c, "Carol")
	assertOnly(t, err, ErrServerBusy)
	assertUnchanged(t, exec, c, wg, tbl)
}

// TestUnknownExitIsUnknown — T4. Код вне закрытого списка или отсутствие кода
// — «неизвестно, записано ли»: не успех, не «изменён», не «занято». Два
// случая — запись не состоялась и состоялась: ответ обязан быть одним и тем
// же, потому что снаружи они неразличимы.
func TestUnknownExitIsUnknown(t *testing.T) {
	for _, tc := range []struct {
		name    string
		fault   fakesrv.WriteFault
		written bool
	}{
		{"код 1, не записано", fakesrv.WriteFault{Code: 1}, false},
		{"код 124 (timeout), записано", fakesrv.WriteFault{Code: 124, Written: true}, true},
		{"код 42, записано", fakesrv.WriteFault{Code: 42, Written: true}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := fakesrv.New()
			srv.WriteFault = map[int]fakesrv.WriteFault{1: tc.fault}
			sess := NewSessionWithRunner(srv, testCreds())
			c := awgContainer()
			wg, tbl := snapshot(t, srv, c)

			_, err := sess.AddUser(c, "Carol")
			assertOnly(t, err, ErrWriteUnknown)
			if !strings.Contains(err.Error(), "неизвестно, записаны ли") {
				t.Errorf("текст не говорит «неизвестно»: %v", err)
			}
			rollbacks := 0
			for _, cmd := range srv.Commands() {
				if isCASWriteCmd(cmd) && strings.Contains(cmd, CASLabelRollback) {
					rollbacks++
				}
			}
			if rollbacks != 0 {
				t.Errorf("при неизвестном исходе откат вслепую недопустим, откатов: %d", rollbacks)
			}
			wg2, tbl2 := snapshot(t, srv, c)
			if changed := !bytes.Equal(wg, wg2) || !bytes.Equal(tbl, tbl2); changed != tc.written {
				t.Errorf("файлы изменились = %v, ждали %v", changed, tc.written)
			}
		})
	}

	t.Run("кода выхода нет вовсе (обрыв связи)", func(t *testing.T) {
		base := fakesrv.New()
		r := stubRunner{base: base, match: "flock -w 15", err: errors.New("ssh: connection lost")}
		sess := NewSessionWithRunner(r, testCreds())
		_, err := sess.AddUser(awgContainer(), "Carol")
		assertOnly(t, err, ErrWriteUnknown)
		if !strings.Contains(err.Error(), "код выхода не получен") {
			t.Errorf("текст не говорит, что кода нет: %v", err)
		}
	})
}

// TestMissingToolRefuses — T5. Нет утилиты — «нет утилиты», ничего не
// записано, утилита названа. Прежний NoSha256 — случай "sha256sum".
func TestMissingToolRefuses(t *testing.T) {
	for _, tool := range []string{"sha256sum", "base64", "flock", "timeout"} {
		t.Run(tool, func(t *testing.T) {
			srv := fakesrv.New()
			srv.MissingTool = tool
			sess := NewSessionWithRunner(srv, testCreds())
			c := awgContainer()
			wg, tbl := snapshot(t, srv, c)

			_, err := sess.AddUser(c, "Carol")
			assertOnly(t, err, ErrServerToolMissing)
			assertUnchanged(t, srv, c, wg, tbl)
			if tool != "flock" && tool != "timeout" && !strings.Contains(err.Error(), tool) {
				t.Errorf("текст не называет %s: %v", tool, err)
			}
			if strings.Contains(err.Error(), "изменился") {
				t.Errorf("ложь: сервер не менялся, а текст говорит «изменился»: %v", err)
			}
		})
	}
}

// stubRunner подменяет ОДНУ команду (по подстроке match), остальные отдаёт base.
type stubRunner struct {
	base  Runner
	match string
	out   string
	err   error
}

func (r stubRunner) Run(cmd string, stdin []byte) (string, error) {
	if strings.Contains(cmd, r.match) {
		return r.out, r.err
	}
	return r.base.Run(cmd, stdin)
}

// TestCASWriteCommandRejectsBadArgs — в текст команды не попадает ничего,
// кроме имени, пути и сумм; скрипт не содержит одинарных кавычек (он сам в
// них).
func TestCASWriteCommandRejectsBadArgs(t *testing.T) {
	good := strings.Repeat("a", 64)
	if strings.Contains(CASWriteScript, "'") {
		t.Fatal("в CASWriteScript есть одинарная кавычка — команда разорвётся")
	}
	if _, err := CASWriteCommand(CASLabelApply, "amnezia-awg", "/opt/amnezia/awg", good, CASAbsent); err != nil {
		t.Fatalf("корректные аргументы отвергнуты: %v", err)
	}
	bad := [][5]string{
		{"x", "amnezia-awg", "/opt/amnezia/awg", good, good},
		{CASLabelApply, "a;rm", "/opt/amnezia/awg", good, good},
		{CASLabelApply, "amnezia-awg", "/opt/a b", good, good},
		{CASLabelApply, "amnezia-awg", "/opt/amnezia/awg", "zz", good},
		{CASLabelApply, "amnezia-awg", "/opt/amnezia/awg", good, "' ; x"},
	}
	for _, a := range bad {
		if _, err := CASWriteCommand(a[0], a[1], a[2], a[3], a[4]); err == nil {
			t.Errorf("CASWriteCommand%q: ждали отказ", a)
		}
	}
}
