package main

// A3б PR-3: исходы записи в CLI — ДОЕЗД через полный run() против
// fakesrv.ListenSSH (настоящий SSH, эфемерный порт 127.0.0.1): что видит
// человек в stderr для каждого исхода, и что успех этих текстов не печатает.

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"

	"amnezia-admin/core"
	"amnezia-admin/internal/fakesrv"
	"amnezia-admin/internal/writeoutcome"
)

func TestPR3CLIWriteOutcomes(t *testing.T) {
	cases := []struct {
		name string
		prep func(*fakesrv.Server)
		kind writeoutcome.Kind
	}{
		{"изменён другим", func(s *fakesrv.Server) {
			s.ForeignWrite = map[int]map[string][]byte{1: {"/opt/amnezia/awg/clientsTable": []byte("[]")}}
		}, writeoutcome.Changed},
		{"занято", func(s *fakesrv.Server) { s.LockBusy = true }, writeoutcome.Busy},
		{"нет утилиты", func(s *fakesrv.Server) { s.MissingTool = "flock" }, writeoutcome.ToolMissing},
		{"замок не открыт", func(s *fakesrv.Server) { s.WriteFault = map[int]fakesrv.WriteFault{1: {Code: 66}} }, writeoutcome.LockUnavailable},
		{"неизвестно", func(s *fakesrv.Server) { s.WriteFault = map[int]fakesrv.WriteFault{1: {Code: 124}} }, writeoutcome.Unknown},
		{"частично", func(s *fakesrv.Server) { s.FailMvTo = "clientsTable" }, writeoutcome.Partial},
		{"откат не тронул чужое", func(s *fakesrv.Server) {
			s.FailSyncconf = errors.New("имитированный отказ syncconf")
			s.ForeignWrite = map[int]map[string][]byte{2: {"/opt/amnezia/awg/clientsTable": []byte("[]")}}
		}, writeoutcome.RollbackForeign},
	}
	titles := map[writeoutcome.Kind]string{}
	for _, c := range cases {
		tx, _ := writeoutcome.Describe(kindErr(c.kind))
		titles[c.kind] = tx.Title
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			key, kh, srv := setupFakeSSHForRunWithExec(t)
			c.prep(srv)
			var o, e bytes.Buffer
			code := run([]string{"add", "-key", key, "-name", "Mallory"}, strings.NewReader(""), &o, &e, kh)
			if code == 0 {
				t.Fatalf("запись прошла, ожидался исход %q", titles[c.kind])
			}
			want, _ := writeoutcome.Describe(kindErr(c.kind))
			got := e.String()
			for _, part := range []string{want.Title, want.What, want.Next, "Подробности: "} {
				if !strings.Contains(got, part) {
					t.Errorf("в stderr нет %q:\n%s", part, got)
				}
			}
			// Второй, независимый сторож (выборка немоты): исход записи не
			// печатается прежним безликим «Ошибка: …».
			if strings.HasPrefix(got, "Ошибка: ") {
				t.Errorf("исход записи напечатан как безликая ошибка:\n%s", got)
			}
			// различение: ни одного чужого заголовка
			for k, title := range titles {
				if k != c.kind && strings.Contains(got, title) {
					t.Errorf("в stderr чужой исход %q:\n%s", title, got)
				}
			}
		})
	}
	t.Run("записано — текстов исходов нет", func(t *testing.T) {
		key, kh, _ := setupFakeSSHForRunWithExec(t)
		var o, e bytes.Buffer
		if code := run([]string{"add", "-key", key, "-name", "Mallory"}, strings.NewReader(""), &o, &e, kh); code != 0 {
			t.Fatalf("штатная запись: код %d, %s", code, e.String())
		}
		for _, title := range titles {
			if strings.Contains(o.String()+e.String(), title) {
				t.Errorf("при успехе напечатан исход %q", title)
			}
		}
	})
}

// kindErr — ошибка, которую writeoutcome относит к исходу k (только чтобы
// взять эталонный текст; сам тест идёт боевым путём).
func kindErr(k writeoutcome.Kind) error {
	for _, e := range sampleErrs {
		if writeoutcome.Classify(e) == k {
			return e
		}
	}
	return errors.New("нет образца")
}

var sampleErrs = []error{
	fmt.Errorf("%w", core.ErrCASMismatch),
	fmt.Errorf("%w", core.ErrServerBusy),
	fmt.Errorf("%w", core.ErrServerToolMissing),
	fmt.Errorf("%w %w", core.ErrLockUnavailable, core.ErrServerToolMissing),
	fmt.Errorf("%w", core.ErrWriteUnknown),
	fmt.Errorf("%w %w", core.ErrWritePartial, core.ErrWriteUnknown),
	fmt.Errorf("%w", core.ErrRollbackForeign),
}
