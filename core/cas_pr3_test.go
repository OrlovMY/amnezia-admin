package core_test

// A3б PR-3: различимые исходы записи (сентинелы ErrLockUnavailable,
// ErrWritePartial), причина отказа mv при частичной записи, «занято» без
// утверждения, что замок держит наша копия. Боевой путь: Session.AddUser
// поверх fakesrv, скрипт записи — настоящий sh.

import (
	"errors"
	"strings"
	"testing"

	"amnezia-admin/core"
	"amnezia-admin/internal/fakesrv"
)

func pr3Session(srv *fakesrv.Server) *core.Session {
	return core.NewSessionWithRunner(srv, &core.ServerCreds{Host: "203.0.113.10", User: "root", Password: "x"})
}

func pr3Container() *core.Container {
	return &core.Container{Name: "amnezia-awg", Dir: "/opt/amnezia/awg", Proto: "AmneziaWG", Managed: true}
}

// TestPR3OutcomeSentinels — ТЕСТ РАЗЛИЧЕНИЯ и ДОЕЗДА по сентинелам: каждый
// исход записи распознаётся своим сентинелом, частные — И общим, и не
// распознаётся чужими.
func TestPR3OutcomeSentinels(t *testing.T) {
	all := []error{core.ErrCASMismatch, core.ErrServerBusy, core.ErrServerToolMissing, core.ErrLockUnavailable,
		core.ErrWriteUnknown, core.ErrWritePartial}
	cases := []struct {
		name string
		prep func(*fakesrv.Server)
		is   []error
	}{
		{"занято", func(s *fakesrv.Server) { s.LockBusy = true }, []error{core.ErrServerBusy}},
		{"нет утилиты", func(s *fakesrv.Server) { s.MissingTool = "base64" }, []error{core.ErrServerToolMissing}},
		{"замок не открыт (66)", func(s *fakesrv.Server) { s.WriteFault = map[int]fakesrv.WriteFault{1: {Code: 66}} },
			[]error{core.ErrLockUnavailable, core.ErrServerToolMissing}},
		{"неизвестно (124)", func(s *fakesrv.Server) { s.WriteFault = map[int]fakesrv.WriteFault{1: {Code: 124}} },
			[]error{core.ErrWriteUnknown}},
		{"частично (mv clientsTable)", func(s *fakesrv.Server) { s.FailMvTo = "clientsTable" },
			[]error{core.ErrWritePartial, core.ErrWriteUnknown}},
		{"изменён другим", func(s *fakesrv.Server) {
			s.ForeignWrite = map[int]map[string][]byte{1: {"/opt/amnezia/awg/clientsTable": []byte("[]")}}
		}, []error{core.ErrCASMismatch}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv := fakesrv.New()
			c.prep(srv)
			_, err := pr3Session(srv).AddUser(pr3Container(), "Mallory")
			if err == nil {
				t.Fatal("запись прошла, ожидался исход записи")
			}
			for _, s := range all {
				want := false
				for _, w := range c.is {
					want = want || w == s
				}
				if got := errors.Is(err, s); got != want {
					t.Errorf("errors.Is(%v) = %v, ожидалось %v; ошибка: %v", s, got, want, err)
				}
			}
		})
	}
}

// TestPR3PartialNamesReason — замечание QA: причина частичной записи (отказ
// mv на clientsTable) видна человеку; повтор под sudo при этом НЕ делается
// (SEC F1: строка «not moved:» — признак начатой записи, хотя в ней есть
// «Permission denied»). Прежде stderr mv глушился («2>/dev/null»).
func TestPR3PartialNamesReason(t *testing.T) {
	srv := fakesrv.New()
	srv.FailMvTo = "clientsTable"
	_, err := pr3Session(srv).AddUser(pr3Container(), "Mallory")
	if !errors.Is(err, core.ErrWritePartial) {
		t.Fatalf("ожидалось «записано частично», получено %v", err)
	}
	if msg := err.Error(); !strings.Contains(msg, "not moved: clientsTable:") || !strings.Contains(msg, "Permission denied") {
		t.Errorf("причина отказа mv не названа: %s", msg)
	}
	for _, c := range srv.Commands() {
		if strings.HasPrefix(c, "sudo ") {
			t.Errorf("после начатой записи повтор под sudo: %.80s…", c)
		}
	}
	if len(srv.Violations) != 0 {
		t.Errorf("нарушения протокола: %v", srv.Violations)
	}
}

// TestPR3BusyDoesNotBlameOurCopy — Low аудита PR-1: замок /run/lock/ может
// держать и посторонняя программа; текст не утверждает, что это наша копия.
func TestPR3BusyDoesNotBlameOurCopy(t *testing.T) {
	srv := fakesrv.New()
	srv.LockBusy = true
	_, err := pr3Session(srv).AddUser(pr3Container(), "Mallory")
	msg := err.Error()
	if strings.Contains(msg, "сервер занят другой копией программы") {
		t.Errorf("текст утверждает, что замок держит наша копия: %s", msg)
	}
	if !strings.Contains(msg, core.CASLockDir) || !strings.Contains(msg, "возможно, другая копия программы") {
		t.Errorf("текст не называет замок и возможного держателя: %s", msg)
	}
}
