package core

// Тест CAS (Г4, ядро: fail-safe) — в отдельном файле, чтобы коммит CAS был
// изолирован и от него самого, и от общего файла тестов транзакции.

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"amnezia-admin/internal/fakesrv"
)

// TestCASMismatchRefuses — Г4: расхождение sha256sum или его недоступность
// на сервере — отказ ДО любой записи (fail-safe).
func TestCASMismatchRefuses(t *testing.T) {
	t.Run("clientsTable изменилась между планом и применением", func(t *testing.T) {
		srv := fakesrv.New()
		sess := NewSessionWithRunner(srv, testCreds())
		c := awgContainer()

		plan, err := sess.PlanAddUser(c, "Carol")
		if err != nil {
			t.Fatalf("PlanAddUser: %v", err)
		}

		tbl, ok := srv.File(c.Dir + "/clientsTable")
		if !ok {
			t.Fatal("clientsTable отсутствует")
		}
		srv.SetFile(c.Dir+"/clientsTable", append(append([]byte{}, tbl...), ' '))

		before := len(srv.Commands())
		if _, err := sess.Apply(plan); err == nil {
			t.Fatal("Apply: ожидался отказ по CAS")
		} else if !strings.Contains(err.Error(), "изменился с момента чтения") {
			t.Errorf("текст ошибки не про CAS: %v", err)
		}

		sawSha256 := false
		for _, cmd := range srv.Commands()[before:] {
			if strings.Contains(cmd, "sha256sum") {
				sawSha256 = true
				continue
			}
			if strings.Contains(cmd, "cat > ") {
				t.Fatalf("после sha256sum не должно быть записи, но: %q", cmd)
			}
			if strings.Contains(cmd, "mkdir -p") {
				t.Fatalf("CAS-отказ не должен был вызвать backup (CAS — шаг 1, backup — шаг 2, позже), но: %q", cmd)
			}
		}
		if !sawSha256 {
			t.Fatal("не увидели ни одной команды sha256sum")
		}
	})

	t.Run("NoSha256 — на сервере нет sha256sum", func(t *testing.T) {
		srv := fakesrv.New()
		srv.NoSha256 = true
		sess := NewSessionWithRunner(srv, testCreds())
		c := awgContainer()

		beforeWG, _ := srv.File(c.Dir + "/wg0.conf")
		beforeTbl, _ := srv.File(c.Dir + "/clientsTable")

		if _, err := sess.AddUser(c, "Carol"); err == nil {
			t.Fatal("AddUser: ожидался отказ (sha256sum недоступен)")
		} else if !strings.Contains(err.Error(), "не удалось проверить контрольную сумму") {
			t.Errorf("текст ошибки не про недоступность CAS: %v", err)
		}

		afterWG, _ := srv.File(c.Dir + "/wg0.conf")
		afterTbl, _ := srv.File(c.Dir + "/clientsTable")
		if !bytes.Equal(afterWG, beforeWG) || !bytes.Equal(afterTbl, beforeTbl) {
			t.Error("NoSha256 не должен был ничего записать")
		}
		for _, cmd := range srv.Commands() {
			if strings.Contains(cmd, "cat > ") {
				t.Fatalf("NoSha256: обнаружена запись: %q", cmd)
			}
			if strings.Contains(cmd, "mkdir -p") {
				t.Fatalf("NoSha256: backup не должен был вызываться (CAS — до backup, шаг 1 раньше шага 2), но: %q", cmd)
			}
		}
	})
}

// TestCASMismatchIsErrCASMismatch — review PR-2, carryover 1: отказ CAS
// обязан распознаваться через errors.Is(err, ErrCASMismatch), а не только по
// подстроке текста (cmd/gui/main.go:isCASRefusal раньше делал именно так).
// Проверяем оба пути отказа casCheckFile — расхождение суммы и NoSha256 —
// и путь checkCAS для отсутствовавшей при планировании clientsTable.
func TestCASMismatchIsErrCASMismatch(t *testing.T) {
	t.Run("расхождение контрольной суммы", func(t *testing.T) {
		srv := fakesrv.New()
		sess := NewSessionWithRunner(srv, testCreds())
		c := awgContainer()

		plan, err := sess.PlanAddUser(c, "Carol")
		if err != nil {
			t.Fatalf("PlanAddUser: %v", err)
		}
		tbl, _ := srv.File(c.Dir + "/clientsTable")
		srv.SetFile(c.Dir+"/clientsTable", append(append([]byte{}, tbl...), ' '))

		_, err = sess.Apply(plan)
		if !errors.Is(err, ErrCASMismatch) {
			t.Errorf("errors.Is(err, ErrCASMismatch) = false, err: %v", err)
		}
	})

	t.Run("NoSha256", func(t *testing.T) {
		srv := fakesrv.New()
		srv.NoSha256 = true
		sess := NewSessionWithRunner(srv, testCreds())
		c := awgContainer()

		_, err := sess.AddUser(c, "Carol")
		if !errors.Is(err, ErrCASMismatch) {
			t.Errorf("errors.Is(err, ErrCASMismatch) = false, err: %v", err)
		}
	})

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

		_, err = sess.Apply(plan)
		if !errors.Is(err, ErrCASMismatch) {
			t.Errorf("errors.Is(err, ErrCASMismatch) = false, err: %v", err)
		}
	})
}
