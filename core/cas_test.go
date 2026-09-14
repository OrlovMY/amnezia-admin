package core

// Тест CAS (Г4, ядро: fail-safe) — в отдельном файле, чтобы коммит CAS был
// изолирован и от него самого, и от общего файла тестов транзакции.

import (
	"bytes"
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
