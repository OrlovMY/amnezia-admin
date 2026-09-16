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

// assertCASErrClean — review-reply PR-3 круг 2 (Medium): текст ошибки CAS не
// должен содержать сырой текст ErrCASMismatch.Error() (доказывает, что
// casError.Error() не печатает сентинел — раньше именно это дублировало и
// портило фразу) и, для веток "не удалось проверить" (сервер не менялся, а
// проверка не удалась), не должен содержать ложное "изменился с момента
// чтения" — эта фраза допустима только в ветках реального расхождения суммы.
func assertCASErrClean(t *testing.T, err error, allowChangedPhrase bool) {
	t.Helper()
	if err == nil {
		t.Fatal("assertCASErrClean: err == nil")
	}
	msg := err.Error()
	if strings.Contains(msg, ErrCASMismatch.Error()) {
		t.Errorf("текст ошибки содержит сырой текст сентинела ErrCASMismatch: %q", msg)
	}
	if !allowChangedPhrase && strings.Contains(msg, "изменился с момента чтения") {
		t.Errorf("текст ошибки ложно утверждает 'изменился с момента чтения', хотя сервер не менялся (просто не удалось проверить): %q", msg)
	}
}

// stubRunner подменяет ОДНУ команду (по подстроке match), остальные отдаёт
// base — нужен двум веткам CAS ниже (пустой ответ sha256sum, сбой test -f),
// для которых заводить именной хук в fakesrv ради одной строки избыточно.
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

// TestCASMismatchIsErrCASMismatch — review PR-2, carryover 1 (текст правлен
// по review-reply PR-3 круга 2, Medium): отказ CAS обязан распознаваться
// через errors.Is(err, ErrCASMismatch), а не только по подстроке текста
// (cmd/gui/main.go:isCASRefusal раньше делал именно так), и при этом сам
// текст ErrCASMismatch не должен попадать в сообщение (assertCASErrClean).
// Проверяем все пять веток отказа CAS (checkCAS: 2, casCheckFile: 3).
func TestCASMismatchIsErrCASMismatch(t *testing.T) {
	t.Run("casCheckFile: расхождение контрольной суммы (wg0.conf)", func(t *testing.T) {
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
		assertCASErrClean(t, err, true) // расхождение суммы — сервер реально изменился
		t.Logf("проба ревьюера, текст ошибки (расхождение суммы): %v", err)
	})

	t.Run("casCheckFile: sha256sum недоступен (NoSha256) — сервер не менялся, проверить не удалось", func(t *testing.T) {
		srv := fakesrv.New()
		srv.NoSha256 = true
		sess := NewSessionWithRunner(srv, testCreds())
		c := awgContainer()

		_, err := sess.AddUser(c, "Carol")
		if !errors.Is(err, ErrCASMismatch) {
			t.Errorf("errors.Is(err, ErrCASMismatch) = false, err: %v", err)
		}
		assertCASErrClean(t, err, false) // сервер НЕ менялся — "изменился" здесь ложь
		t.Logf("проба ревьюера, текст ошибки (NoSha256): %v", err)
	})

	t.Run("casCheckFile: пустой ответ sha256sum", func(t *testing.T) {
		base := fakesrv.New()
		c := awgContainer()
		r := stubRunner{base: base, match: "sha256sum"} // out="", err=nil — пустая строка без ошибки
		sess := NewSessionWithRunner(r, testCreds())

		plan, err := sess.PlanAddUser(c, "Carol")
		if err != nil {
			t.Fatalf("PlanAddUser: %v", err)
		}
		err = sess.checkCAS(c, plan) // белый ящик: проверяем шаг 1 напрямую, минуя Apply
		if !errors.Is(err, ErrCASMismatch) {
			t.Errorf("errors.Is(err, ErrCASMismatch) = false, err: %v", err)
		}
		assertCASErrClean(t, err, false) // сервер не менялся — просто пустой ответ
		if !strings.Contains(err.Error(), "пустой ответ sha256sum") {
			t.Errorf("текст ошибки не про пустой ответ: %v", err)
		}
		t.Logf("проба ревьюера, текст ошибки (пустой ответ sha256sum): %v", err)
	})

	t.Run("checkCAS: probeClientsTable вернул ошибку", func(t *testing.T) {
		base := fakesrv.New()
		c := awgContainer()
		base.DeleteFile(c.Dir + "/clientsTable")
		sess := NewSessionWithRunner(base, testCreds())

		plan, err := sess.PlanAddUser(c, "Carol")
		if err != nil {
			t.Fatalf("PlanAddUser: %v", err)
		}
		// Подмена runner'а ПОСЛЕ планирования (белый ящик, sess.r — то же
		// поле, что видит Apply): test -f при планировании уже отработал
		// штатно (clientsTable отсутствовала — не ошибка), провалить нужно
		// только повторный test -f внутри checkCAS (шаг 1 Apply).
		boom := errors.New("сбой сети")
		sess.r = stubRunner{base: base, match: "test -f", err: boom}
		err = sess.checkCAS(c, plan)
		if !errors.Is(err, ErrCASMismatch) {
			t.Errorf("errors.Is(err, ErrCASMismatch) = false, err: %v", err)
		}
		assertCASErrClean(t, err, false) // не удалось ПРОВЕРИТЬ — не факт, что сервер менялся
		if !errors.Is(err, boom) {
			t.Errorf("errors.Is(err, boom) = false — причина (сбой сети) должна быть в цепочке: %v", err)
		}
		t.Logf("проба ревьюера, текст ошибки (probeClientsTable сбой): %v", err)
	})

	t.Run("checkCAS: clientsTable появилась, хотя при планировании отсутствовала", func(t *testing.T) {
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
		assertCASErrClean(t, err, true) // файл реально появился — "изменился" здесь правда
		t.Logf("проба ревьюера, текст ошибки (clientsTable появилась): %v", err)
	})
}
