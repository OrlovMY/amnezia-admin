package writeoutcome_test

// Сторож A3б PR-3, раунд 4 (AU-LOGIC Н-1/Н-2): КАЖДАЯ ошибка, которую может
// вернуть Session.Apply, классифицируется writeoutcome — не как «прочее».
// Иначе интерфейс не знает, записано ли, и повтор/текст решает умолчание.
// Таблица — все return пути Apply (applyLocked, casWrite, restore), каждый
// доведён БОЕВЫМ путём через fakesrv (хуки сервера, настоящий скрипт записи
// в sh). Единственный return, который боевым путём недостижим, назван ниже.
//
// Пути Apply → исход (соответствие строкам таблицы):
//
//	applyLocked: backup              → NotStarted     («резервная копия»)
//	casWrite(apply): 3               → Changed
//	casWrite(apply): 4               → Busy
//	casWrite(apply): 5, 127          → ToolMissing
//	casWrite(apply): 66              → LockUnavailable
//	casWrite(apply): 6               → Partial
//	casWrite(apply): иное / нет кода → Unknown
//	casWrite(apply): CASWriteCommand → NotStarted     (недостижим: контейнер и
//	                 отверг аргументы                   каталог плана уже прошли
//	                                                    проверку при чтении; тот же
//	                                                    сентинел, проверен в core)
//	restore: откат 3                 → RollbackForeign
//	restore: откат 4 / 5,127 / 66    → RollbackNotDone
//	restore: откат иное / 6          → RollbackUnknown
//	restore: откат прошёл, проверено → RolledBack
//	restore: откат прошёл, не
//	         применено / не прочитано→ RolledBackNotApplied

import (
	"errors"
	"testing"

	"amnezia-admin/core"
	"amnezia-admin/internal/fakesrv"
	"amnezia-admin/internal/writeoutcome"
)

func TestApplyErrorsClassified(t *testing.T) {
	syncErr := errors.New("имитированный отказ syncconf")
	cases := []struct {
		name string
		prep func(*fakesrv.Server)
		want writeoutcome.Kind
	}{
		{"резервная копия", func(s *fakesrv.Server) { s.FailBackup = errors.New("имитированный отказ backup") }, writeoutcome.NotStarted},
		{"изменён другим", func(s *fakesrv.Server) {
			s.ForeignWrite = map[int]map[string][]byte{1: {"/opt/amnezia/awg/clientsTable": []byte("[]")}}
		}, writeoutcome.Changed},
		{"занято", func(s *fakesrv.Server) { s.LockBusy = true }, writeoutcome.Busy},
		{"нет утилиты на хосте (127)", func(s *fakesrv.Server) { s.MissingTool = "flock" }, writeoutcome.ToolMissing},
		{"нет утилиты в контейнере (5)", func(s *fakesrv.Server) { s.MissingTool = "base64" }, writeoutcome.ToolMissing},
		{"замок (66)", func(s *fakesrv.Server) { s.WriteFault = map[int]fakesrv.WriteFault{1: {Code: 66}} }, writeoutcome.LockUnavailable},
		{"частично (6)", func(s *fakesrv.Server) { s.FailMvTo = "clientsTable" }, writeoutcome.Partial},
		{"неизвестно (124)", func(s *fakesrv.Server) { s.WriteFault = map[int]fakesrv.WriteFault{1: {Code: 124}} }, writeoutcome.Unknown},
		{"неизвестно (sha256sum упал, 1)", func(s *fakesrv.Server) { s.FailTool = "sha256sum" }, writeoutcome.Unknown},
		{"откат: чужое", func(s *fakesrv.Server) {
			s.FailSyncconf = syncErr
			s.ForeignWrite = map[int]map[string][]byte{2: {"/opt/amnezia/awg/clientsTable": []byte("[]")}}
		}, writeoutcome.RollbackForeign},
		{"откат: занято", func(s *fakesrv.Server) {
			s.FailSyncconf = syncErr
			s.WriteFault = map[int]fakesrv.WriteFault{2: {Code: 4}}
		}, writeoutcome.RollbackNotDone},
		{"откат: нет утилиты", func(s *fakesrv.Server) {
			s.FailSyncconf = syncErr
			s.WriteFault = map[int]fakesrv.WriteFault{2: {Code: 5}}
		}, writeoutcome.RollbackNotDone},
		{"откат: замок", func(s *fakesrv.Server) {
			s.FailSyncconf = syncErr
			s.WriteFault = map[int]fakesrv.WriteFault{2: {Code: 66}}
		}, writeoutcome.RollbackNotDone},
		{"откат: неизвестно (124)", func(s *fakesrv.Server) {
			s.FailSyncconf = syncErr
			s.WriteFault = map[int]fakesrv.WriteFault{2: {Code: 124}}
		}, writeoutcome.RollbackUnknown},
		{"откат: частично (6)", func(s *fakesrv.Server) {
			s.FailSyncconf = syncErr
			s.WriteFault = map[int]fakesrv.WriteFault{2: {Code: 6}}
		}, writeoutcome.RollbackUnknown},
		{"откат прошёл и проверен", func(s *fakesrv.Server) { s.FailSyncconf = syncErr }, writeoutcome.RolledBack},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv := fakesrv.New()
			sess := core.NewSessionWithRunner(srv, &core.ServerCreds{Host: "203.0.113.10", User: "root", Password: "x"})
			ct := &core.Container{Name: "amnezia-awg", Dir: "/opt/amnezia/awg", Proto: "AmneziaWG", Managed: true}
			plan, err := sess.PlanAddUser(ct, "Mallory")
			if err != nil {
				t.Fatalf("PlanAddUser: %v", err)
			}
			c.prep(srv)
			_, err = sess.Apply(plan)
			if err == nil {
				t.Fatal("проверка ПЕРЕСТАЛА ЧТО-ЛИБО ЗНАЧИТЬ: Apply прошёл")
			}
			got := writeoutcome.Classify(err)
			if got == writeoutcome.Other {
				t.Fatalf("ошибка Apply не классифицирована (прочее — повтор и текст решает умолчание): %v", err)
			}
			if got != c.want {
				t.Errorf("исход %d, ожидался %d: %v", got, c.want, err)
			}
		})
	}
	// Проверка после отката — три состояния (раунд 5, AU-LOGIC Н-4). Раньше
	// здесь стоял случай «прочитать нельзя» с ожиданием RolledBackNotApplied —
	// тест ЗАКРЕПЛЯЛ неверный исход: незнание выдавалось за измеренный отказ
	// работающего сервера.
	after := []struct {
		name string
		prep func(*fakesrv.Server)
		want writeoutcome.Kind
	}{
		// сценарий аудитора: только FailRead на wg0.conf — проверка после
		// записи и после отката не читает файл; рантайм при этом совпал.
		{"после отката не прочитать (сценарий аудитора)", func(s *fakesrv.Server) {
			s.FailRead = map[string]error{"/opt/amnezia/awg/wg0.conf": errors.New("имитированный отказ чтения")}
		}, writeoutcome.RollbackUnverified},
		// измеренный отказ рантайма: проверка после записи не прочитала файл
		// (один раз), повторный syncconf при откате упал — рантайм остался
		// новым, файлы после отката прочитаны и совпали.
		{"рантайм не вернулся", func(s *fakesrv.Server) {
			s.FailReadTimes = map[string]int{"/opt/amnezia/awg/wg0.conf": 1}
			s.FailSyncconfFrom = 2
		}, writeoutcome.RolledBackNotApplied},
		// измеренный отказ рантайма И не прочитать файлы: рантайм стоит
		// ВЫШЕ незнания о файлах — ошибка чтения его не перекрывает.
		{"рантайм не вернулся, файлы не прочитать", func(s *fakesrv.Server) {
			s.FailRead = map[string]error{"/opt/amnezia/awg/wg0.conf": errors.New("имитированный отказ чтения")}
			s.FailSyncconfFrom = 2
		}, writeoutcome.RolledBackNotApplied},
		// файлы после отката прочитаны, но не совпали с прежними.
		{"файлы после отката не совпали", func(s *fakesrv.Server) {
			s.FailSyncconf = errors.New("имитированный отказ syncconf")
			s.ForeignWriteAfter = map[int]map[string][]byte{2: {"/opt/amnezia/awg/clientsTable": []byte("[]")}}
		}, writeoutcome.RolledBackFilesDiffer},
	}
	for _, c := range after {
		t.Run(c.name, func(t *testing.T) {
			srv := fakesrv.New()
			sess := core.NewSessionWithRunner(srv, &core.ServerCreds{Host: "203.0.113.10", User: "root", Password: "x"})
			ct := &core.Container{Name: "amnezia-awg", Dir: "/opt/amnezia/awg", Proto: "AmneziaWG", Managed: true}
			plan, err := sess.PlanAddUser(ct, "Mallory")
			if err != nil {
				t.Fatalf("PlanAddUser: %v", err)
			}
			c.prep(srv)
			_, err = sess.Apply(plan)
			got := writeoutcome.Classify(err)
			if got != c.want {
				t.Fatalf("исход %d, ожидался %d: %v", got, c.want, err)
			}
		})
	}
}
