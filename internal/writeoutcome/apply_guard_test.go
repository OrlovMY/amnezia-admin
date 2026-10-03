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
//	casWrite(apply): docker без sudo
//	                 отказан, sudo тоже → SudoDenied, Retry=false (TestApplySudoDeniedClassified)
//	casWrite(apply): 6               → Partial
//	casWrite(apply): иное / нет кода → Unknown
//	casWrite(apply): CASWriteCommand → NotStarted     (недостижим: контейнер и
//	                 отверг аргументы                   каталог плана уже прошли
//	                                                    проверку при чтении; тот же
//	                                                    сентинел, проверен в core)
//	restore: откат 3                 → RollbackForeign
//	restore: откат 4 / 5,127 / 66 /
//	         sudo отказал            → RollbackNotDone
//	restore: откат иное / 6          → RollbackUnknown
//	restore: откат прошёл, проверено → RolledBack
//	restore: откат прошёл, не
//	         применено / не прочитано→ RolledBackNotApplied

import (
	"errors"
	"strings"
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
			ct := &core.Container{Name: "amnezia-awg", Dir: "/opt/amnezia/awg", Proto: "AmneziaWG", Support: core.SupportYes}
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
	// Проверка после отката — ТАБЛИЦА 3×3 (раунд 6, AU-LOGIC Н-5): файлы
	// (совпали / не совпали / не прочитаны) × работающий сервер (совпал / не
	// совпал / не прочитан). Каждая клетка — боевым путём через fakesrv.
	// Сторож: клеток ровно 9, пропуск — красный. Проверяются исход И
	// отсутствие ложных утверждений: «перезапуст…» — только в клетке
	// (совпали, не совпал); «файлы восстановлены»/«возвращены к прежнему» —
	// только где файлы совпали; «проверено» — только в (совпали, совпал).
	syncFail := func(s *fakesrv.Server) { s.FailSyncconf = errors.New("имитированный отказ syncconf") }
	rtDiffer := func(s *fakesrv.Server) {
		s.FailReadTimes = map[string]int{"/opt/amnezia/awg/wg0.conf": 1} // проверка после записи
		s.FailSyncconfFrom = 2                                           // повторный syncconf при откате
	}
	filesDiffer := func(s *fakesrv.Server) {
		s.ForeignWriteAfter = map[int]map[string][]byte{2: {"/opt/amnezia/awg/clientsTable": []byte("[]")}}
	}
	filesUnknown := func(s *fakesrv.Server) {
		s.FailRead = map[string]error{"/opt/amnezia/awg/wg0.conf": errors.New("имитированный отказ чтения")}
	}
	rtUnknown := func(s *fakesrv.Server) { s.FailWgShowFrom = 1 }
	all := func(fs ...func(*fakesrv.Server)) func(*fakesrv.Server) {
		return func(s *fakesrv.Server) {
			for _, f := range fs {
				f(s)
			}
		}
	}
	type cell struct{ files, runtime string }
	grid := map[cell]struct {
		prep func(*fakesrv.Server)
		want writeoutcome.Kind
	}{
		{"совпали", "совпал"}:        {syncFail, writeoutcome.RolledBack},
		{"совпали", "не совпал"}:     {rtDiffer, writeoutcome.RolledBackNotApplied},
		{"совпали", "неизвестно"}:    {all(syncFail, rtUnknown), writeoutcome.RollbackUnverified},
		{"не совпали", "совпал"}:     {all(syncFail, filesDiffer), writeoutcome.RolledBackFilesDiffer},
		{"не совпали", "не совпал"}:  {all(rtDiffer, filesDiffer), writeoutcome.RolledBackFilesDiffer}, // проба аудитора Н-5
		{"не совпали", "неизвестно"}: {all(syncFail, filesDiffer, rtUnknown), writeoutcome.RolledBackFilesDiffer},
		{"неизвестно", "совпал"}:     {all(syncFail, filesUnknown), writeoutcome.RollbackUnverified},
		{"неизвестно", "не совпал"}:  {all(filesUnknown, func(s *fakesrv.Server) { s.FailSyncconfFrom = 2 }), writeoutcome.RollbackUnverified},
		{"неизвестно", "неизвестно"}: {all(syncFail, filesUnknown, rtUnknown), writeoutcome.RollbackUnverified},
	}
	if len(grid) != 9 {
		t.Fatalf("клеток таблицы отката %d, должно быть ровно 9", len(grid))
	}
	for _, f := range []string{"совпали", "не совпали", "неизвестно"} {
		for _, r := range []string{"совпал", "не совпал", "неизвестно"} {
			if _, ok := grid[cell{f, r}]; !ok {
				t.Errorf("клетка (файлы %s, сервер %s) не проверена", f, r)
			}
		}
	}
	for c, g := range grid {
		t.Run("файлы "+c.files+", сервер "+c.runtime, func(t *testing.T) {
			srv := fakesrv.New()
			sess := core.NewSessionWithRunner(srv, &core.ServerCreds{Host: "203.0.113.10", User: "root", Password: "x"})
			ct := &core.Container{Name: "amnezia-awg", Dir: "/opt/amnezia/awg", Proto: "AmneziaWG", Support: core.SupportYes}
			plan, err := sess.PlanAddUser(ct, "Mallory")
			if err != nil {
				t.Fatalf("PlanAddUser: %v", err)
			}
			g.prep(srv)
			_, err = sess.Apply(plan)
			if got := writeoutcome.Classify(err); got != g.want {
				t.Fatalf("исход %d, ожидался %d: %v", got, g.want, err)
			}
			tx, _ := writeoutcome.Describe(err)
			text := strings.ToLower(tx.Title + " " + writeoutcome.Message(tx, err))
			if strings.Contains(text, "перезапуст") != (c == cell{"совпали", "не совпал"}) {
				t.Errorf("«перезапуск» сказан не в той клетке: %s", text)
			}
			if c.files != "совпали" {
				for _, bad := range []string{"файлы восстановлены", "возвращены к прежнему", "состояние восстановлено"} {
					if strings.Contains(text, bad) {
						t.Errorf("файлы не проверены как прежние, а сказано %q: %s", bad, text)
					}
				}
			}
			if (c != cell{"совпали", "совпал"}) && strings.Contains(text, "восстановлено и проверено") {
				t.Errorf("«проверено» при непроверенном: %s", text)
			}
		})
	}
}

// TestApplySudoDeniedClassified — H1 (раунд 6 ядра), БОЕВЫМ путём: docker без
// sudo не пускает к сокету, повтор под sudo отказан самим sudo. На записи —
// SudoDenied («ничего не записано», повтор НЕ разрешён); на откате — откат не
// выполнен (RollbackNotDone), а не «неизвестно».
func TestApplySudoDeniedClassified(t *testing.T) {
	for _, c := range []struct {
		name     string
		denyFrom int // с какой по счёту команды записи (flock) отказывать
		syncFail bool
		want     writeoutcome.Kind
	}{
		{"запись: sudo отказал", 1, false, writeoutcome.SudoDenied},
		{"откат: sudo отказал", 2, true, writeoutcome.RollbackNotDone},
	} {
		t.Run(c.name, func(t *testing.T) {
			srv := fakesrv.New()
			r := &sudoDenyRunner{srv: srv, from: c.denyFrom}
			sess := core.NewSessionWithRunner(r, &core.ServerCreds{Host: "203.0.113.10", User: "u", Password: "x"})
			ct := &core.Container{Name: "amnezia-awg", Dir: "/opt/amnezia/awg", Proto: "AmneziaWG", Support: core.SupportYes}
			plan, err := sess.PlanAddUser(ct, "Mallory")
			if err != nil {
				t.Fatalf("PlanAddUser: %v", err)
			}
			if c.syncFail {
				srv.FailSyncconf = errors.New("имитированный отказ syncconf")
			}
			_, err = sess.Apply(plan)
			if err == nil {
				t.Fatal("Apply прошёл")
			}
			if got := writeoutcome.Classify(err); got != c.want {
				t.Errorf("исход %d, ожидался %d: %v", got, c.want, err)
			}
			if tx, _ := writeoutcome.Describe(err); tx.Retry {
				t.Errorf("повтор разрешён при отказе sudo: %+v", tx)
			}
			if r.sudoTried == 0 {
				t.Error("повтор под sudo не выполнялся — путь не доехал")
			}
		})
	}
}

// sudoDenyRunner — команды записи (flock) с номера from: без sudo — отказ
// сокета docker, с sudo — отказ sudo (его настоящий текст). Прочее — fakesrv.
type sudoDenyRunner struct {
	srv       *fakesrv.Server
	from, n   int
	sudoTried int
}

func (r *sudoDenyRunner) Run(cmd string, stdin []byte) (string, error) {
	if !strings.Contains(cmd, "flock") {
		return r.srv.Run(cmd, stdin)
	}
	if !strings.Contains(cmd, "sudo") {
		r.n++
	}
	if r.n < r.from {
		return r.srv.Run(cmd, stdin)
	}
	if strings.Contains(cmd, "sudo") {
		r.sudoTried++
		return "", exitErr{code: 1, msg: "exit status 1; stderr: sudo: a password is required"}
	}
	return "", exitErr{code: 1, msg: "exit status 1; stderr: permission denied while trying to connect to the Docker daemon socket at unix:///var/run/docker.sock"}
}

type exitErr struct {
	code int
	msg  string
}

func (e exitErr) Error() string   { return e.msg }
func (e exitErr) ExitStatus() int { return e.code }
