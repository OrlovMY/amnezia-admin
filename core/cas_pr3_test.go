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

// TestPR3WgMoveReasonNamed — раунд 4 (AU-LOGIC Н-3): отказ mv на wg0.conf
// (исход «неизвестно», код 1) называет причину в подробностях — поведенчески,
// через настоящий скрипт в sh, а не только дословной копией в T7.
func TestPR3WgMoveReasonNamed(t *testing.T) {
	srv := fakesrv.New()
	srv.FailMvTo = "wg0.conf"
	_, err := pr3Session(srv).AddUser(pr3Container(), "Mallory")
	if !errors.Is(err, core.ErrWriteUnknown) || errors.Is(err, core.ErrWritePartial) {
		t.Fatalf("ожидалось «неизвестно» (не «частично»), получено %v", err)
	}
	if msg := err.Error(); !strings.Contains(msg, "not moved: wg0.conf:") || !strings.Contains(msg, "Permission denied") {
		t.Errorf("причина отказа mv wg0.conf не названа: %s", msg)
	}
}

// TestPR3ReadFailAfterRollbackIsNotRuntime — раунд 5 (AU-LOGIC Н-4),
// сценарий аудитора, ДОЕЗД: только FailRead на wg0.conf, затем Apply.
// Проверка после записи не читает файл → откат → проверка после отката тоже
// не читает. Рантайм при этом совпал с прежним. Исход — «итог отката не
// проверен», НЕ «работающий сервер не принял» и без «применить их не
// удалось». Пользуется только API 1aabea5 (ErrRolledBackNotApplied там уже
// есть) — там падает поведением.
func TestPR3ReadFailAfterRollbackIsNotRuntime(t *testing.T) {
	srv := fakesrv.New()
	sess := pr3Session(srv)
	plan, err := sess.PlanAddUser(pr3Container(), "Mallory")
	if err != nil {
		t.Fatalf("PlanAddUser: %v", err)
	}
	srv.FailRead = map[string]error{"/opt/amnezia/awg/wg0.conf": errors.New("имитированный отказ чтения")}
	_, err = sess.Apply(plan)
	if err == nil {
		t.Fatal("проверка ПЕРЕСТАЛА ЧТО-ЛИБО ЗНАЧИТЬ: Apply прошёл")
	}
	if errors.Is(err, core.ErrRolledBackNotApplied) {
		t.Errorf("незнание (файл не прочитан) выдано за измеренный отказ работающего сервера: %v", err)
	}
	if strings.Contains(err.Error(), "применить их не удалось") {
		t.Errorf("в тексте утверждение, которого проверка не делала: %v", err)
	}
}

// TestPR3ForeignFilesNoRestartAdvice — раунд 6 (AU-LOGIC Н-5), проба
// аудитора, ДОЕЗД: проверка после записи не прочитала wg0.conf (один раз),
// повторный syncconf при откате упал (рантайм остался новым), и сразу после
// отката другой записал clientsTable. Файлы после отката НЕ прежние —
// совет «перезапустите» применил бы чужие файлы, «файлы восстановлены» —
// неправда. Только API a25d961 — там падает поведением (NotApplied).
func TestPR3ForeignFilesNoRestartAdvice(t *testing.T) {
	srv := fakesrv.New()
	sess := pr3Session(srv)
	plan, err := sess.PlanAddUser(pr3Container(), "Mallory")
	if err != nil {
		t.Fatalf("PlanAddUser: %v", err)
	}
	srv.FailReadTimes = map[string]int{"/opt/amnezia/awg/wg0.conf": 1}
	srv.FailSyncconfFrom = 2
	srv.ForeignWriteAfter = map[int]map[string][]byte{2: {"/opt/amnezia/awg/clientsTable": []byte("[]")}}
	_, err = sess.Apply(plan)
	if err == nil {
		t.Fatal("проверка ПЕРЕСТАЛА ЧТО-ЛИБО ЗНАЧИТЬ: Apply прошёл")
	}
	if errors.Is(err, core.ErrRolledBackNotApplied) {
		t.Errorf("файлы после отката чужие, а исход «сервер нужно перезапустить»: %v", err)
	}
	if msg := strings.ToLower(err.Error()); strings.Contains(msg, "файлы восстановлены") || strings.Contains(msg, "перезапуск") {
		t.Errorf("в тексте утверждение о файлах, которые не совпали с прежними: %v", err)
	}
}

// TestPR3RenameRollbackNoRuntimeClaim — раунд 7 (AU-LOGIC Н-6), проба
// аудитора, ДОЕЗД: переименование (wg0.conf не меняется, работающий сервер
// не трогается), проверка после записи не прочитала clientsTable (один раз),
// откат прошёл, файлы совпали. `wg show` при этом не работает — набор
// активных подключений не мерился. Текст не имеет права говорить, что он
// «проверен». Только API a66400a — там падает поведением.
func TestPR3RenameRollbackNoRuntimeClaim(t *testing.T) {
	srv := fakesrv.New()
	sess := pr3Session(srv)
	cl, err := sess.LoadClients(pr3Container())
	if err != nil || len(cl) == 0 {
		t.Fatalf("LoadClients: %v", err)
	}
	plan, err := sess.PlanRename(pr3Container(), cl[0].ClientID, "Переименованный")
	if err != nil {
		t.Fatalf("PlanRename: %v", err)
	}
	srv.FailReadTimes = map[string]int{"/opt/amnezia/awg/clientsTable": 1}
	srv.FailWgShowFrom = 1
	_, err = sess.Apply(plan)
	if !errors.Is(err, core.ErrRolledBack) {
		t.Fatalf("ожидался «отменено» (файлы проверены), получено: %v", err)
	}
	msg := err.Error()
	if strings.Contains(msg, "набор активных подключений на сервере.") || strings.Contains(msg, "состояние восстановлено и проверено") {
		t.Errorf("о подключениях сказано «проверено», хотя wg show не мерился: %v", err)
	}
	if !strings.Contains(msg, "не менялся и не проверялся") {
		t.Errorf("не сказано, что подключения не менялись и не проверялись: %v", err)
	}
}

// TestPR3RuntimeDifferWithoutSyncErr — раунд 7 (AU-LOGIC Н-7): ветка
// «рантайм не совпал» БЕЗ ошибки повторного syncconf. syncconf «проходит»,
// но выбрасывает постороннего peer'а (DropPeerOnSync) — при записи и при
// откате. Файлы после отката совпали, набор подключений измерен и не совпал:
// исход «сервер нужно перезапустить», не «неизвестно».
func TestPR3RuntimeDifferWithoutSyncErr(t *testing.T) {
	srv := fakesrv.New()
	sess := pr3Session(srv)
	cl, err := sess.LoadClients(pr3Container())
	if err != nil || len(cl) < 2 {
		t.Fatalf("LoadClients: %v", err)
	}
	plan, err := sess.PlanAddUser(pr3Container(), "Mallory")
	if err != nil {
		t.Fatalf("PlanAddUser: %v", err)
	}
	srv.DropPeerOnSync = cl[1].ClientID
	_, err = sess.Apply(plan)
	if !errors.Is(err, core.ErrRolledBackNotApplied) {
		t.Fatalf("ожидался измеренный отказ работающего сервера, получено: %v", err)
	}
	if strings.Contains(err.Error(), "повторный syncconf") {
		t.Errorf("syncconf не падал, а в тексте его ошибка: %v", err)
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
