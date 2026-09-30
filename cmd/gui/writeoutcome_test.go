package main

// A3б PR-3: исходы записи в GUI — ДОЕЗД через настоящее окно «Изменения
// перед применением»: настоящий план над fakesrv, нажатие «Применить»,
// настоящий sess.Apply. Проверяется: строка статуса окна, доступность
// «Применить» (повтор — только где ничего не записано и план не устарел) и
// заголовок диалога исхода. GUI не запускается — тестовый драйвер Fyne.

import (
	"errors"
	"strings"
	"testing"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/test"
	"fyne.io/fyne/v2/widget"

	"amnezia-admin/core"
	"amnezia-admin/internal/fakesrv"
	"amnezia-admin/internal/guiview"
	"amnezia-admin/internal/writeoutcome"
)

type pr3Case struct {
	name string
	prep func(*fakesrv.Server)
	kind writeoutcome.Kind
}

var pr3Cases = []pr3Case{
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
	// Раунд 4 (AU-LOGIC Н-1): откат не начался («занято») и итог отката
	// неизвестен (124) — прежде безликая ошибка и снова включённая «Применить».
	{"откат не выполнен (занято)", func(s *fakesrv.Server) {
		s.FailSyncconf = errors.New("имитированный отказ syncconf")
		s.WriteFault = map[int]fakesrv.WriteFault{2: {Code: 4}}
	}, writeoutcome.RollbackNotDone},
	{"итог отката неизвестен (124)", func(s *fakesrv.Server) {
		s.FailSyncconf = errors.New("имитированный отказ syncconf")
		s.WriteFault = map[int]fakesrv.WriteFault{2: {Code: 124}}
	}, writeoutcome.RollbackUnknown},
	// Раунд 5: исходы проверки после отката и «не удалось подготовить».
	{"отменено и проверено", func(s *fakesrv.Server) {
		s.FailSyncconf = errors.New("имитированный отказ syncconf")
	}, writeoutcome.RolledBack},
	{"отменено не до конца", func(s *fakesrv.Server) {
		s.FailReadTimes = map[string]int{"/opt/amnezia/awg/wg0.conf": 1}
		s.FailSyncconfFrom = 2
	}, writeoutcome.RolledBackNotApplied},
	{"итог отмены не проверен", func(s *fakesrv.Server) {
		s.FailRead = map[string]error{"/opt/amnezia/awg/wg0.conf": errors.New("имитированный отказ чтения")}
	}, writeoutcome.RollbackUnverified},
	{"файлы после отмены не совпали", func(s *fakesrv.Server) {
		s.FailSyncconf = errors.New("имитированный отказ syncconf")
		s.ForeignWriteAfter = map[int]map[string][]byte{2: {"/opt/amnezia/awg/clientsTable": []byte("[]")}}
	}, writeoutcome.RolledBackFilesDiffer},
	{"не удалось подготовить запись", func(s *fakesrv.Server) {
		s.FailBackup = errors.New("имитированный отказ резервной копии")
	}, writeoutcome.NotStarted},
}

// pr3DiffWindow — окно изменений плана добавления над fakesrv с хуком prep;
// предупреждение (решение владельца) в этом запуске уже показано.
func pr3DiffWindow(t *testing.T, prep func(*fakesrv.Server)) (*ui, *widget.Button) {
	t.Helper()
	u := focusTestUI(t)
	osmotrMain(u)
	srv := fakesrv.New()
	u.sess = core.NewSessionWithRunner(srv, &core.ServerCreds{Host: "203.0.113.10", User: "root", Password: "x"})
	u.warnSess = guiview.AfterWarned(u.warnServerID())
	u.win.Resize(fyne.NewSize(1229, 620))
	plan, err := u.sess.PlanAddUser(pr3Container(), "Mallory")
	if err != nil {
		t.Fatalf("PlanAddUser: %v", err)
	}
	// хуки — после построения плана: они про запись, а не про чтение плана
	if prep != nil {
		prep(srv)
	}
	u.showDiffWindow(`добавление "Mallory"`, plan, func(*core.NewUser) {})
	t.Cleanup(func() { waitGUIGoroutines(t) })
	return u, buttonByText(t, topPopup(t, u.win.Canvas()), "Применить")
}

func pr3Container() *core.Container {
	return &core.Container{Name: "amnezia-awg", Dir: "/opt/amnezia/awg", Proto: "AmneziaWG", Managed: true}
}

// TestPR3GUIApplyOutcomes — ДОЕЗД и РАЗЛИЧЕНИЕ по всем семи исходам.
func TestPR3GUIApplyOutcomes(t *testing.T) {
	for _, c := range pr3Cases {
		t.Run(c.name, func(t *testing.T) {
			u, apply := pr3DiffWindow(t, c.prep)
			diff := topPopup(t, u.win.Canvas())
			test.Tap(apply)
			waitGUIGoroutines(t)
			want, _ := writeoutcome.Describe(pr3KindErr(c.kind))
			status := strings.Join(visibleTexts(diff), " | ")
			if !strings.Contains(status, guiview.ApplyStatus(want)) {
				t.Errorf("в окне изменений нет строки статуса исхода %q:\n%s", guiview.ApplyStatus(want), status)
			}
			// Ожидание — СВОЁ, не из таблицы writeoutcome (выборка немоты): иначе
			// подмена Retry в таблице меняла бы и ожидание, и тест молчал.
			// Повтор того же плана — только где точно ничего не записано и
			// план не устарел.
			retry := c.kind == writeoutcome.Busy || c.kind == writeoutcome.ToolMissing || c.kind == writeoutcome.LockUnavailable || c.kind == writeoutcome.NotStarted
			if apply.Disabled() == retry {
				t.Errorf("«Применить»: выключена=%v, а повтор допустим=%v", apply.Disabled(), retry)
			}
			top := strings.Join(visibleTexts(u.win.Canvas().Overlays().Top()), " | ")
			if !strings.Contains(top, want.Title) || !strings.Contains(top, want.Next) {
				t.Errorf("диалог исхода не показан или не тот:\n%s", top)
			}
			for _, o := range pr3Cases {
				if o.kind == c.kind {
					continue
				}
				other, _ := writeoutcome.Describe(pr3KindErr(o.kind))
				if other.Title == want.Title {
					continue // общий заголовок по решению UX-01 (раунд 5); причина — в «что случилось»
				}
				if strings.Contains(top+status, other.Title) {
					t.Errorf("показан чужой исход %q", other.Title)
				}
			}
		})
	}
}

func pr3KindErr(k writeoutcome.Kind) error {
	for _, e := range []error{
		core.ErrCASMismatch, core.ErrServerBusy, core.ErrServerToolMissing,
		errors.Join(core.ErrLockUnavailable, core.ErrServerToolMissing),
		core.ErrWriteUnknown, errors.Join(core.ErrWritePartial, core.ErrWriteUnknown), core.ErrRollbackForeign,
		errors.Join(core.ErrRollbackNotDone, core.ErrServerBusy), errors.Join(core.ErrRollbackUnknown, core.ErrWriteUnknown),
		core.ErrRolledBack, core.ErrRolledBackNotApplied, core.ErrRollbackUnverified, core.ErrRolledBackFilesDiffer, core.ErrWriteNotStarted,
	} {
		if writeoutcome.Classify(e) == k {
			return e
		}
	}
	return errors.New("нет образца")
}
