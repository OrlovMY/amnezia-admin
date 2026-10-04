package core

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"amnezia-admin/internal/fakesrv"
)

// TestClassifyTable — AU-LOGIC р2 High-1, QA-01 р2 Н2: все сочетания. Ошибка
// отката, у которой откат «занят/нет утилиты/sudo», — НЕ «ничего не
// записано» (запись была). Подмены «неклассифицированная → восстановлен» и
// «любая → ничего не записано» роняют таблицу.
func TestClassifyTable(t *testing.T) {
	busy := &casWriteError{outcome: casBusy, msg: "занято"}
	tool := &casWriteError{outcome: casToolMissing, msg: "нет утилиты"}
	cases := []struct {
		name string
		err  error
		want RestoreState
	}{
		{"успех", nil, RestoreDone},
		{"откат выполнен", &restoreError{kind: ErrRolledBack, msg: "x"}, RestoreRolledBack},
		{"откат не выполнен, откат «занят»", &restoreError{kind: ErrRollbackNotDone, rollback: busy, msg: "x"}, RestoreUnknown},
		{"откат не выполнен, «нет утилиты»", &restoreError{kind: ErrRollbackNotDone, rollback: tool, msg: "x"}, RestoreUnknown},
		{"итог отката неизвестен", &restoreError{kind: ErrRollbackUnknown, msg: "x"}, RestoreUnknown},
		{"файлы вернулись, не применены", &restoreError{kind: ErrRolledBackNotApplied, msg: "x"}, RestoreUnknown},
		{"откат не проверен", &restoreError{kind: ErrRollbackUnverified, msg: "x"}, RestoreUnknown},
		{"откат стёр бы чужое", &rollbackForeignError{msg: "x"}, RestoreUnknown},
		{"частичная запись", &casWriteError{outcome: casPartial, msg: "x"}, RestoreUnknown},
		{"неизвестно, записано ли", &casWriteError{outcome: casUnknown, msg: "x"}, RestoreUnknown},
		{"занято до записи", busy, RestoreNotWritten},
		{"изменён другим", &casWriteError{outcome: casChanged, msg: "x"}, RestoreNotWritten},
		{"sudo отказал", &casWriteError{outcome: casSudoDenied, msg: "x"}, RestoreNotWritten},
		{"запись не начиналась", notStarted{errors.New("x")}, RestoreNotWritten},
		{"неопознанная", errors.New("что-то ещё"), RestoreUnknown},
	}
	for _, c := range cases {
		if got := classify(c.err); got != c.want {
			t.Errorf("%s: %v, ждали %v", c.name, got, c.want)
		}
	}
}

// TestRestoreOutcomesViaFakesrv — тест доезда: исходы возникают боевым
// путём через fakesrv.
func TestRestoreOutcomesViaFakesrv(t *testing.T) {
	cases := []struct {
		name  string
		setup func(s *fakesrv.Server)
		want  RestoreState
	}{
		{"mv clientsTable падает после замены конфигурации — частично", func(s *fakesrv.Server) { s.FailMvTo = "clientsTable" }, RestoreUnknown},
		{"обрыв после записи", func(s *fakesrv.Server) { s.WriteFault = map[int]fakesrv.WriteFault{1: {Code: 255, Written: true}} }, RestoreUnknown},
		{"замок занят", func(s *fakesrv.Server) { s.LockBusy = true }, RestoreNotWritten},
		{"изменён другим", func(s *fakesrv.Server) {
			s.ForeignWrite = map[int]map[string][]byte{1: {awgDir + "/clientsTable": []byte("[]")}}
		}, RestoreNotWritten},
		{"откат упёрся в занятый замок", func(s *fakesrv.Server) {
			s.SyncKeepsIface = true // проверка не пройдёт → откат
			s.WriteFault = map[int]fakesrv.WriteFault{2: {Code: 4}}
		}, RestoreUnknown},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			src, tgt := migrationPair(t)
			b := sourceBackup(t, src, "203.0.113.1")
			ts := NewSessionWithRunner(tgt, &ServerCreds{Host: "203.0.113.1"})
			rp := planFor(t, b, ts)
			c.setup(tgt)
			_, outs, err := ts.Restore(rp, restoreOpts(t))
			if err != nil {
				t.Fatal(err)
			}
			if outs[0].State != c.want {
				t.Errorf("исход %v (%v), ждали %v", outs[0].State, outs[0].Err, c.want)
			}
		})
	}
}

// TestRestoreOutcomeLinesChecked — AU-LOGIC р2 High-2: граница проверки — у
// каждого восстановленного, своя у WG и XRay; нет восстановленных — нет
// «проверено»; частичный перенос назван прямо.
func TestRestoreOutcomeLinesChecked(t *testing.T) {
	none := strings.Join(RestoreOutcomeLines("a", []RestoreOutcome{{Container: "amnezia-awg", State: RestoreNotWritten}}), "\n")
	if strings.Contains(none, "проверено") || strings.Contains(none, "файрвол") {
		t.Errorf("без восстановленных есть «проверено»:\n%s", none)
	}
	mixed := strings.Join(RestoreOutcomeLines("a", []RestoreOutcome{
		{Container: "amnezia-awg", State: RestoreDone, Checked: RestoreCheckedWG},
		{Container: "amnezia-xray", State: RestoreDeclined},
	}), "\n")
	for _, part := range []string{RestoreCheckedWG, "ПЕРЕНЕСЕНО ЧАСТИЧНО", "НЕ откатываются: amnezia-awg", "Не восстановлены: amnezia-xray"} {
		if !strings.Contains(mixed, part) {
			t.Errorf("нет «%s»:\n%s", part, mixed)
		}
	}
	if strings.Contains(mixed, RestoreCheckedXRay) {
		t.Error("граница XRay у невосстановленного XRay")
	}
	// боевой путь: XRay восстановлен — его граница
	src, tgt := fakesrv.NewXRay("master"), fakesrv.NewXRay("master")
	for _, s := range []*fakesrv.Server{src, tgt} {
		for _, k := range []string{"xray_short_id.key", "xray_public.key", "xray_private.key"} {
			s.SetFile("/opt/amnezia/xray/"+k, []byte(fakesrv.RandUUID()))
		}
	}
	b := sourceBackup(t, src, "203.0.113.1")
	ts := NewSessionWithRunner(tgt, &ServerCreds{Host: "203.0.113.1"})
	t.Cleanup(SetXRayWaits(0, 0))
	rp := planFor(t, b, ts)
	opt := restoreOpts(t)
	opt.ConfirmXRay = func() bool { return true }
	_, outs, _ := ts.Restore(rp, opt)
	if outs[0].State != RestoreDone || outs[0].Checked != RestoreCheckedXRay {
		t.Errorf("XRay: %v %q", outs[0].State, outs[0].Checked)
	}
}

// TestRestoreAutoCopyWriteFails — AU-LOGIC р2 Medium-1: автокопию не удалось
// записать → замена запрещена, ни одной записи.
func TestRestoreAutoCopyWriteFails(t *testing.T) {
	src, tgt := migrationPair(t)
	b := sourceBackup(t, src, "203.0.113.1")
	ts := NewSessionWithRunner(tgt, &ServerCreds{Host: "203.0.113.1"})
	rp := planFor(t, b, ts)
	opt := restoreOpts(t)
	notDir := filepath.Join(opt.AutoCopyDir, "файл")
	os.WriteFile(notDir, []byte("x"), 0o600)
	opt.AutoCopyDir = notDir // каталог — на самом деле файл
	if _, _, err := ts.Restore(rp, opt); !errors.Is(err, ErrRestoreStopped) || !strings.Contains(err.Error(), "не записана") {
		t.Fatalf("ждали «автокопия не записана — замена запрещена»: %v", err)
	}
	if writesOf(tgt) != 0 {
		t.Error("запись без автокопии")
	}
}

// TestRestoreKeyAbsentInCopyUntouched — QA-01 р2 R6: ключа нет в копии — он
// не входит в план записи, ключ нового сервера не меняется.
func TestRestoreKeyAbsentInCopyUntouched(t *testing.T) {
	src, tgt := migrationPair(t)
	src.DeleteFile(awgDir + "/" + keyPsk)
	b := sourceBackup(t, src, "203.0.113.1")
	ts := NewSessionWithRunner(tgt, &ServerCreds{Host: "203.0.113.1"})
	rp := planFor(t, b, ts)
	for _, x := range rp.Items[0].plan.extra {
		if x.name == keyPsk {
			t.Fatalf("ключ, которого нет в копии, попал в план: %+v", x.name)
		}
	}
	if _, outs, err := ts.Restore(rp, restoreOpts(t)); err != nil || outs[0].State != RestoreDone {
		t.Fatalf("%v %+v", err, outs)
	}
	if got, _ := tgt.File(awgDir + "/" + keyPsk); string(got) != "NEW-PSK\n" {
		t.Errorf("ключ нового сервера изменён: %q", got)
	}
}
