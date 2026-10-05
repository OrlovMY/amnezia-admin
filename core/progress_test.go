package core

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"amnezia-admin/internal/fakesrv"
)

// TestCollectProgressMonotone — X растёт по одному, Y известен с первого
// события, X == Y ровно в последнем событии чтения.
func TestCollectProgressMonotone(t *testing.T) {
	srv := fakesrv.New()
	srv.Names = append(srv.Names, "amnezia-openvpn") // «не входит» — в счёт не идёт
	var ev []Progress
	_, err := backupSession(t, srv).CollectBackupCtx(context.Background(), "t", backupNow, okResolver, func(p Progress) { ev = append(ev, p) })
	if err != nil {
		t.Fatal(err)
	}
	if len(ev) < 3 || ev[0].Done != 0 || ev[0].Total != 8 {
		t.Fatalf("первое событие: %+v (событий %d)", ev[0], len(ev))
	}
	for i := 1; i < len(ev); i++ {
		if ev[i].Done != ev[i-1].Done+1 || ev[i].Total != ev[0].Total {
			t.Fatalf("событие %d: %+v после %+v", i, ev[i], ev[i-1])
		}
		if ev[i].Done == ev[i].Total && i != len(ev)-1 {
			t.Fatalf("100%% до конца: событие %d из %d", i, len(ev))
		}
	}
	if last := ev[len(ev)-1]; last.Done != last.Total || !strings.Contains(last.Text, "проход 2 из 2") {
		t.Errorf("последнее: %+v", last)
	}
}

// TestCollectProgressRetryGrowsTotal — повторный снимок увеличивает Y,
// X не превышает Y и доходит до него только в конце.
func TestCollectProgressRetryGrowsTotal(t *testing.T) {
	m := &mutatingRunner{Server: fakesrv.New(), limit: 1}
	s := NewSessionWithRunner(m, &ServerCreds{Host: "203.0.113.1"})
	var ev []Progress
	if _, err := s.CollectBackupCtx(context.Background(), "t", backupNow, nil, func(p Progress) { ev = append(ev, p) }); err != nil {
		t.Fatal(err)
	}
	last := ev[len(ev)-1]
	if last.Total <= ev[0].Total || last.Done != last.Total {
		t.Fatalf("повтор: первое %+v, последнее %+v", ev[0], last)
	}
	for _, e := range ev[:len(ev)-1] {
		if e.Done >= e.Total && e.Done == last.Total {
			t.Fatalf("100%% до конца: %+v", e)
		}
	}
}

// cancelAt — отменить контекст на первом событии, где cond истинно.
func cancelAt(cond func(Progress) bool) (context.Context, ProgressFunc) {
	ctx, cancel := context.WithCancel(context.Background())
	return ctx, func(p Progress) {
		if cond(p) {
			cancel()
		}
	}
}

// TestBackupCancelEachStage — отмена на чтении, на шифровании (сработает
// сразу после него), на записи файла — файла нет, временных нет,
// ErrCanceled.
func TestBackupCancelEachStage(t *testing.T) {
	stages := map[string]func(Progress) bool{
		"чтение":     func(p Progress) bool { return p.Stage == StageRead && p.Done == 3 },
		"шифрование": func(p Progress) bool { return p.Stage == StageEncrypt },
		"запись":     func(p Progress) bool { return p.Stage == StageWrite },
	}
	for name, cond := range stages {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			p := filepath.Join(dir, "c.aabk")
			ctx, fn := cancelAt(cond)
			b, err := backupSession(t, fakesrv.New()).CollectBackupCtx(ctx, "t", backupNow, okResolver, fn)
			if err == nil {
				_, err = WriteBackupFileUniqueCtx(ctx, p, b, pwLayer(testPassword), fn)
			}
			if !errors.Is(err, ErrCanceled) {
				t.Fatalf("ждали отмену: %v", err)
			}
			if ents, _ := os.ReadDir(dir); len(ents) != 0 {
				t.Errorf("после отмены в каталоге: %v", ents)
			}
		})
	}
}

// TestRestoreCancel — отмена до записи (на чтении автокопии и сразу после
// записи автокопии) — 0 записей на сервер; событие «запись» несёт Writing,
// и отмена после него не действует — восстановление доходит до итога.
func TestRestoreCancel(t *testing.T) {
	for _, c := range []struct {
		name string
		cond func(Progress) bool
	}{
		{"чтение автокопии", func(p Progress) bool { return p.Stage == StageAutoCopy && p.Done == 2 }},
		{"на записи автокопии", func(p Progress) bool { return p.Stage == StageWrite }},
		{"после сохранения автокопии", func(p Progress) bool { return strings.Contains(p.Text, "автокопия нового сервера сохранена") }},
	} {
		t.Run(c.name, func(t *testing.T) {
			src, tgt := migrationPair(t)
			b := sourceBackup(t, src, "203.0.113.1")
			ts := NewSessionWithRunner(tgt, &ServerCreds{Host: "203.0.113.1"})
			rp := planFor(t, b, ts)
			opt := restoreOpts(t)
			opt.Ctx, opt.Progress = cancelAt(c.cond)
			_, outs, err := ts.Restore(rp, opt)
			if !errors.Is(err, ErrCanceled) || outs != nil || !strings.Contains(err.Error(), "ничего не записано") {
				t.Fatalf("ждали отмену до записи: %v %+v", err, outs)
			}
			if writesOf(tgt) != 0 {
				t.Errorf("записей на сервер %d", writesOf(tgt))
			}
		})
	}
	t.Run("после начала записи", func(t *testing.T) {
		src, tgt := migrationPair(t)
		b := sourceBackup(t, src, "203.0.113.1")
		ts := NewSessionWithRunner(tgt, &ServerCreds{Host: "203.0.113.1"})
		rp := planFor(t, b, ts)
		opt := restoreOpts(t)
		sawWriting := false
		ctx, fn := cancelAt(func(p Progress) bool { return p.Writing })
		opt.Ctx = ctx
		opt.Progress = func(p Progress) { sawWriting = sawWriting || p.Writing; fn(p) }
		_, outs, err := ts.Restore(rp, opt)
		if err != nil || !sawWriting || outs[0].State != RestoreDone {
			t.Fatalf("отмена после начала записи не должна действовать: %v %+v", err, outs)
		}
	})
}
