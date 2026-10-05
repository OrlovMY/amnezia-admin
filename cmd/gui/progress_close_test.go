package main

import (
	"os"
	"strings"
	"testing"

	"fyne.io/fyne/v2"

	"amnezia-admin/core"
	"amnezia-admin/internal/fakesrv"
)

// TestCloseInterceptStages — AU-UX П-1: закрытие программы (крестик,
// Alt+F4) вне операции — закрывает; во время записи на сервер — не
// закрывает и объясняет; во время чтения — отменяет операцию, дожидается
// её корректного завершения (файла копии нет) и закрывает. Подмены
// «закрывать всегда» и «во время чтения не отменять» роняют тест.
func TestCloseInterceptStages(t *testing.T) {
	t.Run("вне операции", func(t *testing.T) {
		u := backupUI(t, fakesrv.New(), "203.0.113.1")
		closed := false
		u.closeWin = func() { closed = true }
		u.closeIntercept()
		if !closed {
			t.Error("вне операции программа не закрылась")
		}
	})
	t.Run("запись на сервер", func(t *testing.T) {
		u := backupUI(t, fakesrv.New(), "203.0.113.1")
		closed, canceled := false, false
		u.closeWin = func() { closed = true }
		v := u.progressWindow("т", func() { canceled = true })
		v.apply(core.Progress{Stage: core.StageContainer, Total: 1, Writing: true, Text: "контейнер 1 из 1"})
		u.closeIntercept()
		if closed || canceled {
			t.Fatalf("во время записи: закрыта=%v отменена=%v", closed, canceled)
		}
		if got := topOverlay(t, u); !strings.Contains(got, "закрыть программу сейчас нельзя") {
			t.Errorf("нет объяснения:\n%s", got)
		}
	})
	t.Run("чтение — отмена и закрытие", func(t *testing.T) {
		u := backupUI(t, fakesrv.New(), "203.0.113.1")
		closed := false
		u.closeWin = func() { closed = true }
		dir := t.TempDir()
		release := make(chan struct{})
		beforeBackupWork = func() { <-release }
		t.Cleanup(func() { beforeBackupWork = nil })
		u.doBackup(dir, nil, core.PlainLayer{})
		u.closeIntercept()
		if closed {
			close(release)
			t.Fatal("закрыта до завершения операции")
		}
		close(release)
		waitGUIGoroutines(t)
		if !closed {
			t.Error("после отмены программа не закрылась")
		}
		if ents, _ := os.ReadDir(dir); len(ents) != 0 {
			t.Errorf("после отмены в каталоге: %v", ents)
		}
	})
}

// TestProgressEscCancels — AU-UX П-4: Esc через фокус — «Отмена»; при
// записи на сервер Esc ничего не отменяет.
func TestProgressEscCancels(t *testing.T) {
	u := backupUI(t, fakesrv.New(), "203.0.113.1")
	n := 0
	v := u.progressWindow("т", func() { n++ })
	if u.win.Canvas().Focused() != v.cancel {
		t.Fatalf("фокус не на «Отмена»: %T", u.win.Canvas().Focused())
	}
	deliverKey(u.win.Canvas(), fyne.KeyEscape)
	if n != 1 || !v.cancel.Disabled() {
		t.Errorf("Esc не отменил: %d", n)
	}
	u2 := backupUI(t, fakesrv.New(), "203.0.113.1")
	m := 0
	w := u2.progressWindow("т2", func() { m++ })
	w.apply(core.Progress{Writing: true, Total: 1, Text: "запись"})
	w.cancel.TypedKey(&fyne.KeyEvent{Name: fyne.KeyEscape})
	if m != 0 {
		t.Errorf("Esc при записи отменил: %d", m)
	}
}
