package main

import (
	"strings"
	"testing"
	"time"

	"amnezia-admin/core"
)

// TestCloseRequestedButWritten — AU-UX П-5: закрытие просили во время
// автокопии (closeIntercept → отмена), но ядро уже прошло последнюю точку
// отмены и записало: программа НЕ закрывается, итог восстановления и окно
// «Программа не закрыта» показаны. Завершилось отменой — закрывается без
// итога. Подмена «закрывать всегда после завершения» роняет тест.
func TestCloseRequestedButWritten(t *testing.T) {
	u, _, _, p := guiMigration(t, "203.0.113.1")
	closed := false
	u.closeWin = func() { closed = true }
	_, _, rp, _, err := u.restorePrepare(p)
	if err != nil {
		t.Fatal(err)
	}
	// настоящая запись дошла до конца
	auto, outs, err := u.runRestore(rp, false, time.Now())
	if err != nil || outs[0].State != core.RestoreDone {
		t.Fatalf("замена: %v %+v", err, outs)
	}
	// закрытие было запрошено во время автокопии (до записи)
	v := u.progressWindow("Восстановление из копии", func() {})
	u.closeIntercept()
	if !u.closeAfterOp || v.writing {
		t.Fatalf("закрытие не отложено: %v", u.closeAfterOp)
	}
	u.restoreFinished(auto, outs, nil)
	if closed {
		t.Fatal("программа закрыта, хотя запись прошла — итог не показан")
	}
	got := topOverlay(t, u)
	if !strings.Contains(got, "Программа не закрыта") && !strings.Contains(got, "запись уже шла") {
		t.Errorf("нет окна «не закрыта»:\n%s", got)
	}
	found := false
	for _, o := range u.win.Canvas().Overlays().List() {
		if strings.Contains(texts(o), "Автокопия нового сервера до замены") {
			found = true
		}
	}
	if !found {
		t.Error("итог восстановления не показан")
	}

	// завершилось отменой — закрыть
	u2, _, _, _ := guiMigration(t, "203.0.113.1")
	closed2 := false
	u2.closeWin = func() { closed2 = true }
	u2.progressWindow("Восстановление из копии", func() {})
	u2.closeIntercept()
	u2.restoreFinished("", nil, core.ErrCanceled)
	if !closed2 {
		t.Error("отменено закрытием — программа не закрылась")
	}
}
