package main

// A3б PR-3, раунд 4 (AU-LOGIC Н-1) — ТЕСТ ДОЕЗДА сценария аудитора через
// настоящее окно изменений: запись прошла, применение (syncconf) упало,
// откат не начался («занято», код 4) или его итог неизвестен (124). После
// первой попытки «Применить» обязана остаться выключенной, а человеку не
// говорится «ничего не записано». Пользуется только API ad7e07c
// (pr3DiffWindow, хуки fakesrv FailSyncconf/WriteFault) — там компилируется
// и падает поведением: безликая ошибка, «Применить» снова включена.

import (
	"errors"
	"strings"
	"testing"

	"fyne.io/fyne/v2/test"

	"amnezia-admin/internal/fakesrv"
)

func TestPR3RollbackFailKeepsApplyOff(t *testing.T) {
	for _, code := range []int{4, 124} {
		u, apply := pr3DiffWindow(t, func(s *fakesrv.Server) {
			s.FailSyncconf = errors.New("имитированный отказ syncconf")
			s.WriteFault = map[int]fakesrv.WriteFault{2: {Code: code}}
		})
		test.Tap(apply)
		waitGUIGoroutines(t)
		top := strings.Join(visibleTexts(u.win.Canvas().Overlays().Top()), " | ")
		if !apply.Disabled() {
			t.Errorf("откат с кодом %d: «Применить» снова включена, хотя изменения на сервере записаны: %s", code, top)
		}
		// код 4 — откат не начался: изменения точно на сервере («Записано,»);
		// 124 — итог отката неизвестен: с раунда 5 (UX-01) первое слово —
		// «Неизвестно», утверждать «записано» после попытки отката нельзя.
		want := map[int]string{4: "Записано,", 124: "Неизвестно, что сейчас на сервере: отмена не подтверждена"}[code]
		if !strings.Contains(top, want) {
			t.Errorf("откат с кодом %d: нет %q: %s", code, want, top)
		}
		if strings.Contains(strings.ToLower(top), "ничего не записано") {
			t.Errorf("откат с кодом %d: сказано «Ничего не записано» при записанных изменениях: %s", code, top)
		}
	}
}
