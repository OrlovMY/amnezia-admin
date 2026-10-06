package main

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"fyne.io/fyne/v2/test"
	"fyne.io/fyne/v2/widget"

	"amnezia-admin/core"
	"amnezia-admin/internal/fakesrv"
)

// TestProgressViewStates — полоса «X из Y»; неделимый этап — бесконечная
// полоса; с началом записи на сервер «Отмена» выключается и объясняет
// почему. Подмены «Отмена доступна при записи» и «без бесконечной полосы»
// роняют тест.
func TestProgressViewStates(t *testing.T) {
	u := backupUI(t, fakesrv.New(), "203.0.113.1")
	canceled := false
	v := u.progressWindow("т", func() { canceled = true })
	v.apply(core.Progress{Stage: core.StageRead, Done: 3, Total: 8, Text: "прочитано файлов 3 из 8 — amnezia-awg (проход 1 из 2)"})
	if !v.bar.Visible() || v.inf.Visible() || v.bar.Value != 3 || v.bar.Max != 8 || !strings.Contains(v.label.Text, "3 из 8") {
		t.Errorf("счётный этап: видна=%v беск=%v %v/%v %q", v.bar.Visible(), v.inf.Visible(), v.bar.Value, v.bar.Max, v.label.Text)
	}
	v.apply(core.Progress{Stage: core.StageEncrypt, Text: "шифрование паролем…"})
	if v.bar.Visible() || !v.inf.Visible() {
		t.Error("шифрование — не бесконечная полоса")
	}
	if v.cancel.Disabled() {
		t.Fatal("до записи «Отмена» выключена")
	}
	v.apply(core.Progress{Stage: core.StageContainer, Done: 0, Total: 1, Writing: true, Text: "контейнер 1 из 1"})
	if !v.cancel.Disabled() || !strings.Contains(v.note.Text, "отменить нельзя") {
		t.Errorf("запись: отмена выключена=%v, подпись %q", v.cancel.Disabled(), v.note.Text)
	}
	test.Tap(v.cancel)
	if canceled {
		t.Error("выключенная «Отмена» отменила")
	}
}

// TestGUIBackupCancelAndBusy — во время сохранения главное окно недоступно
// (busy), видно окно прогресса с единственной кнопкой «Отмена»; отмена —
// файла нет, итог «Отменено — копия не сохранена».
func TestGUIBackupCancelAndBusy(t *testing.T) {
	u := backupUI(t, fakesrv.New(), "203.0.113.1")
	u.copyBtn, u.refreshBtn, u.addBtn = widget.NewButton("Копия", nil), widget.NewButton("Обновить", nil), widget.NewButton("Создать", nil)
	u.canManage = true
	dir, _ := core.UserBackupsDir()
	release := make(chan struct{})
	beforeBackupWork = func() { <-release }
	t.Cleanup(func() { beforeBackupWork = nil })
	u.doBackup(dir, nil, core.PlainLayer{})
	if !u.busy || !u.copyBtn.Disabled() || !u.refreshBtn.Disabled() || !u.addBtn.Disabled() || u.lastProgress == nil {
		close(release)
		t.Fatalf("во время операции: busy=%v копия=%v обновить=%v создать=%v", u.busy, u.copyBtn.Disabled(), u.refreshBtn.Disabled(), u.addBtn.Disabled())
	}
	if got := topOverlay(t, u); !strings.Contains(got, "["+progressCancelText+"]") || strings.Count(got, "[") != 1 {
		t.Errorf("в окне прогресса не одна «Отмена»:\n%s", got)
	}
	close(release)
	waitGUIGoroutines(t)
	// отмена: заранее отменённый контекст — тот же путь, что «Отмена»
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	p, b, err := u.runBackupCtx(ctx, dir+"-отмена", time.Now(), core.PlainLayer{}, nil)
	if !errors.Is(err, core.ErrCanceled) || p != "" {
		t.Fatalf("отмена: %q %v", p, err)
	}
	if _, serr := os.Stat(dir + "-отмена"); serr == nil {
		if ents, _ := os.ReadDir(dir + "-отмена"); len(ents) != 0 {
			t.Errorf("после отмены файлы: %v", ents)
		}
	}
	u.backupResult(p, b, err)
	if got := topOverlay(t, u); !strings.Contains(got, "Отменено — копия не сохранена") {
		t.Errorf("итог отмены:\n%s", got)
	}
	if u.busy || u.copyBtn.Disabled() {
		t.Error("после операции главное окно не вернулось")
	}
}

// TestGUIRestoreCancelResult — отмена восстановления до записи — итог
// «Отменено — на сервер ничего не записано».
func TestGUIRestoreCancelResult(t *testing.T) {
	u, _, tgt, p := guiMigration(t, "203.0.113.1")
	_, _, rp, _, err := u.restorePrepare(p)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	auto, outs, err := u.runRestoreCtx(ctx, rp, false, time.Now(), nil)
	if !errors.Is(err, core.ErrCanceled) || outs != nil || writesGUI(tgt) != 0 {
		t.Fatalf("отмена: %v %+v записей %d", err, outs, writesGUI(tgt))
	}
	u.restoreResult(auto, outs, err)
	if got := topOverlay(t, u); !strings.Contains(got, "Отменено — на сервер ничего не записано") {
		t.Errorf("итог:\n%s", got)
	}
}
