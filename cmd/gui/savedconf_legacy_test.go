package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"fyne.io/fyne/v2/widget"

	"amnezia-admin/core"
)

// TestMenuFindsLegacyConfig — ДОЕЗД каталога прежних версий: файл только в
// «Конфигурации» прежних версий — найден, окно говорит откуда, файл не
// тронут; этот каталог не читается — «не прочитано», а не «не сохранялся».
func TestMenuFindsLegacyConfig(t *testing.T) {
	u, dir, conf := savedFixture(t)
	legacy := filepath.Join(t.TempDir(), "Конфигурации")
	saved := legacyConfigDirs
	t.Cleanup(func() { legacyConfigDirs = saved })
	legacyConfigDirs = func() []core.SavedDir { return []core.SavedDir{{Path: legacy, Legacy: true}} }
	if err := os.MkdirAll(legacy, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(dir, "Carol.conf"), filepath.Join(legacy, "Carol.conf")); err != nil {
		t.Fatal(err)
	}
	row := rowOf(t, u, "Carol")
	u.cellMenu(widget.TableCellID{Row: row, Col: 1}).Items[2].Action()
	waitGUIGoroutines(t)
	txt := popupText(t, u)
	if !strings.Contains(txt, "Конфиг из файла: "+filepath.Join(legacy, "Carol.conf")) || !strings.Contains(txt, "Каталог прежних версий") {
		t.Errorf("файл в прежнем каталоге не найден:\n%s", txt)
	}
	if b, _ := os.ReadFile(filepath.Join(legacy, "Carol.conf")); string(b) != conf {
		t.Error("файл в прежнем каталоге изменён")
	}
	u.win.Canvas().Overlays().Top().Hide()

	if err := os.RemoveAll(legacy); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(legacy, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	u.cellMenu(widget.TableCellID{Row: row, Col: 1}).Items[2].Action()
	if txt := popupText(t, u); !strings.Contains(txt, wantUnreadablePrefix) || strings.Contains(txt, wantSavedNotFound) {
		t.Errorf("прежний каталог не читается — ожидалось «не прочитано»:\n%s", txt)
	}
}
