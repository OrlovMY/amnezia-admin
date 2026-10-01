package core

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// TestFindSavedConfigInLegacy — решение 01.10.2026: каталог прежних версий
// обязателен. Файл только там — найден (с пометкой); прежний каталог не
// читается — «не прочитано», а не «не сохранялся»; оба прочитаны и пусты —
// «не сохранялся».
func TestFindSavedConfigInLegacy(t *testing.T) {
	priv, pub, err := genKey()
	if err != nil {
		t.Fatal(err)
	}
	base := t.TempDir()
	newDir := filepath.Join(base, "новый")
	legacy := filepath.Join(base, "Конфигурации")
	os.MkdirAll(legacy, 0o700)
	os.WriteFile(filepath.Join(legacy, "Вася.conf"), []byte(confWithKey(t, priv, "P", "10.8.1.5/32")), 0o600)
	brokenLegacy := filepath.Join(base, "файл-вместо-каталога")
	os.WriteFile(brokenLegacy, []byte("x"), 0o600)
	empty := filepath.Join(base, "пусто")
	os.MkdirAll(empty, 0o700)

	for _, c := range []struct {
		name   string
		dirs   []SavedDir
		want   SavedConfState
		legacy bool
	}{
		{"только в прежнем каталоге", []SavedDir{{Path: newDir}, {Path: legacy, Legacy: true}}, SavedFound, true},
		{"прежний не читается", []SavedDir{{Path: newDir}, {Path: brokenLegacy, Legacy: true}}, SavedUnreadable, false},
		{"прежний не определён", []SavedDir{{Path: newDir}, {Err: errors.New("Getwd"), Legacy: true}}, SavedUnreadable, false},
		{"оба прочитаны, пусто", []SavedDir{{Path: newDir}, {Path: empty, Legacy: true}}, SavedNotFound, false},
		{"найден, хотя другой не читается", []SavedDir{{Path: brokenLegacy, Legacy: true}, {Path: legacy, Legacy: true}}, SavedFound, true},
		{"каталогов нет вовсе", nil, SavedUnreadable, false},
	} {
		got := FindSavedConfigIn(c.dirs, pub)
		if got.State != c.want || got.Legacy != c.legacy {
			t.Errorf("%s: %v legacy=%v — %s", c.name, got.State, got.Legacy, got.Why)
		}
	}
}

// TestLegacyConfigDirsShape — каталоги прежних версий: абсолютные, имя
// «Конфигурации» (как в 42eafbd), без повторов. Каталоги НЕ читаются.
func TestLegacyConfigDirsShape(t *testing.T) {
	ds := LegacyConfigDirs()
	if len(ds) == 0 || len(ds) > 2 {
		t.Fatalf("каталогов %d", len(ds))
	}
	for _, d := range ds {
		if d.Err != nil || !d.Legacy || !filepath.IsAbs(d.Path) || filepath.Base(d.Path) != "Конфигурации" {
			t.Errorf("каталог прежних версий: %+v", d)
		}
	}
}
