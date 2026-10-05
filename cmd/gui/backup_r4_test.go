package main

import (
	"strings"
	"testing"
	"time"

	"amnezia-admin/core"
)

// TestGUIAutoCopyInheritsLayer — автокопия наследует режим копии-источника:
// зашифрованная — тем же паролем, незашифрованная — без пароля, и итог
// предупреждает «автокопия НЕ зашифрована». Подмена «всегда без пароля»
// роняет тест.
func TestGUIAutoCopyInheritsLayer(t *testing.T) {
	old := core.ProdArgonParams
	core.ProdArgonParams = core.ArgonParams{MemoryKiB: 64, Time: 1, Threads: 1}
	t.Cleanup(func() { core.ProdArgonParams = old })
	u, _, _, plain := guiMigration(t, "203.0.113.1")
	b, _ := core.ReadBackupFile(plain, core.PlainLayer{})
	enc := plain + ".enc.aabk"
	pw := core.NewSecret([]byte("пароль-копии-окна"))
	if err := core.WriteBackupFile(enc, b, core.PasswordLayer{Password: pw}); err != nil {
		t.Fatal(err)
	}

	u.restoreWith(enc, core.PlainLayer{}, core.PasswordLayer{Password: pw})
	waitGUIGoroutines(t)
	_, _, rp, _, err := u.restorePrepare(enc, core.PlainLayer{}, core.PasswordLayer{Password: pw})
	if err != nil {
		t.Fatal(err)
	}
	auto, outs, err := u.runRestore(rp, false, time.Now())
	if err != nil || outs[0].State != core.RestoreDone {
		t.Fatalf("замена: %v %+v", err, outs)
	}
	if l, _ := core.BackupLayerOf(auto); l != core.PasswordLayerName {
		t.Fatalf("автокопия из зашифрованной — слой %q", l)
	}
	if _, err := core.ReadBackupFile(auto, core.PasswordLayer{Password: pw}); err != nil {
		t.Errorf("автокопия не открывается паролем источника: %v", err)
	}
	u.restoreResult(auto, outs, nil)
	if strings.Contains(topOverlay(t, u), core.AutoCopyUnencryptedNote) {
		t.Error("у зашифрованной автокопии предупреждение «НЕ зашифрована»")
	}

	u2, _, _, plain2 := guiMigration(t, "203.0.113.1")
	u2.restoreWith(plain2, core.PlainLayer{})
	waitGUIGoroutines(t)
	_, _, rp2, _, _ := u2.restorePrepare(plain2)
	auto2, outs2, err := u2.runRestore(rp2, false, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if l, _ := core.BackupLayerOf(auto2); l != "none" {
		t.Errorf("автокопия из незашифрованной — слой %q", l)
	}
	u2.restoreResult(auto2, outs2, nil)
	if !strings.Contains(topOverlay(t, u2), core.AutoCopyUnencryptedNote) {
		t.Error("нет предупреждения «автокопия НЕ зашифрована»")
	}
}
