package core

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"amnezia-admin/internal/fakesrv"
)

// TestAutoCopyUniqueSameSecond — CI PR #38: два восстановления с ОДНИМ
// временем (не зависит от скорости машины: время задано) — две автокопии
// под разными именами, первая не затёрта. Подмена «писать без
// уникальности» роняет тест (второе восстановление отказывает).
func TestAutoCopyUniqueSameSecond(t *testing.T) {
	opt := restoreOpts(t) // один каталог и одно время на оба прогона
	var autos []string
	for i := 0; i < 2; i++ {
		src, tgt := migrationPair(t)
		b := sourceBackup(t, src, "203.0.113.1")
		ts := NewSessionWithRunner(tgt, &ServerCreds{Host: "203.0.113.1"})
		rp := planFor(t, b, ts)
		auto, outs, err := ts.Restore(rp, opt)
		if err != nil || outs[0].State != RestoreDone {
			t.Fatalf("восстановление %d: %v %+v", i+1, err, outs)
		}
		autos = append(autos, auto)
	}
	if autos[0] == autos[1] {
		t.Fatalf("одно имя у двух автокопий: %s", autos[0])
	}
	first, _ := os.ReadFile(autos[0])
	for _, p := range autos {
		if _, err := ReadBackupFile(p, PlainLayer{}); err != nil {
			t.Errorf("автокопия %s не читается: %v", p, err)
		}
	}
	if again, _ := os.ReadFile(autos[0]); !bytes.Equal(first, again) {
		t.Error("первая автокопия изменена")
	}
	if filepath.Base(autos[1]) != filepath.Base(autos[0][:len(autos[0])-len(".aabk")])+" (2).aabk" {
		t.Errorf("имя второй автокопии: %s", autos[1])
	}
}

// TestWriteBackupFileUniqueNeverOverwrites — занятое имя не затирается:
// чужой файл цел, копия — под «(2)».
func TestWriteBackupFileUniqueNeverOverwrites(t *testing.T) {
	b, _ := backupSession(t, fakesrv.New()).CollectBackup("t", backupNow, okResolver)
	p := filepath.Join(t.TempDir(), "x.aabk")
	os.WriteFile(p, []byte("ЧУЖОЙ"), 0o600)
	got, err := WriteBackupFileUnique(p, b, PlainLayer{})
	if err != nil || got == p {
		t.Fatalf("%s %v", got, err)
	}
	if c, _ := os.ReadFile(p); string(c) != "ЧУЖОЙ" {
		t.Error("чужой файл затёрт")
	}
	if err := WriteBackupFile(p, b, PlainLayer{}); !errors.Is(err, ErrBackupExists) {
		t.Errorf("явное имя занято — ждали ErrBackupExists: %v", err)
	}
}

// TestSealTimeBound — SEC-01: граница t ≤ 16 и при записи.
func TestSealTimeBound(t *testing.T) {
	l := PasswordLayer{Password: NewSecret([]byte(testPassword)), Params: ArgonParams{MemoryKiB: 64, Time: backupMaxArgonTime + 1, Threads: 1}}
	if _, err := l.Seal([]byte("x")); !errors.Is(err, ErrBackupParams) {
		t.Errorf("t=%d при записи: %v", backupMaxArgonTime+1, err)
	}
	l.Params.Time = backupMaxArgonTime
	if _, err := l.Seal([]byte("x")); err != nil {
		t.Errorf("t=%d отвергнуто: %v", backupMaxArgonTime, err)
	}
}
