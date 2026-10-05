package core

import (
	"bytes"
	"testing"
)

// TestFileMissingForms — закрытый список ответов cat «файла нет»: GNU и
// busybox (контейнеры Amnezia — Alpine), оба — только о пути ЭТОГО файла.
func TestFileMissingForms(t *testing.T) {
	const p = "/opt/amnezia/awg/clientsTable"
	cases := []struct {
		stderr string
		want   bool
	}{
		{"cat: " + p + ": No such file or directory", true},
		{"cat: can't open '" + p + "': No such file or directory", true},
		{"cat: can't open '/opt/amnezia/awg/other': No such file or directory", false},
		{"cat: /etc/x: No such file or directory", false},
		{"cat: can't open '" + p + "': Permission denied", false},
		{"cat: " + p + ": Input/output error", false},
	}
	for _, c := range cases {
		if got := fileMissing(c.stderr, p); got != c.want {
			t.Errorf("%q: %v, ждали %v", c.stderr, got, c.want)
		}
	}
}

// TestBusyboxMissingClientsTable — живая находка 05.10, доезд через
// fakesrv, отвечающий как busybox: clientsTable нет — «нет на сервере» и
// при снятии копии, и на цели; свежая цель без clientsTable
// восстанавливается (CAS «файла не было»), в автокопии цели clientsTable —
// «нет на сервере». Подмена «только GNU» роняет тест.
func TestBusyboxMissingClientsTable(t *testing.T) {
	src, tgt := migrationPair(t)
	src.BusyboxCat, tgt.BusyboxCat = true, true
	b := sourceBackup(t, src, "203.0.113.1")
	if c := ctrOf(t, b, "amnezia-awg"); c.Status != CtrSaved || fileOfB(c, "wireguard_psk.key").Status != FileSaved {
		t.Fatalf("источник: %s", c.Status)
	}
	tgt.DeleteFile(awgDir + "/clientsTable") // свежая установка без пользователей
	ts := NewSessionWithRunner(tgt, &ServerCreds{Host: "203.0.113.1"})
	rp := planFor(t, b, ts)
	auto, outs, err := ts.Restore(rp, restoreOpts(t))
	if err != nil || outs[0].State != RestoreDone {
		t.Fatalf("восстановление на свежую цель: %v %+v", err, outs)
	}
	want, _ := src.File(awgDir + "/clientsTable")
	if got, ok := tgt.File(awgDir + "/clientsTable"); !ok || !bytes.Equal(got, want) {
		t.Error("clientsTable не перенесена")
	}
	ac, err := ReadBackupFile(auto, PlainLayer{})
	if err != nil {
		t.Fatal(err)
	}
	if f := fileOfB(ctrOf(t, ac, "amnezia-awg"), "clientsTable"); f.Status != FileAbsent {
		t.Errorf("в автокопии цели clientsTable — %s, ждали «нет на сервере»", f.Status)
	}
	// обязательные файлы цели по-прежнему обязательны: ключа нет — СТОП
	_, tgt2 := migrationPair(t)
	tgt2.BusyboxCat = true
	tgt2.DeleteFile(awgDir + "/" + keyPsk)
	ts2 := NewSessionWithRunner(tgt2, &ServerCreds{Host: "203.0.113.1"})
	compat, _ := ts2.CheckTarget(b, okResolver)
	if _, err := ts2.PlanRestore(b, compat, true); err == nil {
		t.Error("ключа сервера нет на цели — план построен")
	}
}
