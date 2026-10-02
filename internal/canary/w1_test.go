package canary

// PR-W1: канарейка для семейства WG — К4 со своим «старым писателем», К7 на
// amnezia-awg2 — «НЕ ПРИМЕНИМО», файл конфигурации из таблицы.

import (
	"os"
	"strings"
	"testing"
	"time"

	"amnezia-admin/core"
)

// TestOldWriterRestoresFiles — контроль К4 (прежняя запись без замка)
// возвращает оба файла к состоянию до контроля; потеря при этом измерена.
func TestOldWriterRestoresFiles(t *testing.T) {
	f := emptyFake(t, false)
	f.exec.CommandDelay = 30 * time.Millisecond
	f.env.RaceRounds = 3
	confBefore, _ := f.exec.File("/opt/amnezia/awg/wg0.conf")
	if _, ok := f.exec.File("/opt/amnezia/awg/clientsTable"); ok {
		t.Fatal("тест ждёт сервер без clientsTable")
	}
	o, err := f.env.oldWriterRace()
	if err != nil {
		t.Fatalf("контроль: %v", err)
	}
	if o.Done+o.Collided != 6 {
		t.Errorf("записей старого писателя %d (+%d упало на .tmp), ждали 6", o.Done, o.Collided)
	}
	t.Logf("потеряно %d из %d", o.Lost, o.Done)
	confAfter, _ := f.exec.File("/opt/amnezia/awg/wg0.conf")
	tblAfter, _ := f.exec.File("/opt/amnezia/awg/clientsTable")
	if string(confAfter) != string(confBefore) {
		t.Errorf("wg0.conf после контроля не вернулся к прежнему")
	}
	if string(tblAfter) != "[]" {
		t.Errorf("clientsTable до контроля не было — ждали пустую таблицу, получили %q", tblAfter)
	}
}

// TestK7NotApplicableOnAWG2 — К7 (v0.2.0 после всего) для amnezia-awg2 —
// «НЕ ПРИМЕНИМО» с причиной; v0.2.0 при этом не запускается.
func TestK7NotApplicableOnAWG2(t *testing.T) {
	ctr := &core.Container{Name: "amnezia-awg2", Dir: "/opt/amnezia/awg", Proto: "awg2", Support: core.SupportYes}
	fam, err := core.WGFamilyOf(ctr)
	if err != nil {
		t.Fatal(err)
	}
	e := &Env{Ctr: ctr, fam: fam, OldBin: "/nonexistent/v0.2.0"}
	r := e.oldWorks("drwxrwxrwt")
	if r.Status != NotApplicable || !strings.Contains(r.Detail, "amnezia-awg2") {
		t.Fatalf("К7 на amnezia-awg2: %s — %s", r.Status, r.Detail)
	}
}

// TestSummaryNotApplicable — «НЕ ПРИМЕНИМО» не превращает итог ни в
// «пройдено», ни в «не проверено»; но одни лишь «не применимо» — не
// «пройдено».
func TestSummaryNotApplicable(t *testing.T) {
	st, line := Summary([]Result{{Status: Pass}, {Status: NotApplicable}}, nil)
	if st != Pass || !strings.Contains(line, "не применимо 1") {
		t.Errorf("пройдено + не применимо: %s — %s", st, line)
	}
	if st, line := Summary([]Result{{Status: NotApplicable}}, nil); st == Pass {
		t.Errorf("только «не применимо» — это не ПРОЙДЕН: %s", line)
	}
	if st, _ := Summary([]Result{{Status: Pass}, {Status: NotApplicable}, {Status: NotChecked}}, nil); st != NotChecked {
		t.Errorf("с «не проверено» итог обязан быть НЕ ПРОВЕРЕНО, получен %s", st)
	}
}

// TestCanaryUsesFamilyFile — шаги канарейки берут файл конфигурации из
// таблицы семейства: на amnezia-awg2 — awg0.conf.
func TestCanaryUsesFamilyFile(t *testing.T) {
	ctr := &core.Container{Name: "amnezia-awg2", Dir: "/opt/amnezia/awg"}
	fam, _ := core.WGFamilyOf(ctr)
	e := &Env{Ctr: ctr, fam: fam}
	if got := e.conf(); got != "/opt/amnezia/awg/awg0.conf" {
		t.Errorf("файл конфигурации на amnezia-awg2: %q", got)
	}
}

// TestCanaryPassesContainerToNew — новой версии канарейка передаёт
// -container проверяемого контейнера; v0.2.0 (флага не знает) — нет.
func TestCanaryPassesContainerToNew(t *testing.T) {
	newBin := fakeCLI(t, "fakecli-args")
	oldBin := fakeCLI(t, "fakecli-args-old")
	ctr := &core.Container{Name: "amnezia-awg2", Dir: "/opt/amnezia/awg"}
	e := &Env{Ctr: ctr, NewBin: newBin, OldBin: oldBin, HostKey: "SHA256:x"}
	e.cli(newBin, nil, "list")
	e.cli(oldBin, nil, "list")
	na, _ := os.ReadFile(newBin + ".args")
	oa, _ := os.ReadFile(oldBin + ".args")
	if !strings.Contains(string(na), "-container amnezia-awg2") {
		t.Errorf("новой версии не передан -container: %q", na)
	}
	if strings.Contains(string(oa), "-container") {
		t.Errorf("v0.2.0 передан -container, которого она не знает: %q", oa)
	}
}
