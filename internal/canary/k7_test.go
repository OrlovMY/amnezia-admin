package canary

// К7 на amnezia-wireguard (живой прогон 02.10; AU-LOGIC раунд 3 High-2):
// v0.2.0 выбирать контейнер не умеет. НЕ ПРИМЕНИМО — только при
// доказательстве: до add canary-k7 не было ни в одном WG-контейнере,
// после add она появилась в другом, после del её нет по повторному чтению.

import (
	"os"
	"strings"
	"testing"

	"amnezia-admin/core"
	"amnezia-admin/internal/fakesrv"
)

// twoWG — fakesrv с amnezia-awg (первый) и amnezia-wireguard (проверяемый);
// preK7 — canary-k7 лежит в amnezia-awg ещё до К7.
func twoWG(t *testing.T, preK7 bool) *fakeServer {
	fs := fakesrv.New()
	conf, _ := fs.File("/opt/amnezia/awg/wg0.conf")
	tbl, _ := fs.File("/opt/amnezia/awg/clientsTable")
	fs.SetFile("/opt/amnezia/wireguard/wg0.conf", conf)
	fs.SetFile("/opt/amnezia/wireguard/clientsTable", tbl)
	if preK7 {
		s := strings.TrimRight(strings.TrimSpace(string(tbl)), "]")
		s += `, {"clientId": "` + strings.Repeat("K", 43) + `=", "userData": {"clientName": "canary-k7"}}]`
		fs.SetFile("/opt/amnezia/awg/clientsTable", []byte(s))
	}
	fs.Names = []string{"amnezia-awg", "amnezia-wireguard"}
	f := emptyFakeOn(t, fs, &core.Container{Name: "amnezia-wireguard", Dir: "/opt/amnezia/wireguard", Proto: "WireGuard", Support: core.SupportYes}, false)
	return f
}

// firstOld — подставная v0.2.0: настоящая программа, всегда в amnezia-awg;
// nodel — del «успешен» без действия.
func firstOld(t *testing.T, nodel bool) string {
	p := fakeCLI(t, "fakecli-first")
	if err := os.WriteFile(p+".real", []byte(newCLI(t)), 0o600); err != nil {
		t.Fatal(err)
	}
	if nodel {
		if err := os.WriteFile(p+".nodel", nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return p
}

// TestK7ElsewhereProven — доезд: «v0.2.0» сама пишет canary-k7 в первый
// контейнер и удаляет её — НЕ ПРИМЕНИМО с названием контейнера.
func TestK7ElsewhereProven(t *testing.T) {
	f := twoWG(t, false)
	f.env.OldBin = firstOld(t, false)
	r := f.env.oldWorks("drwxrwxrwt")
	if r.Status != NotApplicable || !strings.Contains(r.Detail, "появилась в amnezia-awg") {
		t.Fatalf("К7: %s — %s", r.Status, r.Detail)
	}
	if cl, _ := f.env.Sess.LoadClients(&core.Container{Name: "amnezia-awg", Dir: "/opt/amnezia/awg"}); func() bool {
		for _, c := range cl {
			if c.Name() == "canary-k7" {
				return true
			}
		}
		return false
	}() {
		t.Errorf("canary-k7 осталась в amnezia-awg")
	}
}

// TestK7RecordBeforeAdd — тест аудитора: canary-k7 была в amnezia-awg до
// add, «v0.2.0» ничего не делает (fakecli-ok) — не НЕ ПРИМЕНИМО.
func TestK7RecordBeforeAdd(t *testing.T) {
	f := twoWG(t, true)
	f.env.OldBin = fakeCLI(t, "fakecli-ok")
	r := f.env.oldWorks("drwxrwxrwt")
	if r.Status == NotApplicable || !strings.Contains(r.Detail, "уже есть до add") {
		t.Fatalf("К7: %s — %s", r.Status, r.Detail)
	}
}

// TestK7DelLeftRecord — del ответил кодом 0, а запись осталась — не НЕ
// ПРИМЕНИМО (НЕ ПРОЙДЕН).
func TestK7DelLeftRecord(t *testing.T) {
	f := twoWG(t, false)
	f.env.OldBin = firstOld(t, true)
	r := f.env.oldWorks("drwxrwxrwt")
	if r.Status != Fail || !strings.Contains(r.Detail, "запись осталась") {
		t.Fatalf("К7: %s — %s", r.Status, r.Detail)
	}
}

// TestK7NotFoundAnywhere — различение: «v0.2.0» (fakecli-ok) ничего не
// записала — НЕ ПРОВЕРЕНО, а не НЕ ПРИМЕНИМО.
func TestK7NotFoundAnywhere(t *testing.T) {
	f := twoWG(t, false)
	f.env.OldBin = fakeCLI(t, "fakecli-ok")
	r := f.env.oldWorks("drwxrwxrwt")
	if r.Status != NotChecked || !strings.Contains(r.Detail, "не доказано") {
		t.Fatalf("К7: %s — %s", r.Status, r.Detail)
	}
}

// TestK7OtherListUnreadable — QA-01 T6: список другого WG-контейнера не
// прочитан — НЕ ПРОВЕРЕНО с причиной в тексте, а не молчаливый пропуск.
func TestK7OtherListUnreadable(t *testing.T) {
	f := twoWG(t, false)
	f.env.OldBin = firstOld(t, false)
	f.exec.Configure(func(s *fakesrv.Server) {
		if s.FailReadTimes == nil {
			s.FailReadTimes = map[string]int{}
		}
		s.FailReadTimes["/opt/amnezia/awg/clientsTable"] = 1000
	})
	r := f.env.oldWorks("drwxrwxrwt")
	if r.Status != NotChecked || !strings.Contains(r.Detail, "список amnezia-awg не прочитан") {
		t.Fatalf("К7: %s — %s", r.Status, r.Detail)
	}
}

// TestP1TraceInOtherContainer — живой прогон 02.10: canary-k7 от прошлого
// прогона лежала в amnezia-awg, проверялся amnezia-wireguard. П1 обязан
// остановить ДО любой записи — след ищется во всех WG-контейнерах.
func TestP1TraceInOtherContainer(t *testing.T) {
	f := twoWG(t, true)
	inner := f.env.Remote
	f.env.Remote = func(cmd string) (string, error) {
		switch {
		case strings.Contains(cmd, "id "+TempUser) && strings.Contains(cmd, "echo DONE"):
			return "DONE", nil
		case strings.Contains(cmd, "canary-orig"):
			return "DONE", nil
		}
		return inner(cmd)
	}
	before := len(f.exec.Commands())
	r := f.env.traces()
	if r.Status != Fail || !strings.Contains(r.Detail, "в amnezia-awg есть canary-k7") {
		t.Fatalf("П1: %s — %s", r.Status, r.Detail)
	}
	for _, c := range f.exec.Commands()[before:] {
		if strings.Contains(c, "flock") || strings.Contains(c, "cat > ") {
			t.Errorf("запись при П1: %.80s", c)
		}
	}
}
