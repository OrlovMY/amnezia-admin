package canary

// К7 на amnezia-wireguard (живой прогон 02.10): «v0.2.0 add прошёл, но не в
// amnezia-wireguard». v0.2.0 выбирать контейнер не умеет — НЕ ПРИМЕНИМО
// только при доказательстве: контейнеров семейства WG не меньше двух и
// canary-k7 найдена в другом из них. Иначе — НЕ ПРОВЕРЕНО.

import (
	"strings"
	"testing"

	"amnezia-admin/core"
	"amnezia-admin/internal/fakesrv"
)

// twoWG — fakesrv с amnezia-awg (первый) и amnezia-wireguard; withK7 —
// canary-k7 лежит в таблице amnezia-awg (туда записала «v0.2.0»).
func twoWG(t *testing.T, withK7 bool) *fakeServer {
	fs := fakesrv.New()
	conf, _ := fs.File("/opt/amnezia/awg/wg0.conf")
	tbl, _ := fs.File("/opt/amnezia/awg/clientsTable")
	fs.SetFile("/opt/amnezia/wireguard/wg0.conf", conf)
	fs.SetFile("/opt/amnezia/wireguard/clientsTable", tbl)
	if withK7 {
		s := strings.TrimRight(strings.TrimSpace(string(tbl)), "]")
		s += `, {"clientId": "` + strings.Repeat("K", 43) + `=", "userData": {"clientName": "canary-k7"}}]`
		fs.SetFile("/opt/amnezia/awg/clientsTable", []byte(s))
	}
	fs.Names = []string{"amnezia-awg", "amnezia-wireguard"}
	f := emptyFakeOn(t, fs, &core.Container{Name: "amnezia-wireguard", Dir: "/opt/amnezia/wireguard", Proto: "WireGuard", Support: core.SupportYes}, false)
	f.env.OldBin = fakeCLI(t, "fakecli-ok")
	return f
}

// TestK7ElsewhereProven — доезд: запись v0.2.0 найдена в amnezia-awg, WG-
// контейнеров два — НЕ ПРИМЕНИМО с названием контейнера.
func TestK7ElsewhereProven(t *testing.T) {
	r := twoWG(t, true).env.k7Elsewhere()
	if r.Status != NotApplicable || !strings.Contains(r.Detail, "ушла в amnezia-awg") {
		t.Fatalf("К7: %s — %s", r.Status, r.Detail)
	}
}

// TestK7ElsewhereNotFound — различение: canary-k7 нигде не найдена —
// НЕ ПРОВЕРЕНО, а не НЕ ПРИМЕНИМО.
func TestK7ElsewhereNotFound(t *testing.T) {
	r := twoWG(t, false).env.k7Elsewhere()
	if r.Status != NotChecked || !strings.Contains(r.Detail, "не доказано") {
		t.Fatalf("К7: %s — %s", r.Status, r.Detail)
	}
}
