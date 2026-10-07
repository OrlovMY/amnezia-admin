package core

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"amnezia-admin/internal/fakesrv"
)

// srcIDs — ключи клиентов копии по именам (Alice 10.8.1.2, Bob 10.8.1.3).
func srcIDs(t *testing.T, srv *fakesrv.Server, dir string) map[string]string {
	t.Helper()
	raw, _ := srv.File(dir + "/clientsTable")
	var l []ClientEntry
	if err := json.Unmarshal(raw, &l); err != nil {
		t.Fatal(err)
	}
	m := map[string]string{}
	for _, e := range l {
		m[e.Name()] = e.ClientID
	}
	return m
}

func kinds(cs []RestoreConflict) []ConflictKind {
	var k []ConflictKind
	for _, c := range cs {
		k = append(k, c.Kind)
	}
	return k
}

// TestRestoreTargetUsersWG — табличный: пусто / есть пользователи /
// совпадение / конфликты имени, ключа, адреса / peer без записи — боевым
// путём (CollectBackup → CheckTarget → PlanRestore по fakesrv).
func TestRestoreTargetUsersWG(t *testing.T) {
	const other = "OTHERKEYaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa="
	cases := []struct {
		name     string
		tgt      func(src map[string]string) []tc
		users    []string
		matches  int
		conflict []ConflictKind
		confirm  bool
	}{
		{"пусто", func(map[string]string) []tc { return nil }, nil, 0, nil, false},
		{"есть пользователи без пересечений", func(map[string]string) []tc { return []tc{{other, "Carol", "10.8.1.9/32"}} },
			[]string{"Carol"}, 0, nil, true},
		{"тот же клиент — совпадение", func(s map[string]string) []tc { return []tc{{s["Alice"], "Alice", "10.8.1.2/32"}} },
			[]string{"Alice"}, 1, nil, true},
		{"то же имя, другой ключ", func(map[string]string) []tc { return []tc{{other, "Alice", "10.8.1.9/32"}} },
			[]string{"Alice"}, 0, []ConflictKind{ConflictName}, true},
		{"тот же ключ, другое имя", func(s map[string]string) []tc { return []tc{{s["Alice"], "Dave", "10.8.1.2/32"}} },
			[]string{"Dave"}, 0, []ConflictKind{ConflictKey}, true},
		{"тот же адрес у разных", func(map[string]string) []tc { return []tc{{other, "Erin", "10.8.1.3/32"}} },
			[]string{"Erin"}, 0, []ConflictKind{ConflictAddress}, true},
		{"peer без записи в таблице", func(map[string]string) []tc { return []tc{{other, "", "10.8.1.9/32"}} },
			[]string{"(без имени)"}, 0, nil, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			src, tgt := migrationPair(t)
			b := sourceBackup(t, src, "203.0.113.1")
			setWGClients(t, tgt, c.tgt(srcIDs(t, src, awgDir)))
			ts := NewSessionWithRunner(tgt, &ServerCreds{Host: "203.0.113.1"})
			rp := planFor(t, b, ts)
			it := rp.Items[0]
			if fmt.Sprint(it.Target.Users) != fmt.Sprint(c.users) || len(it.Target.Matches) != c.matches ||
				fmt.Sprint(kinds(it.Conflicts)) != fmt.Sprint(c.conflict) || it.Target.Service != ServiceNone {
				t.Fatalf("пользователи %v совпадения %v конфликты %v служебный %v", it.Target.Users, it.Target.Matches, it.Conflicts, it.Target.Service)
			}
			if rp.NeedsTargetConfirm() != c.confirm || rp.TargetUserCount() != len(c.users) {
				t.Fatalf("подтверждение %v, число %d", rp.NeedsTargetConfirm(), rp.TargetUserCount())
			}
			if len(it.Removed) != len(c.users)-c.matches-countKind(it.Conflicts, ConflictKey) {
				t.Errorf("удаляемые %v", it.Removed)
			}
			if c.confirm {
				head := TargetWarnHead(rp)
				body := strings.Join(TargetWarnLines(rp, 0), "\n")
				if !strings.Contains(head, fmt.Sprintf("— %d", len(c.users))) || !strings.Contains(body, c.users[0]) {
					t.Errorf("текст:\n%s\n%s", head, body)
				}
				if len(c.conflict) > 0 && !strings.Contains(body, "КОНФЛИКТ") {
					t.Errorf("конфликт не назван:\n%s", body)
				}
			}
		})
	}
}

func countKind(cs []RestoreConflict, k ConflictKind) int {
	n := 0
	for _, c := range cs {
		if c.Kind == k {
			n++
		}
	}
	return n
}

// TestRestoreTargetUnparsed — третье состояние: clientsTable цели не
// разобрана — «не удалось узнать», план не строится (не «0 пользователей»).
func TestRestoreTargetUnparsed(t *testing.T) {
	src, tgt := migrationPair(t)
	b := sourceBackup(t, src, "203.0.113.1")
	ts := NewSessionWithRunner(tgt, &ServerCreds{Host: "203.0.113.1"})
	compat, err := ts.CheckTarget(b, okResolver)
	if err != nil {
		t.Fatal(err)
	}
	tgt.SetFile(awgDir+"/clientsTable", []byte("{не json"))
	rp, err := ts.PlanRestore(b, compat, true)
	if !errors.Is(err, ErrRestoreStopped) || rp != nil || !strings.Contains(err.Error(), "не разобрана") {
		t.Fatalf("ожидался СТОП «не разобрана»: %v %+v", err, rp)
	}
}

// TestRestoreTargetXRay — служебный XRay (xray_uuid.key) не считается
// пользователем; только он — подтверждение не нужно; ключ установки не
// прочитан — служебный не опознан, посчитаны все.
func TestRestoreTargetXRay(t *testing.T) {
	mk := func() *fakesrv.Server {
		s := fakesrv.NewXRay("master")
		for _, k := range []string{"xray_short_id.key", "xray_public.key", "xray_private.key"} {
			s.SetFile("/opt/amnezia/xray/"+k, []byte(k+"-"+fakesrv.RandUUID()))
		}
		return s
	}
	const dir = "/opt/amnezia/xray"
	onlyAdmin := func(s *fakesrv.Server) {
		raw, _ := s.File(dir + "/clientsTable")
		var l []ClientEntry
		_ = json.Unmarshal(raw, &l)
		j, _ := json.Marshal(l[:1])
		s.SetFile(dir+"/clientsTable", j)
	}
	cases := []struct {
		name    string
		prep    func(*fakesrv.Server)
		users   int
		svc     ServiceState
		confirm bool
	}{
		{"только админ", onlyAdmin, 0, ServiceFound, false},
		{"админ и пользователи", func(*fakesrv.Server) {}, 2, ServiceFound, true},
		{"ключ установки не прочитан", func(s *fakesrv.Server) { onlyAdmin(s); s.SetFile(dir+"/xray_uuid.key", []byte("не uuid\n")) }, 1, ServiceUnknown, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			src, tgt := mk(), mk()
			b := sourceBackup(t, src, "203.0.113.1")
			ts := NewSessionWithRunner(tgt, &ServerCreds{Host: "203.0.113.1"})
			t.Cleanup(SetXRayWaits(0, 0))
			compat, err := ts.CheckTarget(b, okResolver)
			if err != nil {
				t.Fatal(err)
			}
			c.prep(tgt)
			rp, err := ts.PlanRestore(b, compat, true)
			if err != nil {
				t.Fatal(err)
			}
			it := rp.Items[len(rp.Items)-1]
			if len(it.Target.Users) != c.users || it.Target.Service != c.svc || rp.NeedsTargetConfirm() != c.confirm {
				t.Fatalf("пользователи %v служебный %v «%s» подтверждение %v", it.Target.Users, it.Target.Service, it.Target.ServiceName, rp.NeedsTargetConfirm())
			}
			if c.svc == ServiceFound && !strings.HasPrefix(it.Target.ServiceName, "Admin") {
				t.Errorf("служебный не назван: %q", it.Target.ServiceName)
			}
			if c.svc == ServiceUnknown && !strings.Contains(strings.Join(TargetWarnLines(rp, 0), "\n"), "не опознан") {
				t.Error("не сказано, что служебный не опознан")
			}
		})
	}
}
