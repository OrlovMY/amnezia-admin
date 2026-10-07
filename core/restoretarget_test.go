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

func kinds(cs []RestoreConflict) [][]ConflictKind {
	var k [][]ConflictKind
	for _, c := range cs {
		k = append(k, c.Kinds)
	}
	return k
}

type ck = []ConflictKind

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
		conflict [][]ConflictKind // по паре клиентов — одна запись
		confirm  bool
		text     string   // строка конфликта (круг 3)
		removed  []string // удаляемые как в тексте (круг 3)
		src      []tc     // nil — клиенты копии как у fakesrv (Alice, Bob)
	}{
		{"пусто", func(map[string]string) []tc { return nil }, nil, 0, nil, false, "", nil, nil},
		{"есть пользователи без пересечений", func(map[string]string) []tc { return []tc{{other, "Carol", "10.8.1.9/32"}} },
			[]string{"Carol"}, 0, nil, true, "", []string{"Carol"}, nil},
		{"тот же клиент — совпадение", func(s map[string]string) []tc { return []tc{{s["Alice"], "Alice", "10.8.1.2/32"}} },
			[]string{"Alice"}, 1, nil, true, "", nil, nil},
		{"то же имя, другой ключ", func(map[string]string) []tc { return []tc{{other, "Alice", "10.8.1.9/32"}} },
			[]string{"Alice"}, 0, [][]ConflictKind{{ConflictName}}, true,
			"КОНФЛИКТ: «Alice»: на сервере и в копии — разные клиенты (разные ключи)\n", []string{"Alice" + ReplacedNote}, nil},
		// живая проверка: одноимённая пара с разными ключами и тем же
		// адресом — ОДИН конфликт, не два
		{"то же имя, другой ключ, тот же адрес", func(map[string]string) []tc { return []tc{{other, "Bob", "10.8.1.3/32"}} },
			[]string{"Bob"}, 0, [][]ConflictKind{{ConflictName, ConflictAddress}}, true,
			"КОНФЛИКТ: «Bob»: на сервере и в копии — разные клиенты (разные ключи), адрес тот же — 10.8.1.3/32\n", []string{"Bob" + ReplacedNote}, nil},
		// QA Minor: повтор адреса в AllowedIPs — в строке конфликта один раз,
		// порядок первого появления
		// QA: у пары ДВА разных общих адреса — оба, в порядке появления
		// у клиента сервера
		{"два общих адреса у пары", func(map[string]string) []tc { return []tc{{other, "Bob", "10.8.1.4/32, 10.8.1.3/32"}} },
			[]string{"Bob"}, 0, [][]ConflictKind{{ConflictName, ConflictAddress}}, true,
			"КОНФЛИКТ: «Bob»: на сервере и в копии — разные клиенты (разные ключи), адрес тот же — 10.8.1.4/32, 10.8.1.3/32\n", []string{"Bob" + ReplacedNote},
			[]tc{{"SRCBOBKEYaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa=", "Bob", "10.8.1.3/32, 10.8.1.4/32"}}},
		{"адрес повторён в AllowedIPs", func(map[string]string) []tc { return []tc{{other, "Bob", "10.8.1.3/32, 10.8.1.9/32, 10.8.1.3/32"}} },
			[]string{"Bob"}, 0, [][]ConflictKind{{ConflictName, ConflictAddress}}, true,
			"КОНФЛИКТ: «Bob»: на сервере и в копии — разные клиенты (разные ключи), адрес тот же — 10.8.1.3/32\n", []string{"Bob" + ReplacedNote}, nil},
		{"тот же ключ, другое имя", func(s map[string]string) []tc { return []tc{{s["Alice"], "Dave", "10.8.1.2/32"}} },
			[]string{"Dave"}, 0, [][]ConflictKind{{ConflictKey}}, true, "КОНФЛИКТ: один и тот же ключ: на сервере — «Dave», в копии — «Alice»", nil, nil},
		{"тот же адрес у разных", func(map[string]string) []tc { return []tc{{other, "Erin", "10.8.1.3/32"}} },
			[]string{"Erin"}, 0, [][]ConflictKind{{ConflictAddress}}, true, "КОНФЛИКТ: адрес 10.8.1.3/32: на сервере у «Erin», в копии у «Bob»", []string{"Erin"}, nil},
		{"peer без записи в таблице", func(map[string]string) []tc { return []tc{{other, "", "10.8.1.9/32"}} },
			[]string{"(без имени)"}, 0, nil, true, "", []string{"(без имени)"}, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			src, tgt := migrationPair(t)
			if c.src != nil {
				setWGClients(t, src, c.src)
			}
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
			if fmt.Sprint(it.Removed) != fmt.Sprint(c.removed) {
				t.Errorf("удаляемые %q, ожидались %q", it.Removed, c.removed)
			}
			if rp.TargetConflictCount() != len(c.conflict) {
				t.Errorf("конфликтов %d, ожидалось %d (по парам клиентов)", rp.TargetConflictCount(), len(c.conflict))
			}
			if c.confirm {
				head := TargetWarnHead(rp)
				body := strings.Join(TargetWarnLines(rp, 0), "\n")
				if !strings.Contains(head, fmt.Sprintf("— %d", len(c.users))) || !strings.Contains(body, c.users[0]) {
					t.Errorf("текст:\n%s\n%s", head, body)
				}
				if n := strings.Count(body, "КОНФЛИКТ"); n != len(c.conflict) || (c.text != "" && !strings.Contains(body+"\n", c.text)) {
					t.Errorf("конфликтов в тексте %d, ожидалась строка %q:\n%s", n, c.text, body)
				}
			}
		})
	}
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
	setClients := func(s *fakesrv.Server, tblN int, ids ...string) {
		raw, _ := s.File(dir + "/clientsTable")
		var l []ClientEntry
		_ = json.Unmarshal(raw, &l)
		j, _ := json.Marshal(l[:tblN])
		s.SetFile(dir+"/clientsTable", j)
		conf, _ := s.File(dir + "/server.json")
		s.SetFile(dir+"/server.json", []byte(fakesrv.XRayWithClients(string(conf), ids...)))
	}
	svcID := func(s *fakesrv.Server) string {
		k, _ := s.File(dir + "/xray_uuid.key")
		return strings.TrimSpace(string(k))
	}
	onlyAdmin := func(s *fakesrv.Server) { setClients(s, 1, svcID(s)) }
	cases := []struct {
		name         string
		prep         func(*fakesrv.Server)
		users        int
		svc          ServiceState
		confirm      bool
		removedUsers []string
	}{
		{"только админ", onlyAdmin, 0, ServiceFound, false, nil},
		{"админ и пользователи", func(*fakesrv.Server) {}, 2, ServiceFound, true, []string{"Alice" + ReplacedNote, "Bob" + ReplacedNote}},
		// AU-LOGIC З1: клиенты только в server.json — тоже пользователи
		{"UUID в server.json, таблица пуста", func(s *fakesrv.Server) {
			setClients(s, 0, svcID(s), fakesrv.RandUUID(), fakesrv.RandUUID())
		}, 2, ServiceFound, true, []string{"(без имени)", "(без имени)"}},
		{"ключ установки не прочитан", func(s *fakesrv.Server) { onlyAdmin(s); s.SetFile(dir+"/xray_uuid.key", []byte("не uuid\n")) }, 1, ServiceUnknown, true, nil},
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
			// круг 3: одно имя служебного везде, как в list
			body := strings.Join(TargetWarnLines(rp, 0), "\n")
			if c.svc == ServiceFound && (it.Target.ServiceName != XRayServiceName || !strings.Contains(body, "служебный «"+XRayServiceName+"»") || strings.Contains(body, "(без имени)") && c.users == 0) {
				t.Errorf("служебный назван не «%s»: %q\n%s", XRayServiceName, it.Target.ServiceName, body)
			}
			if c.svc == ServiceFound && fmt.Sprint(it.Removed) != fmt.Sprint(append([]string{XRayServiceName}, c.removedUsers...)) {
				t.Errorf("удаляемые %q: служебный не назван «%s»", it.Removed, XRayServiceName)
			}
			if c.svc == ServiceUnknown && !strings.Contains(strings.Join(TargetWarnLines(rp, 0), "\n"), "не опознан") {
				t.Error("не сказано, что служебный не опознан")
			}
		})
	}
}

// TestRestoreTargetXRayConfUnparsed — AU-LOGIC З1, третье состояние:
// server.json цели не разобран — кто там, неизвестно: СТОП, не «0».
func TestRestoreTargetXRayConfUnparsed(t *testing.T) {
	mk := func() *fakesrv.Server {
		s := fakesrv.NewXRay("master")
		for _, k := range []string{"xray_short_id.key", "xray_public.key", "xray_private.key"} {
			s.SetFile("/opt/amnezia/xray/"+k, []byte(k+"-"+fakesrv.RandUUID()))
		}
		return s
	}
	src, tgt := mk(), mk()
	b := sourceBackup(t, src, "203.0.113.1")
	ts := NewSessionWithRunner(tgt, &ServerCreds{Host: "203.0.113.1"})
	t.Cleanup(SetXRayWaits(0, 0))
	compat, err := ts.CheckTarget(b, okResolver)
	if err != nil {
		t.Fatal(err)
	}
	tgt.SetFile("/opt/amnezia/xray/server.json", []byte("{не json"))
	rp, err := ts.PlanRestore(b, compat, true)
	if !errors.Is(err, ErrRestoreStopped) || rp != nil || !strings.Contains(err.Error(), "не разобрана") {
		t.Fatalf("ожидался СТОП: %v %+v", err, rp)
	}
}
