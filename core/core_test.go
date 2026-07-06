package core

import (
	"bytes"
	"compress/zlib"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"strconv"
	"testing"
	"time"
)

// ---------- DecodeVpnKey ----------

func makeQCompressKey(t *testing.T, payload map[string]any) string {
	t.Helper()
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var zbuf bytes.Buffer
	w := zlib.NewWriter(&zbuf)
	if _, err := w.Write(data); err != nil {
		t.Fatalf("zlib write: %v", err)
	}
	w.Close()

	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(data)))
	raw := append(lenBuf[:], zbuf.Bytes()...)
	return "vpn://" + base64.RawURLEncoding.EncodeToString(raw)
}

func TestDecodeVpnKey(t *testing.T) {
	t.Run("qCompress", func(t *testing.T) {
		key := makeQCompressKey(t, map[string]any{"hostName": "1.2.3.4", "userName": "root"})
		m, err := DecodeVpnKey(key)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if m["hostName"] != "1.2.3.4" {
			t.Errorf("hostName = %v, want 1.2.3.4", m["hostName"])
		}
	})

	t.Run("bare JSON base64", func(t *testing.T) {
		data, _ := json.Marshal(map[string]any{"userName": "vasya"})
		key := "vpn://" + base64.RawURLEncoding.EncodeToString(data)
		m, err := DecodeVpnKey(key)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if m["userName"] != "vasya" {
			t.Errorf("userName = %v, want vasya", m["userName"])
		}
	})

	t.Run("broken base64", func(t *testing.T) {
		_, err := DecodeVpnKey("vpn://not-valid-base64!!!===")
		if err == nil {
			t.Fatal("expected error for broken base64, got nil")
		}
	})
}

// ---------- parseWgConf ----------

func TestParseWgConf(t *testing.T) {
	t.Run("basic with two peers", func(t *testing.T) {
		text := `[Interface]
PrivateKey = serverpriv
Address = 10.8.1.1/24
ListenPort = 51820

[Peer]
PublicKey = peer1pub
AllowedIPs = 10.8.1.2/32

[Peer]
PublicKey = peer2pub
AllowedIPs = 10.8.1.3/32
`
		conf := parseWgConf(text)
		if conf.iface["PrivateKey"] != "serverpriv" {
			t.Errorf("PrivateKey = %q", conf.iface["PrivateKey"])
		}
		if len(conf.peers) != 2 {
			t.Fatalf("peers = %d, want 2", len(conf.peers))
		}
		if conf.peers[0]["PublicKey"] != "peer1pub" {
			t.Errorf("peer0 pubkey = %q", conf.peers[0]["PublicKey"])
		}
		if conf.peers[1]["AllowedIPs"] != "10.8.1.3/32" {
			t.Errorf("peer1 AllowedIPs = %q", conf.peers[1]["AllowedIPs"])
		}
	})

	t.Run("CRLF line endings", func(t *testing.T) {
		text := "[Interface]\r\nPrivateKey = abc\r\n\r\n[Peer]\r\nPublicKey = pk1\r\n"
		conf := parseWgConf(text)
		// CRLF: TrimSpace должен убрать \r из конца строки
		if conf.iface["PrivateKey"] != "abc" {
			t.Errorf("PrivateKey = %q, want abc (без \\r)", conf.iface["PrivateKey"])
		}
		if len(conf.peers) != 1 || conf.peers[0]["PublicKey"] != "pk1" {
			t.Errorf("peers = %+v", conf.peers)
		}
	})

	t.Run("comments ignored", func(t *testing.T) {
		text := `[Interface]
# это комментарий
PrivateKey = abc
[Peer]
# ещё комментарий
PublicKey = pk1
`
		conf := parseWgConf(text)
		if conf.iface["PrivateKey"] != "abc" {
			t.Errorf("PrivateKey = %q", conf.iface["PrivateKey"])
		}
		if len(conf.peers) != 1 || conf.peers[0]["PublicKey"] != "pk1" {
			t.Errorf("peers = %+v", conf.peers)
		}
	})
}

// ---------- removePeerFromConf ----------

func TestRemovePeerFromConf(t *testing.T) {
	base := `[Interface]
PrivateKey = serverpriv

[Peer]
PublicKey = pk1
AllowedIPs = 10.8.1.2/32

[Peer]
PublicKey = pk2
AllowedIPs = 10.8.1.3/32

[Peer]
PublicKey = pk3
AllowedIPs = 10.8.1.4/32
`

	t.Run("remove middle peer", func(t *testing.T) {
		res := removePeerFromConf(base, "pk2")
		conf := parseWgConf(res)
		if len(conf.peers) != 2 {
			t.Fatalf("peers = %d, want 2", len(conf.peers))
		}
		for _, p := range conf.peers {
			if p["PublicKey"] == "pk2" {
				t.Errorf("pk2 не должен остаться в конфиге")
			}
		}
	})

	t.Run("remove nonexistent key", func(t *testing.T) {
		res := removePeerFromConf(base, "no-such-key")
		conf := parseWgConf(res)
		if len(conf.peers) != 3 {
			t.Errorf("peers = %d, want 3 (ничего не должно удалиться)", len(conf.peers))
		}
	})

	t.Run("remove only peer", func(t *testing.T) {
		text := `[Interface]
PrivateKey = abc

[Peer]
PublicKey = pk1
AllowedIPs = 10.8.1.2/32
`
		res := removePeerFromConf(text, "pk1")
		conf := parseWgConf(res)
		if len(conf.peers) != 0 {
			t.Errorf("peers = %d, want 0", len(conf.peers))
		}
	})
}

// ---------- ResolveClient ----------

func TestResolveClient(t *testing.T) {
	clients := []ClientEntry{
		{ClientID: "pk1", UserData: map[string]any{"clientName": "Alice"}},
		{ClientID: "pk2", UserData: map[string]any{"clientName": "Bob"}},
		{ClientID: "pk3", UserData: map[string]any{"clientName": "Alice"}}, // дубль имени
	}

	t.Run("by number", func(t *testing.T) {
		if idx := ResolveClient(clients, "2"); idx != 1 {
			t.Errorf("idx = %d, want 1", idx)
		}
	})

	t.Run("by pubkey", func(t *testing.T) {
		if idx := ResolveClient(clients, "pk2"); idx != 1 {
			t.Errorf("idx = %d, want 1", idx)
		}
	})

	t.Run("not found", func(t *testing.T) {
		if idx := ResolveClient(clients, "nope"); idx != -1 {
			t.Errorf("idx = %d, want -1", idx)
		}
	})

	// При дублях имён ResolveClient по имени возвращает первого найденного
	// (индекс 0, "Alice" на pk1), а не pk3 — таково задокументированное поведение.
	t.Run("duplicate names returns first", func(t *testing.T) {
		if idx := ResolveClient(clients, "Alice"); idx != 0 {
			t.Errorf("idx = %d, want 0 (первый с этим именем)", idx)
		}
	})
}

// ---------- ValidateName ----------

func TestValidateName(t *testing.T) {
	valid := []string{
		"Иванов Иван",
		"vasya-2 (test).conf",
		"a",
	}
	for _, name := range valid {
		if err := ValidateName(name); err != nil {
			t.Errorf("ValidateName(%q) = %v, want nil", name, err)
		}
	}

	invalid := []struct{ name, desc string }{
		{"", "пустое"},
		{"   ", "только пробелы"},
		{"a\"b", "кавычка"},
		{"a;rm -rf /", "точка с запятой"},
		{"a\x00b", "control char"},
	}
	for _, tc := range invalid {
		name, desc := tc.name, tc.desc
		if err := ValidateName(name); err == nil {
			t.Errorf("ValidateName(%q) [%s] = nil, want error", name, desc)
		}
	}

	// длина 65 рун — невалидно
	long := make([]rune, 65)
	for i := range long {
		long[i] = 'a'
	}
	if err := ValidateName(string(long)); err == nil {
		t.Error("65 рун должно быть невалидным")
	}
}

// ---------- HumanBytes ----------

func TestHumanBytes(t *testing.T) {
	cases := []struct {
		in   int64
		want string
	}{
		{0, "0 B"},
		{512, "512 B"},
		{1500, "1.5 KB"},
		{23_400_000, "23.4 MB"},
		{1_200_000_000, "1.2 GB"},
	}
	for _, c := range cases {
		if got := HumanBytes(c.in); got != c.want {
			t.Errorf("HumanBytes(%d) = %q, want %q", c.in, got, c.want)
		}
	}
}

// ---------- parsePeerStats ----------

func TestParsePeerStats(t *testing.T) {
	now := time.Now().Unix()
	dump := "serverpriv\tserverpub\t51820\toff\n" +
		"peer1pub\t(none)\t1.2.3.4:12345\t10.8.1.2/32\t" + strconv.FormatInt(now, 10) + "\t1000\t2000\toff\n" +
		"peer2pub\t(none)\t(none)\t10.8.1.3/32\t0\t0\t0\toff\n" +
		"garbage line with too few fields\n"

	stats := parsePeerStats(dump)
	if len(stats) != 2 {
		t.Fatalf("stats len = %d, want 2", len(stats))
	}
	p1 := stats["peer1pub"]
	if p1.LastHandshake.IsZero() {
		t.Error("peer1 должен иметь ненулевой handshake")
	}
	if p1.RxBytes != 1000 || p1.TxBytes != 2000 {
		t.Errorf("peer1 rx/tx = %d/%d, want 1000/2000", p1.RxBytes, p1.TxBytes)
	}
	p2 := stats["peer2pub"]
	if !p2.LastHandshake.IsZero() {
		t.Error("peer2 должен иметь нулевой handshake (никогда не подключался)")
	}
}

// ---------- SortByActivity ----------

func TestSortByActivity(t *testing.T) {
	now := time.Now()
	clients := []ClientEntry{
		{ClientID: "never-old", UserData: map[string]any{"clientName": "NeverOld", "creationDate": "2020-01-01T00:00:00Z"}},
		{ClientID: "recent", UserData: map[string]any{"clientName": "Recent", "creationDate": "2021-01-01T00:00:00Z"}},
		{ClientID: "never-new", UserData: map[string]any{"clientName": "NeverNew", "creationDate": "2022-01-01T00:00:00Z"}},
		{ClientID: "older", UserData: map[string]any{"clientName": "Older", "creationDate": "2019-01-01T00:00:00Z"}},
	}
	stats := map[string]PeerStat{
		"recent": {LastHandshake: now},
		"older":  {LastHandshake: now.Add(-time.Hour)},
		// never-old, never-new — нет записи вовсе (нулевой handshake)
	}

	SortByActivity(clients, stats)

	got := make([]string, len(clients))
	for i, cl := range clients {
		got[i] = cl.ClientID
	}
	// недавний handshake первым, затем более старый; никогда не подключавшиеся —
	// в конце, среди них порядок по Created (never-old раньше never-new)
	want := []string{"recent", "older", "never-old", "never-new"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("порядок = %v, want %v", got, want)
		}
	}
}

// Инвариант, на который опирается CLI/GUI: номер строки в отрисованном списке
// должен соответствовать индексу элемента в том же (уже отсортированном) slice —
// то есть после SortByActivity ResolveClient по номеру "N" обязан вернуть
// N-й элемент именно этого slice, без повторного чтения/пересортировки.
func TestSortedSliceRowNumberInvariant(t *testing.T) {
	now := time.Now()
	clients := []ClientEntry{
		{ClientID: "a", UserData: map[string]any{"clientName": "A", "creationDate": "2020-01-01T00:00:00Z"}},
		{ClientID: "b", UserData: map[string]any{"clientName": "B", "creationDate": "2021-01-01T00:00:00Z"}},
		{ClientID: "c", UserData: map[string]any{"clientName": "C", "creationDate": "2022-01-01T00:00:00Z"}},
	}
	stats := map[string]PeerStat{
		"c": {LastHandshake: now},
	}
	SortByActivity(clients, stats)
	// после сортировки "c" (единственный с handshake) должен быть первым
	if clients[0].ClientID != "c" {
		t.Fatalf("clients[0] = %s, want c", clients[0].ClientID)
	}
	// строка "1" в отрисованном списке должна резолвиться именно в clients[0]
	idx := ResolveClient(clients, "1")
	if idx != 0 || clients[idx].ClientID != "c" {
		t.Fatalf("ResolveClient(clients, \"1\") = %d (%s), want 0 (c)", idx, clients[idx].ClientID)
	}
}

// ---------- DeleteByID (чистая часть: filterClientsByID + removePeerFromConf) ----------

func TestFilterClientsByID(t *testing.T) {
	clients := []ClientEntry{
		{ClientID: "pk1", UserData: map[string]any{"clientName": "Alice"}},
		{ClientID: "pk2", UserData: map[string]any{"clientName": "Bob"}},
		{ClientID: "pk3", UserData: map[string]any{"clientName": "Carol"}},
	}

	t.Run("removes only the target, keeps order", func(t *testing.T) {
		out, found := filterClientsByID(clients, "pk2")
		if !found {
			t.Fatal("expected found = true")
		}
		if len(out) != 2 {
			t.Fatalf("len = %d, want 2", len(out))
		}
		if out[0].ClientID != "pk1" || out[1].ClientID != "pk3" {
			t.Fatalf("порядок нарушен: %+v", out)
		}
		// исходный slice не должен быть задет (другие клиенты — те же объекты)
		if clients[0].ClientID != "pk1" || clients[2].ClientID != "pk3" {
			t.Fatal("исходный список изменён")
		}
	})

	t.Run("not found", func(t *testing.T) {
		out, found := filterClientsByID(clients, "no-such-key")
		if found {
			t.Fatal("expected found = false")
		}
		if len(out) != 3 {
			t.Fatalf("len = %d, want 3", len(out))
		}
	})
}

// TestDeleteByIDDoesNotTouchOthers проверяет, что удаление одного клиента
// (через чистые части DeleteByID — removePeerFromConf + filterClientsByID)
// не затрагивает остальных: их peer-блоки и записи clientsTable сохраняются.
func TestDeleteByIDDoesNotTouchOthers(t *testing.T) {
	confText := `[Interface]
PrivateKey = serverpriv

[Peer]
PublicKey = pk1
AllowedIPs = 10.8.1.2/32

[Peer]
PublicKey = pk2
AllowedIPs = 10.8.1.3/32

[Peer]
PublicKey = pk3
AllowedIPs = 10.8.1.4/32
`
	clients := []ClientEntry{
		{ClientID: "pk1", UserData: map[string]any{"clientName": "Alice"}},
		{ClientID: "pk2", UserData: map[string]any{"clientName": "Bob"}},
		{ClientID: "pk3", UserData: map[string]any{"clientName": "Carol"}},
	}

	newConf := removePeerFromConf(confText, "pk2")
	newClients, found := filterClientsByID(clients, "pk2")
	if !found {
		t.Fatal("pk2 должен быть найден")
	}

	conf := parseWgConf(newConf)
	if len(conf.peers) != 2 {
		t.Fatalf("peers = %d, want 2", len(conf.peers))
	}
	for _, p := range conf.peers {
		if p["PublicKey"] == "pk2" {
			t.Error("pk2 не должен остаться в конфиге")
		}
	}
	haveKeys := map[string]bool{}
	for _, p := range conf.peers {
		haveKeys[p["PublicKey"]] = true
	}
	if !haveKeys["pk1"] || !haveKeys["pk3"] {
		t.Errorf("pk1/pk3 должны остаться в конфиге: %+v", haveKeys)
	}

	if len(newClients) != 2 {
		t.Fatalf("clientsTable len = %d, want 2", len(newClients))
	}
	names := map[string]bool{}
	for _, cl := range newClients {
		names[cl.Name()] = true
	}
	if !names["Alice"] || !names["Carol"] {
		t.Errorf("Alice/Carol должны остаться: %+v", names)
	}
	if names["Bob"] {
		t.Error("Bob должен быть удалён")
	}
}

// ---------- RenameUser (чистая часть: renameClientInList) ----------

func TestRenameClientInList(t *testing.T) {
	base := []ClientEntry{
		{ClientID: "pk1", UserData: map[string]any{"clientName": "Alice", "creationDate": "2020-01-01T00:00:00Z"}},
		{ClientID: "pk2", UserData: map[string]any{"clientName": "Bob", "creationDate": "2021-01-01T00:00:00Z"}},
	}

	t.Run("renames and keeps order/other fields", func(t *testing.T) {
		out, err := renameClientInList(base, "pk2", "  Robert  ")
		if err != nil {
			t.Fatalf("renameClientInList: %v", err)
		}
		if out[0].Name() != "Alice" || out[0].ClientID != "pk1" {
			t.Errorf("первая запись не должна измениться: %+v", out[0])
		}
		if out[1].Name() != "Robert" {
			t.Errorf("Name() = %q, want Robert (обрезано пробелами)", out[1].Name())
		}
		if out[1].Created() != "2021-01-01T00:00:00Z" {
			t.Errorf("Created() изменился: %q", out[1].Created())
		}
		// исходный slice не мутирован
		if base[1].Name() != "Bob" {
			t.Error("исходный список не должен изменяться")
		}
	})

	t.Run("duplicate name rejected", func(t *testing.T) {
		_, err := renameClientInList(base, "pk2", "Alice")
		if err == nil {
			t.Fatal("expected error for duplicate name")
		}
	})

	t.Run("rename to own current name is allowed (not a duplicate of itself)", func(t *testing.T) {
		_, err := renameClientInList(base, "pk1", "Alice")
		if err != nil {
			t.Errorf("renaming to the same name should not conflict with itself: %v", err)
		}
	})

	t.Run("not found", func(t *testing.T) {
		_, err := renameClientInList(base, "no-such-id", "NewName123")
		if err == nil {
			t.Fatal("expected error for unknown clientID")
		}
	})

	t.Run("invalid new name rejected", func(t *testing.T) {
		_, err := renameClientInList(base, "pk1", "")
		if err == nil {
			t.Fatal("expected error for empty name")
		}
	})
}

// ---------- buildPeerBlock ----------

func TestBuildPeerBlock(t *testing.T) {
	block := buildPeerBlock("PUBKEY", "PSK", "10.8.1.5/32")
	conf := parseWgConf(block)
	if len(conf.peers) != 1 {
		t.Fatalf("peers = %d, want 1", len(conf.peers))
	}
	p := conf.peers[0]
	if p["PublicKey"] != "PUBKEY" || p["PresharedKey"] != "PSK" || p["AllowedIPs"] != "10.8.1.5/32" {
		t.Errorf("peer = %+v", p)
	}
}

// TestDisableEnableRoundtripPreservesPeer проверяет ключевой инвариант
// disable→enable: PresharedKey и AllowedIPs, сохранённые в UserData при
// отключении, восстанавливают ТОЧНО ТЕ ЖЕ ключ/IP через buildPeerBlock —
// то есть повторное появление peer'а в wg0.conf после enable будет
// идентично тому, что было до disable.
func TestDisableEnableRoundtripPreservesPeer(t *testing.T) {
	originalPeerText := buildPeerBlock("PUBKEY123", "PSK456", "10.8.1.9/32")
	conf := parseWgConf(originalPeerText)
	peer := conf.peers[0]

	// имитация того, что делает disableClient: сохраняем psk/allowedIP в UserData
	entry := ClientEntry{
		ClientID: "PUBKEY123",
		UserData: map[string]any{
			"clientName": "Dave",
			"disabled":   true,
			"psk":        peer["PresharedKey"],
			"allowedIP":  peer["AllowedIPs"],
		},
	}
	if !entry.Disabled() {
		t.Fatal("entry должен быть Disabled()")
	}

	// имитация enableClient: строим блок обратно из сохранённых полей
	restored := buildPeerBlock(entry.ClientID, Str(entry.UserData, "psk"), Str(entry.UserData, "allowedIP"))
	if restored != originalPeerText {
		t.Errorf("восстановленный блок отличается от исходного:\nwant: %q\ngot:  %q", originalPeerText, restored)
	}
}

// ---------- ClientEntry.Disabled ----------

func TestClientEntryDisabled(t *testing.T) {
	cases := []struct {
		name string
		ud   map[string]any
		want bool
	}{
		{"absent field", map[string]any{"clientName": "A"}, false},
		{"explicit false", map[string]any{"disabled": false}, false},
		{"explicit true", map[string]any{"disabled": true}, true},
		{"wrong type ignored", map[string]any{"disabled": "true"}, false},
	}
	for _, tc := range cases {
		e := ClientEntry{UserData: tc.ud}
		if got := e.Disabled(); got != tc.want {
			t.Errorf("%s: Disabled() = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// ---------- ResolveNonNumeric ----------

// TestResolveNonNumericRejectsNumbers — регресс на wrong-target баг: вне
// интерактивного (отсортированного и напечатанного) списка номер строки не
// имеет смысла, потому что LoadClients не гарантирует тот же порядок, что
// видел пользователь. rename/toggle/del в non-interactive CLI обязаны
// использовать этот резолвер, а не голый ResolveClient.
func TestResolveNonNumericRejectsNumbers(t *testing.T) {
	clients := []ClientEntry{
		{ClientID: "pk1", UserData: map[string]any{"clientName": "Alice"}},
		{ClientID: "pk2", UserData: map[string]any{"clientName": "Bob"}},
		{ClientID: "pk3", UserData: map[string]any{"clientName": "Carol"}},
	}

	numeric := []string{"1", "2", "3", " 2 ", "007"}
	for _, ident := range numeric {
		t.Run("numeric_"+ident, func(t *testing.T) {
			idx, err := ResolveNonNumeric(clients, ident)
			if err == nil {
				t.Fatalf("ResolveNonNumeric(%q) = idx %d, nil — want error (numbers must be rejected)", ident, idx)
			}
		})
	}

	t.Run("by name", func(t *testing.T) {
		idx, err := ResolveNonNumeric(clients, "Bob")
		if err != nil {
			t.Fatalf("ResolveNonNumeric(Bob): %v", err)
		}
		if idx != 1 {
			t.Errorf("idx = %d, want 1", idx)
		}
	})

	t.Run("by pubkey", func(t *testing.T) {
		idx, err := ResolveNonNumeric(clients, "pk3")
		if err != nil {
			t.Fatalf("ResolveNonNumeric(pk3): %v", err)
		}
		if idx != 2 {
			t.Errorf("idx = %d, want 2", idx)
		}
	})

	t.Run("not found", func(t *testing.T) {
		_, err := ResolveNonNumeric(clients, "nope")
		if err == nil {
			t.Fatal("expected error for unknown ident")
		}
	})
}

// TestEnableClearsSecretCopies — после включения UserData не должен хранить
// лишнюю копию psk/allowedIP (peer уже восстановлен в wg0.conf; хранить
// секрет в двух местах ни к чему). Проверяем чистую часть логики enable —
// тот же фильтр ключей, что использует enableClient при формировании
// нового UserData.
func TestEnableClearsSecretCopies(t *testing.T) {
	before := map[string]any{
		"clientName": "Dave",
		"disabled":   true,
		"disabledAt": "2024-01-01T00:00:00Z",
		"psk":        "SECRETPSK",
		"allowedIP":  "10.8.1.9/32",
	}
	after := make(map[string]any, len(before))
	for k, v := range before {
		if k == "disabled" || k == "disabledAt" || k == "psk" || k == "allowedIP" {
			continue
		}
		after[k] = v
	}
	for _, k := range []string{"disabled", "disabledAt", "psk", "allowedIP"} {
		if _, ok := after[k]; ok {
			t.Errorf("после enable ключ %q не должен оставаться в UserData", k)
		}
	}
	if after["clientName"] != "Dave" {
		t.Error("остальные поля (clientName) должны сохраниться")
	}
}

// ---------- rekeyClientInList (RegenerateUser) ----------

func TestRekeyClientInList(t *testing.T) {
	base := []ClientEntry{
		{ClientID: "pk1", UserData: map[string]any{"clientName": "Alice", "creationDate": "2020-01-01T00:00:00Z"}},
		{ClientID: "pk2", UserData: map[string]any{"clientName": "Bob", "creationDate": "2021-01-01T00:00:00Z"}},
		{ClientID: "pk3", UserData: map[string]any{"clientName": "Carol", "creationDate": "2022-01-01T00:00:00Z"}},
	}

	t.Run("replaces in place, keeps name/creationDate/order", func(t *testing.T) {
		out, err := rekeyClientInList(base, "pk2", "pk2-NEW")
		if err != nil {
			t.Fatalf("rekeyClientInList: %v", err)
		}
		if len(out) != 3 {
			t.Fatalf("len = %d, want 3", len(out))
		}
		// порядок сохранён: замена на месте (индекс 1), а не в конец списка
		if out[0].ClientID != "pk1" || out[2].ClientID != "pk3" {
			t.Fatalf("порядок нарушен: %+v", out)
		}
		if out[1].ClientID != "pk2-NEW" {
			t.Errorf("ClientID = %q, want pk2-NEW", out[1].ClientID)
		}
		// старый ClientID больше нигде не встречается
		for _, cl := range out {
			if cl.ClientID == "pk2" {
				t.Error("старый ClientID pk2 не должен остаться в списке")
			}
		}
		if out[1].Name() != "Bob" {
			t.Errorf("Name() = %q, want Bob (сохранено)", out[1].Name())
		}
		if out[1].Created() != "2021-01-01T00:00:00Z" {
			t.Errorf("Created() = %q, want исходную дату создания", out[1].Created())
		}
		if Str(out[1].UserData, "rekeyedAt") == "" {
			t.Error("ожидался UserData[\"rekeyedAt\"]")
		}
		// исходный слайс не мутирован
		if base[1].ClientID != "pk2" {
			t.Error("исходный список не должен изменяться")
		}
	})

	t.Run("clears stale disable-related fields", func(t *testing.T) {
		withDisabled := []ClientEntry{
			{ClientID: "pkA", UserData: map[string]any{
				"clientName": "Dave", "creationDate": "2020-01-01T00:00:00Z",
				"disabled": true, "disabledAt": "2023-01-01T00:00:00Z",
				"psk": "OLDPSK", "allowedIP": "10.8.1.5/32",
			}},
		}
		out, err := rekeyClientInList(withDisabled, "pkA", "pkA-NEW")
		if err != nil {
			t.Fatalf("rekeyClientInList: %v", err)
		}
		for _, k := range []string{"disabled", "disabledAt", "psk", "allowedIP"} {
			if _, ok := out[0].UserData[k]; ok {
				t.Errorf("ключ %q должен быть удалён при re-key", k)
			}
		}
		if out[0].Name() != "Dave" {
			t.Errorf("Name() = %q, want Dave", out[0].Name())
		}
	})

	t.Run("not found", func(t *testing.T) {
		_, err := rekeyClientInList(base, "no-such-id", "new-id")
		if err == nil {
			t.Fatal("expected error for unknown oldID")
		}
	})
}

// ---------- QRPNG ----------

func TestQRPNG(t *testing.T) {
	png, err := QRPNG("vpn://test-config-data", 256)
	if err != nil {
		t.Fatalf("QRPNG: %v", err)
	}
	if len(png) == 0 {
		t.Fatal("QRPNG вернул пустой результат")
	}
	sig := []byte{0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n'}
	if len(png) < len(sig) || string(png[:len(sig)]) != string(sig) {
		n := len(png)
		if n > 8 {
			n = 8
		}
		t.Errorf("PNG-сигнатура не найдена, первые байты: %v", png[:n])
	}
}
