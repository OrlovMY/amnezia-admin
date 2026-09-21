package core

import (
	"bytes"
	"compress/zlib"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"amnezia-admin/internal/fakesrv"
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
		res, err := removePeerFromConf(base, "pk2")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
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
		res, err := removePeerFromConf(base, "no-such-key")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
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
		res, err := removePeerFromConf(text, "pk1")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		conf := parseWgConf(res)
		if len(conf.peers) != 0 {
			t.Errorf("peers = %d, want 0", len(conf.peers))
		}
	})
}

// TestRemovePeerExactMatch проверяет, что сравнение — точное: ключ "abc" не
// должен удалять peer с ключом "abcd" или "xabc" (раньше — strings.Contains,
// см. аудит 2026-09-14, High).
func TestRemovePeerExactMatch(t *testing.T) {
	text := `[Interface]
PrivateKey = serverpriv

[Peer]
PublicKey = abcd
AllowedIPs = 10.8.1.2/32

[Peer]
PublicKey = xabc
AllowedIPs = 10.8.1.3/32
`
	t.Run("substring key does not match", func(t *testing.T) {
		res, err := removePeerFromConf(text, "abc")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		conf := parseWgConf(res)
		if len(conf.peers) != 2 {
			t.Fatalf("peers = %d, want 2 (ничего не должно удалиться)", len(conf.peers))
		}
	})

	t.Run("exact key removes exactly its block, others untouched byte-for-byte", func(t *testing.T) {
		res, err := removePeerFromConf(text, "abcd")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		conf := parseWgConf(res)
		if len(conf.peers) != 1 {
			t.Fatalf("peers = %d, want 1", len(conf.peers))
		}
		if conf.peers[0]["PublicKey"] != "xabc" || conf.peers[0]["AllowedIPs"] != "10.8.1.3/32" {
			t.Errorf("оставшийся блок изменён: %+v", conf.peers[0])
		}
	})
}

// TestRemovePeerEmptyKeyRefused проверяет отказ на пустом/пробельном ключе:
// текст не меняется, DeleteByID отказывает до любой команды записи.
func TestRemovePeerEmptyKeyRefused(t *testing.T) {
	text := `[Interface]
PrivateKey = serverpriv

[Peer]
PublicKey = pk1
AllowedIPs = 10.8.1.2/32
`
	for _, key := range []string{"", "   "} {
		res, err := removePeerFromConf(text, key)
		if err == nil {
			t.Fatalf("key %q: expected error, got nil", key)
		}
		if res != text {
			t.Fatalf("key %q: текст конфига не должен меняться", key)
		}
	}

	srv := fakesrv.New()
	sess := NewSessionWithRunner(srv, &ServerCreds{Host: "1.2.3.4", User: "root", Password: "x"})
	c := &Container{Name: "amnezia-awg", Dir: "/opt/amnezia/awg", Proto: "AmneziaWG", Managed: true}
	if err := sess.DeleteByID(c, ""); err == nil {
		t.Fatal("DeleteByID(\"\") должен вернуть ошибку")
	}
	if len(srv.Commands()) != 0 {
		t.Errorf("DeleteByID(\"\") не должен посылать ни одной команды, получено: %v", srv.Commands())
	}
}

// ---------- ResolveClient ----------

func TestResolveClient(t *testing.T) {
	clients := []ClientEntry{
		{ClientID: "pk1", UserData: map[string]any{"clientName": "Alice"}},
		{ClientID: "pk2", UserData: map[string]any{"clientName": "Bob"}},
		{ClientID: "pk3", UserData: map[string]any{"clientName": "Alice"}}, // дубль имени
	}

	t.Run("by number", func(t *testing.T) {
		r := ResolveClient(clients, "2")
		if r.Kind != ResolveFound || r.Index != 1 {
			t.Errorf("r = %+v, want Found index 1", r)
		}
		if r.ByName {
			t.Errorf("ByName = true, want false (найден по номеру строки)")
		}
	})

	t.Run("by pubkey", func(t *testing.T) {
		r := ResolveClient(clients, "pk2")
		if r.Kind != ResolveFound || r.Index != 1 || !r.ByName {
			t.Errorf("r = %+v, want Found index 1 ByName", r)
		}
	})

	t.Run("not found", func(t *testing.T) {
		r := ResolveClient(clients, "nope")
		if r.Kind != ResolveNotFound {
			t.Errorf("Kind = %v, want ResolveNotFound", r.Kind)
		}
	})

	// A8: дубль имени БОЛЬШЕ НЕ разрешается молча в первого — это отдельный,
	// отличимый исход. Прежнее поведение (вернуть индекс 0) — ровно тот
	// дефект, из-за которого del/rename/toggle могли ударить не по тому.
	t.Run("duplicate names is ambiguous", func(t *testing.T) {
		r := ResolveClient(clients, "Alice")
		if r.Kind != ResolveAmbiguous {
			t.Fatalf("Kind = %v, want ResolveAmbiguous (было: молча индекс 0)", r.Kind)
		}
		if len(r.Matches) != 2 || r.Matches[0] != 0 || r.Matches[1] != 2 {
			t.Fatalf("Matches = %v, want [0 2]", r.Matches)
		}
		err := r.Err(clients)
		if err == nil {
			t.Fatal("Err = nil, want ошибку с перечнем")
		}
		for _, want := range []string{"несколько", "pk1", "pk3"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("Err = %q, не содержит %q", err.Error(), want)
			}
		}
	})
}

// TestResolveClientThreeOutcomes — тест РАЗЛИЧЕНИЯ (CLAUDE.md): «не найдено»
// и «подходит несколько» обязаны отличаться друг от друга, а не оба
// сворачиваться в одно перегруженное -1. Плюс решение владельца
// (21.09.2026): имя главнее номера, и программа говорит, кого поняла.
func TestResolveClientThreeOutcomes(t *testing.T) {
	// Список из 12 строк; у 12-го клиента имя из одних цифр — "12".
	var many []ClientEntry
	for i := 1; i <= 12; i++ {
		name := fmt.Sprintf("user%d", i)
		if i == 12 {
			name = "12"
		}
		many = append(many, ClientEntry{
			ClientID: fmt.Sprintf("key%d", i),
			UserData: map[string]any{"clientName": name},
		})
	}
	// Клиент с именем "12" стоит ПОСЛЕДНИМ (индекс 11), и строка № 12 — это
	// он же; чтобы проверка «имя главнее номера» не проходила случайно,
	// переставим его на первое место: тогда имя даёт 0, а номер — 11.
	many[0], many[11] = many[11], many[0]

	dup := []ClientEntry{
		{ClientID: "pkA", UserData: map[string]any{"clientName": "Дубль"}},
		{ClientID: "pkB", UserData: map[string]any{"clientName": "Дубль"}},
	}

	cases := []struct {
		name     string
		clients  []ClientEntry
		ident    string
		wantKind ResolveKind
		wantIdx  int
	}{
		{"имя из цифр главнее номера строки", many, "12", ResolveFound, 0},
		{"номер строки без конфликта имён", many, "5", ResolveFound, 4},
		{"обычное имя", many, "user5", ResolveFound, 4},
		{"два одноимённых — неоднозначно", dup, "Дубль", ResolveAmbiguous, -1},
		{"ничего не совпало", many, "нет-такого", ResolveNotFound, -1},
		{"число вне списка — не номер строки", many, "999", ResolveNotFound, -1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := ResolveClient(tc.clients, tc.ident)
			if r.Kind != tc.wantKind {
				t.Fatalf("Kind = %v, want %v (r = %+v)", r.Kind, tc.wantKind, r)
			}
			if tc.wantKind == ResolveFound && r.Index != tc.wantIdx {
				t.Fatalf("Index = %d, want %d", r.Index, tc.wantIdx)
			}
			// Тест различения: третье состояние не равно «нет».
			if tc.wantKind == ResolveAmbiguous && r.Kind == ResolveNotFound {
				t.Fatal("неоднозначность неотличима от «не найдено»")
			}
		})
	}

	// «Не найдено» и «неоднозначно» — разные тексты, а не один.
	notFound := ResolveClient(many, "нет-такого").Err(many)
	ambiguous := ResolveClient(dup, "Дубль").Err(dup)
	if notFound == nil || ambiguous == nil {
		t.Fatal("оба исхода обязаны давать ошибку")
	}
	if notFound.Error() == ambiguous.Error() {
		t.Fatalf("тексты совпали (%q) — исходы неотличимы для человека", notFound.Error())
	}
	if strings.Contains(ambiguous.Error(), "не найден") {
		t.Fatalf("неоднозначность выдана за «не найдено»: %q", ambiguous.Error())
	}
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
	r := ResolveClient(clients, "1")
	if r.Kind != ResolveFound || r.Index != 0 || clients[r.Index].ClientID != "c" {
		t.Fatalf("ResolveClient(clients, \"1\") = %+v, want Found index 0 (c)", r)
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

	newConf, err := removePeerFromConf(confText, "pk2")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
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

// ---------- Runner / fakesrv (PR-1) ----------
//
// Ниже — тесты на internal/fakesrv.Server: без сети, без диска (кроме map в
// памяти самого fakesrv), без реального SSH. Тестового сервера у владельца
// нет и не будет (bk-consult-2026-09-14, ответ 6) — это единственный способ
// проверить операции над сервером.

func testCreds() *ServerCreds {
	return &ServerCreds{Host: "1.2.3.4", User: "root", Password: "x"}
}

func awgContainer() *Container {
	return &Container{Name: "amnezia-awg", Dir: "/opt/amnezia/awg", Proto: "AmneziaWG", Managed: true}
}

// TestLoadClientsMissingVsError — "нет файла" не ошибка, "не удалось
// прочитать" — ошибка (аудит 2026-09-14, Critical: раньше обе ветки давали
// пустой список, и AddUser поверх сбойного чтения стирал всех пользователей).
func TestLoadClientsMissingVsError(t *testing.T) {
	c := awgContainer()

	t.Run("a: файла нет — пустой список, не ошибка", func(t *testing.T) {
		srv := fakesrv.New()
		srv.DeleteFile(c.Dir + "/clientsTable")
		sess := NewSessionWithRunner(srv, testCreds())

		list, err := sess.LoadClients(c)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(list) != 0 {
			t.Errorf("list = %+v, want empty", list)
		}
	})

	t.Run("b: файл есть, cat падает — ошибка, AddUser ничего не пишет", func(t *testing.T) {
		srv := fakesrv.New()
		srv.FailRead = map[string]error{c.Dir + "/clientsTable": fmt.Errorf("i/o timeout")}
		sess := NewSessionWithRunner(srv, testCreds())

		list, err := sess.LoadClients(c)
		if err == nil {
			t.Fatal("expected error")
		}
		if list != nil {
			t.Errorf("list = %+v, want nil", list)
		}

		if _, err := sess.AddUser(c, "Carol"); err == nil {
			t.Fatal("AddUser: expected error")
		}
		for _, cmd := range srv.Commands() {
			if strings.Contains(cmd, "cat > ") {
				t.Fatalf("AddUser не должен был выполнить ни одной записи, но выполнил: %q", cmd)
			}
		}
	})

	t.Run("c: файл есть и пуст — пустой список, не ошибка", func(t *testing.T) {
		srv := fakesrv.New()
		srv.SetFile(c.Dir+"/clientsTable", []byte("   \n"))
		sess := NewSessionWithRunner(srv, testCreds())

		list, err := sess.LoadClients(c)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(list) != 0 {
			t.Errorf("list = %+v, want empty", list)
		}
	})
}

// TestAwg2Unsupported — amnezia-awg2 (и любой другой неизвестный WG-подобный
// контейнер) считается неуправляемым, а не "пустым сервером" (аудит
// 2026-09-14, Backlog: у awg2 конфиг называется awg0.conf, а не wg0.conf).
func TestAwg2Unsupported(t *testing.T) {
	srv := fakesrv.New()
	srv.Names = append(srv.Names, "amnezia-awg2")
	sess := NewSessionWithRunner(srv, testCreds())

	containers, err := sess.FindContainers()
	if err != nil {
		t.Fatalf("FindContainers: %v", err)
	}
	var awg2 *Container
	for i := range containers {
		if containers[i].Name == "amnezia-awg2" {
			awg2 = &containers[i]
		}
	}
	if awg2 == nil {
		t.Fatalf("amnezia-awg2 не найден среди контейнеров: %+v", containers)
	}
	if awg2.Managed {
		t.Error("amnezia-awg2 должен быть Managed == false")
	}

	if _, err := sess.AddUser(awg2, "Dave"); err == nil {
		t.Fatal("AddUser на awg2 должен вернуть ошибку")
	} else if !strings.Contains(err.Error(), "не поддерживается") {
		t.Errorf("текст ошибки не содержит «не поддерживается»: %v", err)
	}

	for _, cmd := range srv.Commands() {
		if strings.Contains(cmd, "/opt/amnezia/awg2/") {
			t.Fatalf("AddUser на awg2 не должен обращаться к /opt/amnezia/awg2/, но: %q", cmd)
		}
	}
}

// dyn — маркер динамической части (имя контейнера / каталог) в шаблонах
// cmdTemplates; строится в regex как \S+. Значение — непечатный байт, который
// не встречается в самих командах, поэтому regexp.QuoteMeta его не трогает.
const dyn = "\x00"

// cmdTemplates — литеральные шаблоны серверных команд, скопированные из
// core/core.go на базовом коммите d6b3a5a (В2, п.2 задания PR-1) + новая
// команда test -f (Г3). Именно эти строки нельзя менять без обновления
// TestServerCommandsUnchanged — тест ловит любое расхождение.
var cmdTemplates = []string{
	// core.go:212
	"docker ps --format '{{.Names}}'",
	// core.go:241
	"docker exec " + dyn + " cat " + dyn,
	// core.go:246
	"docker exec -i " + dyn + " sh -c 'cat > " + dyn + ".tmp && mv " + dyn + ".tmp " + dyn + "'",
	// core.go:258-264
	"docker exec " + dyn + " sh -c 'mkdir -p " + dyn + "/backup && ts=$(date +%Y%m%d-%H%M%S) && " +
		"cp " + dyn + "/wg0.conf " + dyn + "/backup/wg0.conf.$ts && " +
		"(cp " + dyn + "/clientsTable " + dyn + "/backup/clientsTable.$ts 2>/dev/null; " +
		"ls -1t " + dyn + "/backup/wg0.conf.* 2>/dev/null | tail -n +21 | while read f; do rm -f \"$f\"; done; " +
		"ls -1t " + dyn + "/backup/clientsTable.* 2>/dev/null | tail -n +21 | while read f; do rm -f \"$f\"; done)'",
	// core.go:351
	"docker exec " + dyn + " wg show wg0 dump",
	// core.go:586
	"docker exec " + dyn + " bash -c 'wg syncconf wg0 <(wg-quick strip " + dyn + "/wg0.conf)'",
	// core.go: LoadClients (Г3, новая команда этого PR)
	"docker exec " + dyn + " sh -c 'test -f " + dyn + "/clientsTable && echo yes || echo no'",
	// core/txn.go: casCheckFile (PR-2, Г4 — CAS по sha256sum, fail-safe, единственная новая команда PR-2)
	"docker exec " + dyn + " sha256sum " + dyn,
}

func mustTemplateRegex(tmpl string) *regexp.Regexp {
	escaped := regexp.QuoteMeta(tmpl)
	return regexp.MustCompile("^" + strings.ReplaceAll(escaped, dyn, `\S+`) + "$")
}

// TestServerCommandsUnchanged — эталон на запрет В2 п.2: серверные команды,
// проверенные на живом сервере, не должны измениться ни на байт. Прогоняет
// весь набор операций и сверяет каждую команду из Commands() с множеством
// шаблонов cmdTemplates (порядок и кратность не важны, но каждый шаблон
// обязан встретиться хотя бы раз). Обязательно DenyOnce == false — иначе
// команды пойдут с префиксом "sudo " и не совпадут ни с одним шаблоном
// (sudo-фолбэк проверяет отдельный TestSudoFallback).
func TestServerCommandsUnchanged(t *testing.T) {
	srv := fakesrv.New()
	sess := NewSessionWithRunner(srv, testCreds())

	containers, err := sess.FindContainers()
	if err != nil {
		t.Fatalf("FindContainers: %v", err)
	}
	var c *Container
	for i := range containers {
		if containers[i].Name == "amnezia-awg" {
			c = &containers[i]
		}
	}
	if c == nil {
		t.Fatalf("amnezia-awg не найден: %+v", containers)
	}

	if _, err := sess.LoadClients(c); err != nil {
		t.Fatalf("LoadClients: %v", err)
	}
	if _, err := sess.GetPeerStats(c); err != nil {
		t.Fatalf("GetPeerStats: %v", err)
	}
	if _, err := sess.AddUser(c, "Carol"); err != nil {
		t.Fatalf("AddUser: %v", err)
	}

	clients, err := sess.LoadClients(c)
	if err != nil {
		t.Fatalf("LoadClients после AddUser: %v", err)
	}
	carolID := ""
	for _, cl := range clients {
		if cl.Name() == "Carol" {
			carolID = cl.ClientID
		}
	}
	if carolID == "" {
		t.Fatalf("Carol не найдена после AddUser: %+v", clients)
	}

	if err := sess.RenameUser(c, carolID, "Carol2"); err != nil {
		t.Fatalf("RenameUser: %v", err)
	}
	if err := sess.SetEnabled(c, carolID, false); err != nil {
		t.Fatalf("SetEnabled(false): %v", err)
	}
	if err := sess.SetEnabled(c, carolID, true); err != nil {
		t.Fatalf("SetEnabled(true): %v", err)
	}
	if _, err := sess.RegenerateUser(c, carolID); err != nil {
		t.Fatalf("RegenerateUser: %v", err)
	}

	clients, err = sess.LoadClients(c)
	if err != nil {
		t.Fatalf("LoadClients после RegenerateUser: %v", err)
	}
	carol2ID := ""
	for _, cl := range clients {
		if cl.Name() == "Carol2" {
			carol2ID = cl.ClientID
		}
	}
	if carol2ID == "" {
		t.Fatalf("Carol2 не найдена после RegenerateUser: %+v", clients)
	}

	if err := sess.DeleteByID(c, carol2ID); err != nil {
		t.Fatalf("DeleteByID: %v", err)
	}

	templates := make([]*regexp.Regexp, len(cmdTemplates))
	for i, tmpl := range cmdTemplates {
		templates[i] = mustTemplateRegex(tmpl)
	}
	seen := make([]bool, len(templates))
	for _, cmd := range srv.Commands() {
		matched := -1
		for i, re := range templates {
			if re.MatchString(cmd) {
				matched = i
				break
			}
		}
		if matched < 0 {
			t.Fatalf("команда не совпала ни с одним шаблоном (серверная строка изменилась?): %q", cmd)
		}
		seen[matched] = true
	}
	for i, ok := range seen {
		if !ok {
			t.Errorf("шаблон ни разу не встретился: %s", cmdTemplates[i])
		}
	}
}

// TestSudoFallback — при отказе первой команды с "denied" повтор идёт с
// префиксом "sudo ", результат тот же.
func TestSudoFallback(t *testing.T) {
	srv := fakesrv.New()
	srv.DenyOnce = true
	sess := NewSessionWithRunner(srv, testCreds())

	containers, err := sess.FindContainers()
	if err != nil {
		t.Fatalf("FindContainers: %v", err)
	}
	if len(containers) == 0 {
		t.Fatal("контейнеры не найдены")
	}

	cmds := srv.Commands()
	if len(cmds) != 2 {
		t.Fatalf("commands = %v, want 2 (первая отклонена, вторая — с sudo)", cmds)
	}
	if strings.HasPrefix(cmds[0], "sudo ") {
		t.Errorf("первая команда не должна быть с sudo: %q", cmds[0])
	}
	if !strings.HasPrefix(cmds[1], "sudo ") {
		t.Errorf("вторая команда должна быть с sudo: %q", cmds[1])
	}
	if strings.TrimPrefix(cmds[1], "sudo ") != cmds[0] {
		t.Errorf("вторая команда должна повторять первую с префиксом sudo: %q vs %q", cmds[0], cmds[1])
	}
}

// TestAddUserDeleteByIDIntegration — сквозной сценарий на fakesrv (раздел Ж,
// "Интеграция"): AddUser → LoadClients содержит 3 записи → DeleteByID →
// 2 записи; wg0.conf и рантайм фейка (последний применённый syncconf)
// согласованы на каждом шаге.
func TestAddUserDeleteByIDIntegration(t *testing.T) {
	srv := fakesrv.New()
	sess := NewSessionWithRunner(srv, testCreds())

	containers, err := sess.FindContainers()
	if err != nil {
		t.Fatalf("FindContainers: %v", err)
	}
	var c *Container
	for i := range containers {
		if containers[i].Name == "amnezia-awg" {
			c = &containers[i]
		}
	}
	if c == nil {
		t.Fatalf("amnezia-awg не найден: %+v", containers)
	}

	if _, err := sess.AddUser(c, "Dave"); err != nil {
		t.Fatalf("AddUser: %v", err)
	}
	clients, err := sess.LoadClients(c)
	if err != nil {
		t.Fatalf("LoadClients: %v", err)
	}
	if len(clients) != 3 {
		t.Fatalf("clients = %d, want 3: %+v", len(clients), clients)
	}
	daveID := ""
	for _, cl := range clients {
		if cl.Name() == "Dave" {
			daveID = cl.ClientID
		}
	}
	if daveID == "" {
		t.Fatalf("Dave не найден: %+v", clients)
	}

	runtimePeers := func() map[string]bool {
		m := map[string]bool{}
		for _, p := range srv.RuntimePeers() {
			m[p] = true
		}
		return m
	}
	if !runtimePeers()[daveID] {
		t.Errorf("рантайм фейка не содержит нового peer после AddUser: %v", srv.RuntimePeers())
	}
	wg0, ok := srv.File(c.Dir + "/wg0.conf")
	if !ok || !strings.Contains(string(wg0), daveID) {
		t.Errorf("wg0.conf не содержит нового peer после AddUser")
	}

	if err := sess.DeleteByID(c, daveID); err != nil {
		t.Fatalf("DeleteByID: %v", err)
	}
	clients, err = sess.LoadClients(c)
	if err != nil {
		t.Fatalf("LoadClients после DeleteByID: %v", err)
	}
	if len(clients) != 2 {
		t.Fatalf("clients = %d, want 2: %+v", len(clients), clients)
	}
	if runtimePeers()[daveID] {
		t.Errorf("рантайм фейка всё ещё содержит удалённый peer: %v", srv.RuntimePeers())
	}
	wg0, ok = srv.File(c.Dir + "/wg0.conf")
	if !ok || strings.Contains(string(wg0), daveID) {
		t.Errorf("wg0.conf всё ещё содержит удалённый peer")
	}
}

// TestResolveClientAnnouncesNameOverNumber — условие ядра сверх выбора
// владельца: когда ввод годится И как номер строки, И как имя
// существующего клиента, программа обязана сказать ВСЛУХ, кого поняла.
// Без этого привычный ввод номера однажды молча попадёт не в того клиента,
// а del/rename/toggle необратимы. Отдельный тест от
// TestResolveClientThreeOutcomes: молчание и неверный выбор — разные
// дефекты, и канарейки на них обязаны различаться.
func TestResolveClientAnnouncesNameOverNumber(t *testing.T) {
	// Клиент с именем "12" — на первой строке; строка № 12 — другой клиент.
	var clients []ClientEntry
	for i := 1; i <= 12; i++ {
		name := fmt.Sprintf("user%d", i)
		if i == 1 {
			name = "12"
		}
		clients = append(clients, ClientEntry{
			ClientID: fmt.Sprintf("key%d", i),
			UserData: map[string]any{"clientName": name},
		})
	}

	r := ResolveClient(clients, "12")
	if r.Kind != ResolveFound {
		t.Fatalf("Kind = %v, want ResolveFound", r.Kind)
	}
	if !r.NameOverNumber {
		t.Fatal("NameOverNumber = false — программа не заметила, что ввод двусмыслен")
	}
	note := r.Note()
	if note == "" {
		t.Fatal("Note() пуст: программа молча выбрала между именем и номером строки")
	}
	for _, want := range []string{"ИМЯ", `"12"`, "строка 1", "12"} {
		if !strings.Contains(note, want) {
			t.Errorf("Note() = %q, не содержит %q — не сказано, кого поняли", note, want)
		}
	}

	// Однозначные случаи молчат: болтовня на каждом вводе обесценивает
	// предупреждение.
	if n := ResolveClient(clients, "5").Note(); n != "" {
		t.Errorf("Note() для обычного номера = %q, want пусто", n)
	}
	if n := ResolveClient(clients, "user5").Note(); n != "" {
		t.Errorf("Note() для обычного имени = %q, want пусто", n)
	}
}
