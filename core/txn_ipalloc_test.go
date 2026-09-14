package core

// Тесты Д (обязательные имена) — PR-3: единый аллокатор IP с резервом
// отключённых (Г1), отказ при включении с занятым резервом (Г2), rekey
// сохраняет IP и отказывает отключённому (Г3). Через Session/fakesrv, без сети.
//
// Все пять тестов в этом файле обязаны падать на fe5e013:
//   - TestReservedIPNotReused: на fe5e013 планAddUserLocked звал nextFreeIP,
//     который не знает о userData.allowedIP отключённых — Carol получила бы
//     .3 (резерв Bob), тест ожидает .4.
//   - TestEnableRefusesNamesHolder: на fe5e013 planEnableLocked дописывал
//     блок peer'а без всякой проверки занятости — Apply прошёл бы успешно
//     (дубль AllowedIPs), тест ожидает отказ.
//   - TestRekeyKeepsIP: проходит и на fe5e013 (rekey уже сохранял IP, если
//     peer был в wg0.conf) — добавлен для полноты обязательного списка Д и
//     как регресс на дальнейшую правку Г3; для доказательства регресса см.
//     TestRekeyDisabledRefused/TestRekeyMissingPeerRefused ниже.
//   - TestRekeyDisabledRefused: на fe5e013 RegenerateUser отключённого без
//     peer'а в wg0.conf выделял НОВЫЙ IP и тихо включал пользователя
//     (core.go:889-918 на d6b3a5a, перенесено в planRekeyLocked к fe5e013);
//     тест ожидает отказ "сначала включите" ДО этого выделения.
//   - TestRekeyMissingPeerRefused: на fe5e013 та же ветка "peer'а нет —
//     выделяем новый IP" отрабатывала и для АКТИВНОГО, но рассинхронизиро-
//     ванного клиента; тест ожидает отказ, а не новый IP.
//
// Прогон, подтверждающий падение на fe5e013, — в отчёте и review-request.

import (
	"encoding/json"
	"strings"
	"testing"

	"amnezia-admin/internal/fakesrv"
)

// buildIPAllocServer — детерминированный fakesrv.Server для тестов этого
// файла: собственный wg0.conf и clientsTable (не fakesrv.New(), у которого
// оба peer'а активны и оба присутствуют в конфиге — здесь нужны разные
// комбинации "активен"/"отключён с резервом"/"сирота").
func buildIPAllocServer(t *testing.T, wg0 string, clients []ClientEntry) (*fakesrv.Server, *Container) {
	t.Helper()
	c := awgContainer()
	srv := fakesrv.New()
	srv.SetFile(c.Dir+"/wg0.conf", []byte(wg0))
	tbl, err := json.MarshalIndent(clients, "", "    ")
	if err != nil {
		t.Fatalf("marshal clientsTable: %v", err)
	}
	srv.SetFile(c.Dir+"/clientsTable", tbl)
	return srv, c
}

func serverPrivKey(t *testing.T) string {
	t.Helper()
	priv, _, err := genKey()
	if err != nil {
		t.Fatalf("genKey: %v", err)
	}
	return priv
}

// clientByName находит ClientID клиента по имени в живом сервере (после
// мутации) — нужен как subjectID для assertOthersUntouched.
func clientByName(t *testing.T, srv *fakesrv.Server, c *Container, name string) string {
	t.Helper()
	sess := NewSessionWithRunner(srv, testCreds())
	clients, err := sess.LoadClients(c)
	if err != nil {
		t.Fatalf("LoadClients: %v", err)
	}
	for _, cl := range clients {
		if cl.Name() == name {
			return cl.ClientID
		}
	}
	t.Fatalf("клиент %q не найден после мутации", name)
	return ""
}

// ---------- TestReservedIPNotReused (Г1) ----------

func TestReservedIPNotReused(t *testing.T) {
	priv := serverPrivKey(t)

	t.Run("один резерв — новый получает следующий свободный", func(t *testing.T) {
		wg0 := "[Interface]\nPrivateKey = " + priv + "\nAddress = 10.8.1.1/24\nListenPort = 51820\n\n" +
			"[Peer]\nPublicKey = ALICEPUB\nPresharedKey = ALICEPSK\nAllowedIPs = 10.8.1.2/32\n"
		clients := []ClientEntry{
			{ClientID: "ALICEPUB", UserData: map[string]any{"clientName": "Alice", "creationDate": "2020-01-01T00:00:00Z"}},
			{ClientID: "BOBPUB", UserData: map[string]any{
				"clientName": "Bob", "creationDate": "2020-01-01T00:00:00Z",
				"disabled": true, "disabledAt": "2020-02-01T00:00:00Z",
				"psk": "BOBPSK", "allowedIP": "10.8.1.3/32",
			}},
		}
		srv, c := buildIPAllocServer(t, wg0, clients)
		beforeWG, _ := srv.File(c.Dir + "/wg0.conf")
		beforeTbl, _ := srv.File(c.Dir + "/clientsTable")
		sess := NewSessionWithRunner(srv, testCreds())

		newUser, err := sess.AddUser(c, "Carol")
		if err != nil {
			t.Fatalf("AddUser: %v", err)
		}
		if newUser.IP != "10.8.1.4" {
			t.Errorf("IP = %q, want 10.8.1.4 (резерв Bob .3 не должен быть выдан)", newUser.IP)
		}

		carolID := clientByName(t, srv, c, "Carol")
		before := snapshotFiles(c, beforeWG, beforeTbl)
		assertOthersUntouched(t, before, srv, carolID)
	})

	t.Run("два резерва — новый получает адрес после обоих", func(t *testing.T) {
		wg0 := "[Interface]\nPrivateKey = " + priv + "\nAddress = 10.8.1.1/24\nListenPort = 51820\n\n" +
			"[Peer]\nPublicKey = ALICEPUB\nPresharedKey = ALICEPSK\nAllowedIPs = 10.8.1.2/32\n"
		clients := []ClientEntry{
			{ClientID: "ALICEPUB", UserData: map[string]any{"clientName": "Alice", "creationDate": "2020-01-01T00:00:00Z"}},
			{ClientID: "BOBPUB", UserData: map[string]any{
				"clientName": "Bob", "creationDate": "2020-01-01T00:00:00Z",
				"disabled": true, "disabledAt": "2020-02-01T00:00:00Z",
				"psk": "BOBPSK", "allowedIP": "10.8.1.3/32",
			}},
			{ClientID: "DAVEPUB", UserData: map[string]any{
				"clientName": "Dave", "creationDate": "2020-01-01T00:00:00Z",
				"disabled": true, "disabledAt": "2020-02-01T00:00:00Z",
				"psk": "DAVEPSK", "allowedIP": "10.8.1.4/32",
			}},
		}
		srv, c := buildIPAllocServer(t, wg0, clients)
		beforeWG, _ := srv.File(c.Dir + "/wg0.conf")
		beforeTbl, _ := srv.File(c.Dir + "/clientsTable")
		sess := NewSessionWithRunner(srv, testCreds())

		newUser, err := sess.AddUser(c, "Erin")
		if err != nil {
			t.Fatalf("AddUser: %v", err)
		}
		if newUser.IP != "10.8.1.5" {
			t.Errorf("IP = %q, want 10.8.1.5 (оба резерва .3 и .4 должны быть пропущены)", newUser.IP)
		}

		erinID := clientByName(t, srv, c, "Erin")
		before := snapshotFiles(c, beforeWG, beforeTbl)
		assertOthersUntouched(t, before, srv, erinID)
	})
}

// ---------- TestEnableRefusesNamesHolder (Г2) ----------

func TestEnableRefusesNamesHolder(t *testing.T) {
	priv := serverPrivKey(t)

	t.Run("владелец известен по имени", func(t *testing.T) {
		wg0 := "[Interface]\nPrivateKey = " + priv + "\nAddress = 10.8.1.1/24\nListenPort = 51820\n\n" +
			"[Peer]\nPublicKey = CAROLPUB\nPresharedKey = CAROLPSK\nAllowedIPs = 10.8.1.3/32\n"
		clients := []ClientEntry{
			{ClientID: "BOBPUB", UserData: map[string]any{
				"clientName": "Bob", "creationDate": "2020-01-01T00:00:00Z",
				"disabled": true, "disabledAt": "2020-02-01T00:00:00Z",
				"psk": "BOBPSK", "allowedIP": "10.8.1.3/32",
			}},
			{ClientID: "CAROLPUB", UserData: map[string]any{"clientName": "Carol", "creationDate": "2020-01-01T00:00:00Z"}},
		}
		srv, c := buildIPAllocServer(t, wg0, clients)
		sess := NewSessionWithRunner(srv, testCreds())

		before := len(srv.Commands())
		err := sess.SetEnabled(c, "BOBPUB", true)
		if err == nil {
			t.Fatal("SetEnabled(true): ожидался отказ — IP занят Carol")
		}
		if !strings.Contains(err.Error(), "Carol") {
			t.Errorf("ошибка не содержит имя владельца Carol: %v", err)
		}
		if !strings.Contains(err.Error(), "10.8.1.3") {
			t.Errorf("ошибка не содержит адрес 10.8.1.3: %v", err)
		}
		for _, cmd := range srv.Commands()[before:] {
			if strings.Contains(cmd, "cat > ") {
				t.Errorf("отказ при включении не должен был писать файлы, но: %q", cmd)
			}
			if strings.Contains(cmd, "syncconf") {
				t.Errorf("отказ при включении не должен был звать syncconf, но: %q", cmd)
			}
		}
	})

	t.Run("владелец — сирота (нет в clientsTable)", func(t *testing.T) {
		wg0 := "[Interface]\nPrivateKey = " + priv + "\nAddress = 10.8.1.1/24\nListenPort = 51820\n\n" +
			"[Peer]\nPublicKey = ORPHANPUB\nPresharedKey = ORPHANPSK\nAllowedIPs = 10.8.1.3/32\n"
		clients := []ClientEntry{
			{ClientID: "BOBPUB", UserData: map[string]any{
				"clientName": "Bob", "creationDate": "2020-01-01T00:00:00Z",
				"disabled": true, "disabledAt": "2020-02-01T00:00:00Z",
				"psk": "BOBPSK", "allowedIP": "10.8.1.3/32",
			}},
		}
		srv, c := buildIPAllocServer(t, wg0, clients)
		sess := NewSessionWithRunner(srv, testCreds())

		err := sess.SetEnabled(c, "BOBPUB", true)
		if err == nil {
			t.Fatal("SetEnabled(true): ожидался отказ — IP занят сиротой")
		}
		if !strings.Contains(err.Error(), "ORPHANPUB") {
			t.Errorf("ошибка не содержит PublicKey сироты: %v", err)
		}
	})
}

// ---------- TestRekeyKeepsIP / TestRekeyDisabledRefused / TestRekeyMissingPeerRefused (Г3) ----------

func TestRekeyKeepsIP(t *testing.T) {
	srv := fakesrv.New()
	c := awgContainer()
	sess := NewSessionWithRunner(srv, testCreds())

	clientsBefore, err := sess.LoadClients(c)
	if err != nil {
		t.Fatalf("LoadClients: %v", err)
	}
	var aliceID string
	for _, cl := range clientsBefore {
		if cl.Name() == "Alice" {
			aliceID = cl.ClientID
		}
	}
	if aliceID == "" {
		t.Fatal("Alice не найдена в дефолтном фейке")
	}
	beforeWG, _ := srv.File(c.Dir + "/wg0.conf")
	beforeTbl, _ := srv.File(c.Dir + "/clientsTable")

	newUser, err := sess.RegenerateUser(c, aliceID)
	if err != nil {
		t.Fatalf("RegenerateUser: %v", err)
	}
	if newUser.IP != "10.8.1.2" {
		t.Errorf("IP = %q, want 10.8.1.2 (прежний адрес Alice)", newUser.IP)
	}

	wgNow, _ := srv.File(c.Dir + "/wg0.conf")
	conf := parseWgConf(string(wgNow))
	var matches int
	var newID string
	for _, p := range conf.peers {
		if p["AllowedIPs"] == "10.8.1.2/32" {
			matches++
			newID = p["PublicKey"]
		}
		if p["PublicKey"] == aliceID {
			t.Errorf("старый PublicKey Alice всё ещё в wg0.conf: %s", aliceID)
		}
	}
	if matches != 1 {
		t.Errorf("блоков с AllowedIPs=10.8.1.2/32 в wg0.conf: %d, want 1", matches)
	}
	if newID == "" || newID == aliceID {
		t.Errorf("новый PublicKey Alice некорректен: %q", newID)
	}

	before := snapshotFiles(c, beforeWG, beforeTbl)
	assertOthersUntouched(t, before, srv, aliceID, newID)
}

func TestRekeyDisabledRefused(t *testing.T) {
	priv := serverPrivKey(t)
	wg0 := "[Interface]\nPrivateKey = " + priv + "\nAddress = 10.8.1.1/24\nListenPort = 51820\n"
	clients := []ClientEntry{
		{ClientID: "BOBPUB", UserData: map[string]any{
			"clientName": "Bob", "creationDate": "2020-01-01T00:00:00Z",
			"disabled": true, "disabledAt": "2020-02-01T00:00:00Z",
			"psk": "BOBPSK", "allowedIP": "10.8.1.3/32",
		}},
	}
	srv, c := buildIPAllocServer(t, wg0, clients)
	sess := NewSessionWithRunner(srv, testCreds())

	before := len(srv.Commands())
	_, err := sess.RegenerateUser(c, "BOBPUB")
	if err == nil {
		t.Fatal("RegenerateUser: ожидался отказ для отключённого клиента")
	}
	if !strings.Contains(err.Error(), "сначала включите") {
		t.Errorf("текст ошибки не про «сначала включите»: %v", err)
	}
	for _, cmd := range srv.Commands()[before:] {
		if strings.Contains(cmd, "cat > ") {
			t.Errorf("rekey отключённого не должен был писать файлы, но: %q", cmd)
		}
		if strings.Contains(cmd, "syncconf") {
			t.Errorf("rekey отключённого не должен был звать syncconf, но: %q", cmd)
		}
		if strings.Contains(cmd, "mkdir -p") {
			t.Errorf("rekey отключённого не должен был делать backup, но: %q", cmd)
		}
	}

	clientsAfter, err := sess.LoadClients(c)
	if err != nil {
		t.Fatalf("LoadClients после отказа: %v", err)
	}
	idx := findClient(clientsAfter, "BOBPUB")
	if idx < 0 {
		t.Fatal("запись Bob пропала")
	}
	if !clientsAfter[idx].Disabled() {
		t.Error("запись Bob должна остаться disabled после отказа")
	}
}

func TestRekeyMissingPeerRefused(t *testing.T) {
	priv := serverPrivKey(t)
	// Alice активна по таблице, но её peer'а нет в wg0.conf — рассинхрон.
	wg0 := "[Interface]\nPrivateKey = " + priv + "\nAddress = 10.8.1.1/24\nListenPort = 51820\n"
	clients := []ClientEntry{
		{ClientID: "ALICEPUB", UserData: map[string]any{"clientName": "Alice", "creationDate": "2020-01-01T00:00:00Z"}},
	}
	srv, c := buildIPAllocServer(t, wg0, clients)
	sess := NewSessionWithRunner(srv, testCreds())

	before := len(srv.Commands())
	_, err := sess.RegenerateUser(c, "ALICEPUB")
	if err == nil {
		t.Fatal("RegenerateUser: ожидался отказ (peer отсутствует в wg0.conf)")
	}
	if !strings.Contains(err.Error(), "рассинхронизированы") {
		t.Errorf("текст ошибки не про рассинхронизацию: %v", err)
	}
	for _, cmd := range srv.Commands()[before:] {
		if strings.Contains(cmd, "cat > ") {
			t.Errorf("отказ по рассинхрону не должен был писать файлы, но: %q", cmd)
		}
	}
}
