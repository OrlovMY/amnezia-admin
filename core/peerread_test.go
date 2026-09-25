package core

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"amnezia-admin/internal/fakesrv"
)

// Задание НЕЗНАНИЕ-ТРАФИК. Здесь — ФАКТ: когда клиент, записанный в
// clientsTable, отсутствует в ответе `wg show wg0 dump` боевым путём
// (настоящие Plan*/Apply/GetPeerStats поверх fakesrv), и различение трёх
// состояний показания.

// TestReadPeerThreeStates — ТЕСТ РАЗЛИЧЕНИЯ на уровне типа: «запрос не
// удался», «клиента нет в ответе» и «измерен ноль» — три разных состояния,
// и числа отдаются только измеренному.
func TestReadPeerThreeStates(t *testing.T) {
	stats := map[string]PeerStat{"zero": {}, "busy": {RxBytes: 5, TxBytes: 7}}
	for _, tc := range []struct {
		name   string
		failed bool
		id     string
		state  PeerState
		ok     bool
		rx     int64
	}{
		{"измерен ноль — настоящий ноль", false, "zero", PeerMeasured, true, 0},
		{"измерен трафик", false, "busy", PeerMeasured, true, 5},
		{"клиента нет в ответе", false, "gone", PeerAbsent, false, 0},
		{"запрос не удался — карта не читается", true, "busy", PeerFailed, false, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := ReadPeer(stats, tc.failed, tc.id)
			st, ok := r.Measured()
			if r.State != tc.state || ok != tc.ok || st.RxBytes != tc.rx {
				t.Errorf("ReadPeer = {State:%d ok:%v rx:%d}, want {State:%d ok:%v rx:%d}",
					r.State, ok, st.RxBytes, tc.state, tc.ok, tc.rx)
			}
		})
	}
	if _, ok := (PeerReading{}).Measured(); ok {
		t.Error("нулевое PeerReading{} считается измеренным — забытое поле снова станет уверенным нулём")
	}
}

// liveIDs — ключи из настоящего ответа GetPeerStats.
func liveIDs(t *testing.T, sess *Session, c *Container) map[string]PeerStat {
	t.Helper()
	stats, err := sess.GetPeerStats(c)
	if err != nil {
		t.Fatalf("GetPeerStats: %v", err)
	}
	return stats
}

// TestPeerAbsentInBattleDisabled — ФАКТ № 1: каждый ОТКЛЮЧЁННЫЙ клиент
// отсутствует в статистике. planDisableLocked вырезает peer из wg0.conf и
// применяет syncconf; запись в clientsTable остаётся. Это штатный путь, не
// авария: до правки у каждого отключённого клиента таблица печатала
// «0 B / 0 B».
func TestPeerAbsentInBattleDisabled(t *testing.T) {
	srv := fakesrv.New()
	sess := NewSessionWithRunner(srv, testCreds())
	c := awgContainer()
	clients, err := sess.LoadClients(c)
	if err != nil || len(clients) < 2 {
		t.Fatalf("LoadClients: %v, %d", err, len(clients))
	}
	victim := clients[0].ClientID
	if _, ok := liveIDs(t, sess, c)[victim]; !ok {
		t.Fatal("тест перестал что-либо проверять: клиент отсутствует в статистике ещё ДО отключения")
	}
	p, err := sess.PlanSetEnabled(c, victim, false)
	if err != nil {
		t.Fatalf("PlanSetEnabled: %v", err)
	}
	if _, err := sess.Apply(p); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	after, err := sess.LoadClients(c)
	if err != nil {
		t.Fatal(err)
	}
	if i := findClient(after, victim); i < 0 || !after[i].Disabled() {
		t.Fatal("после отключения клиента нет в clientsTable или он не отключён")
	}
	if r := ReadPeer(liveIDs(t, sess, c), false, victim); r.State != PeerAbsent {
		t.Errorf("отключённый клиент: State = %d, want PeerAbsent (%d)", r.State, PeerAbsent)
	}
}

// desyncForTest воспроизводит ФАКТ № 2 — рассинхрон после неудачного
// применения: рекей клиента subject, syncconf «применился» без стороннего
// peer'а bystander (DropPeerOnSync), verify упал, restore вернул ФАЙЛЫ, но
// его повторный syncconf упал (FailSyncconfFrom). Итог: clientsTable и
// wg0.conf прежние, а в работающем wg нет ни старого ключа subject, ни
// bystander — оба ВКЛЮЧЕНЫ и оба отсутствуют в статистике. Тот же сценарий
// проверен в TestRestoreSyncFailureReportsRuntimeMismatch с точки зрения
// транзакции; здесь — с точки зрения таблицы.
func desyncForTest(t *testing.T, srv *fakesrv.Server, sess *Session, c *Container, priorSyncs int) (subject, bystander string) {
	t.Helper()
	clients, err := sess.LoadClients(c)
	if err != nil || len(clients) < 2 {
		t.Fatalf("LoadClients: %v, %d", err, len(clients))
	}
	subject, bystander = clients[0].ClientID, clients[1].ClientID
	p, err := sess.PlanRekey(c, subject)
	if err != nil {
		t.Fatalf("PlanRekey: %v", err)
	}
	srv.DropPeerOnSync = bystander
	srv.FailSyncconfFrom = priorSyncs + 2 // счёт syncconf — с начала жизни сервера
	if _, err := sess.Apply(p); err == nil {
		t.Fatal("Apply: ожидалась ошибка — сценарий рассинхрона не воспроизвёлся")
	}
	srv.DropPeerOnSync, srv.FailSyncconfFrom = "", 0
	return subject, bystander
}

func TestPeerAbsentInBattleDesync(t *testing.T) {
	srv := fakesrv.New()
	sess := NewSessionWithRunner(srv, testCreds())
	c := awgContainer()
	subject, bystander := desyncForTest(t, srv, sess, c, 0)

	clients, err := sess.LoadClients(c)
	if err != nil {
		t.Fatal(err)
	}
	stats := liveIDs(t, sess, c)
	if len(stats) == 0 {
		t.Fatal("тест перестал что-либо проверять: статистика пуста целиком")
	}
	for _, id := range []string{subject, bystander} {
		i := findClient(clients, id)
		if i < 0 || clients[i].Disabled() {
			t.Fatalf("клиент %s: нет в clientsTable или отключён — сценарий не тот", id)
		}
		if r := ReadPeer(stats, false, id); r.State != PeerAbsent {
			t.Errorf("включённый клиент после рассинхрона: State = %d, want PeerAbsent (%d)", r.State, PeerAbsent)
		}
	}
}

// TestClassifyLastSeenTable — ТЕСТ РАЗЛИЧЕНИЯ правила карточек (GUI и
// CLI зовут одну эту функцию): пять исходов, порядок ветвей — часть
// правила. «Отключён» стоит выше «нет в ответе», ошибка — выше всего.
func TestClassifyLastSeenTable(t *testing.T) {
	boom := fmt.Errorf("wg show wg0 dump: ssh: connection reset")
	hs := map[string]string{"was": "2026-09-18 21:40", "never": "—"}
	for _, tc := range []struct {
		name     string
		hs       map[string]string
		err      error
		id       string
		disabled bool
		want     LastSeen
	}{
		{"было подключение", hs, nil, "was", false, LastSeen{State: SeenWas, When: "2026-09-18 21:40"}},
		{"в ответе, не подключался", hs, nil, "never", false, LastSeen{State: SeenNever}},
		{"включённого нет в ответе — не «не подключался»", hs, nil, "gone", false, LastSeen{State: SeenAbsent}},
		{"отключённого нет в ответе — отключён, выше «нет в ответе»", hs, nil, "gone", true, LastSeen{State: SeenDisabled}},
		{"отключённый, но в ответе есть (рассинхрон) — показываем ответ", hs, nil, "was", true, LastSeen{State: SeenWas, When: "2026-09-18 21:40"}},
		{"ошибка перевешивает карту", hs, boom, "was", false, LastSeen{State: SeenFailed}},
		{"ошибка перевешивает «отключён»", nil, boom, "gone", true, LastSeen{State: SeenFailed}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := ClassifyLastSeen(tc.hs, tc.err, tc.id, tc.disabled); got != tc.want {
				t.Errorf("ClassifyLastSeen = %+v, want %+v", got, tc.want)
			}
		})
	}
	if (LastSeen{}).State != SeenFailed {
		t.Error("незаполненный LastSeen{} — не «незнание»: забытое поле станет уверенным ответом")
	}
}

// TestClassifyLastSeenInBattle — ТЕСТ ДОЕЗДА правила карточек: исходы
// SeenDisabled и SeenAbsent возникают боевым путём (настоящее отключение и
// рассинхрон на fakesrv, настоящий GetHandshakes без ошибки).
func TestClassifyLastSeenInBattle(t *testing.T) {
	srv := fakesrv.New()
	sess := NewSessionWithRunner(srv, testCreds())
	c := awgContainer()
	clients, _ := sess.LoadClients(c)
	p, err := sess.PlanSetEnabled(c, clients[0].ClientID, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sess.Apply(p); err != nil {
		t.Fatal(err)
	}
	hs, err := sess.GetHandshakes(c)
	if err != nil {
		t.Fatal(err)
	}
	if got := ClassifyLastSeen(hs, err, clients[0].ClientID, true); got.State != SeenDisabled {
		t.Errorf("отключённый клиент: %+v, want SeenDisabled", got)
	}

	srv2 := fakesrv.New()
	sess2 := NewSessionWithRunner(srv2, testCreds())
	subject, _ := desyncForTest(t, srv2, sess2, c, 0)
	hs, err = sess2.GetHandshakes(c)
	if err != nil {
		t.Fatal(err)
	}
	if got := ClassifyLastSeen(hs, err, subject, false); got.State != SeenAbsent {
		t.Errorf("включённый клиент после рассинхрона: %+v, want SeenAbsent", got)
	}
}

// ---------- сортировка: незнание не сортируется как ноль ----------

func sortNames(cl []ClientEntry) string {
	var s []string
	for _, c := range cl {
		s = append(s, c.Name())
	}
	return strings.Join(s, ",")
}

func sortFixture() ([]ClientEntry, map[string]PeerStat) {
	mk := func(id, name string) ClientEntry {
		return ClientEntry{ClientID: id, UserData: map[string]any{"clientName": name, "creationDate": "2026-01-0" + id}}
	}
	// gone — клиента нет в ответе (неизвестно); zero — измеренный ноль;
	// busy — трафик и рукопожатие.
	clients := []ClientEntry{mk("1", "gone"), mk("2", "zero"), mk("3", "busy")}
	stats := map[string]PeerStat{
		"2": {},
		"3": {RxBytes: 500, TxBytes: 1, LastHandshake: time.Unix(1_700_000_000, 0)},
	}
	return clients, stats
}

// TestSortUnknownLastEitherDirection — ревью QA-01: сортировка трафика по
// ВОЗРАСТАНИЮ — способ искать неиспользуемых на удаление, и неизвестный
// клиент не имеет права встать первым как «наименьший трафик». Неизвестные
// — в конце при любом направлении и для обеих колонок статистики; честный
// ноль сортируется как ноль.
func TestSortUnknownLastEitherDirection(t *testing.T) {
	for _, tc := range []struct {
		col  SortColumn
		dir  SortDir
		want string
	}{
		{SortByTraffic, Asc, "zero,busy,gone"},
		{SortByTraffic, Desc, "busy,zero,gone"},
		{SortByActivityCol, Asc, "zero,busy,gone"},
		{SortByActivityCol, Desc, "busy,zero,gone"},
	} {
		clients, stats := sortFixture()
		SortClientsMultiKey(clients, stats, tc.col, tc.dir, SortNone, Asc)
		if got := sortNames(clients); got != tc.want {
			t.Errorf("колонка %d, направление %d: %s, want %s", tc.col, tc.dir, got, tc.want)
		}
	}
	// Вторичный ключ по трафику — то же правило.
	clients, stats := sortFixture()
	for i := range clients {
		clients[i].UserData["creationDate"] = "same"
	}
	SortClientsMultiKey(clients, stats, SortByCreated, Asc, SortByTraffic, Asc)
	if got := sortNames(clients); got != "zero,busy,gone" {
		t.Errorf("вторичный ключ трафик ↑: %s, want zero,busy,gone", got)
	}
	// SortByActivity (CLI): неизвестный — после «не подключался».
	clients, stats = sortFixture()
	SortByActivity(clients, stats)
	if got := sortNames(clients); got != "busy,zero,gone" {
		t.Errorf("SortByActivity: %s, want busy,zero,gone", got)
	}
}

// TestSortUnknownLastInBattle — ТЕСТ ДОЕЗДА сортировки: неизвестность
// возникает боевым путём (рассинхрон), статистика — настоящий GetPeerStats;
// сортировка трафика по возрастанию ставит отсутствующих в конец.
func TestSortUnknownLastInBattle(t *testing.T) {
	srv := fakesrv.New()
	sess := NewSessionWithRunner(srv, testCreds())
	c := awgContainer()
	add, err := sess.PlanAddUser(c, "Carol")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sess.Apply(add); err != nil {
		t.Fatal(err)
	}
	subject, bystander := desyncForTest(t, srv, sess, c, 1)
	clients, err := sess.LoadClients(c)
	if err != nil {
		t.Fatal(err)
	}
	stats := liveIDs(t, sess, c)
	SortClientsMultiKey(clients, stats, SortByTraffic, Asc, SortNone, Asc)
	if clients[0].Name() != "Carol" {
		t.Errorf("трафик ↑: первым стоит %q — клиент с неизвестным трафиком выдан за «наименьший»; порядок %s",
			clients[0].Name(), sortNames(clients))
	}
	for _, cl := range clients[1:] {
		if cl.ClientID != subject && cl.ClientID != bystander {
			t.Errorf("после Carol ожидались только отсутствующие в статистике, а стоит %q", cl.Name())
		}
	}
}
