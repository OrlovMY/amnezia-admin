package core

import (
	"testing"

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
func desyncForTest(t *testing.T, srv *fakesrv.Server, sess *Session, c *Container) (subject, bystander string) {
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
	srv.FailSyncconfFrom = 2
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
	subject, bystander := desyncForTest(t, srv, sess, c)

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
