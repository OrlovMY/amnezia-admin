package core

// Тесты части А PR-2 (раздел Д задания): транзакция Apply (CAS→backup→
// запись→verify→restore), мьютекс и dry-run (Plan.Diff без записи).
// Общие для всех тестов данной таблицы — assertOthersUntouched (I1) и
// snapshotFiles (снимок "до" для сравнения с живым *fakesrv.Server "после").

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"

	"amnezia-admin/internal/fakesrv"
)

// snapshotFiles строит лёгкий *fakesrv.Server, хранящий только сырые байты
// wg0.conf/clientsTable — снимок состояния "до" для последующего сравнения
// с живым сервером "после" через assertOthersUntouched. Остальные поля
// (Names, peers и т.п.) для сравнения файлов не нужны.
func snapshotFiles(c *Container, wg, tbl []byte) *fakesrv.Server {
	snap := &fakesrv.Server{}
	snap.SetFile(c.Dir+"/wg0.conf", wg)
	if tbl != nil {
		snap.SetFile(c.Dir+"/clientsTable", tbl)
	}
	return snap
}

// assertOthersUntouched (Г5, инвариант I1) — доступ прочих пользователей
// меняют только операции над НИМИ САМИМИ. Для wg0.conf: удаляем subjectID
// (уже проверенным removePeerFromConf) из обоих снимков и сравниваем
// остаток байт в байт. Для clientsTable: сравниваем JSON каждой записи,
// кроме subjectID, и убеждаемся, что ни одна чужая запись не появилась и
// не пропала.
func assertOthersUntouched(t *testing.T, before, after *fakesrv.Server, subjectID string) {
	t.Helper()
	c := awgContainer()

	beforeWG, _ := before.File(c.Dir + "/wg0.conf")
	afterWG, _ := after.File(c.Dir + "/wg0.conf")
	beforeRest, err := removePeerFromConf(string(beforeWG), subjectID)
	if err != nil && subjectID != "" {
		t.Fatalf("assertOthersUntouched: removePeerFromConf(before): %v", err)
	}
	afterRest, err := removePeerFromConf(string(afterWG), subjectID)
	if err != nil && subjectID != "" {
		t.Fatalf("assertOthersUntouched: removePeerFromConf(after): %v", err)
	}
	if subjectID == "" {
		beforeRest, afterRest = string(beforeWG), string(afterWG)
	}
	if beforeRest != afterRest {
		t.Errorf("assertOthersUntouched (I1): чужие peer'ы в wg0.conf изменились:\nбыло:  %q\nстало: %q", beforeRest, afterRest)
	}

	beforeTbl, _ := before.File(c.Dir + "/clientsTable")
	afterTbl, _ := after.File(c.Dir + "/clientsTable")
	beforeClients, err := parseClientsTable(beforeTbl)
	if err != nil {
		t.Fatalf("assertOthersUntouched: parseClientsTable(before): %v", err)
	}
	afterClients, err := parseClientsTable(afterTbl)
	if err != nil {
		t.Fatalf("assertOthersUntouched: parseClientsTable(after): %v", err)
	}

	beforeByID := map[string][]byte{}
	for _, cl := range beforeClients {
		if cl.ClientID == subjectID {
			continue
		}
		b, _ := json.Marshal(cl)
		beforeByID[cl.ClientID] = b
	}
	seen := map[string]bool{}
	for _, cl := range afterClients {
		if cl.ClientID == subjectID {
			continue
		}
		b, _ := json.Marshal(cl)
		seen[cl.ClientID] = true
		want, ok := beforeByID[cl.ClientID]
		if !ok {
			t.Errorf("assertOthersUntouched (I1): в clientsTable появилась посторонняя запись %q", cl.ClientID)
			continue
		}
		if string(b) != string(want) {
			t.Errorf("assertOthersUntouched (I1): запись clientsTable %q изменилась:\nбыло:  %s\nстало: %s", cl.ClientID, want, b)
		}
	}
	for id := range beforeByID {
		if !seen[id] {
			t.Errorf("assertOthersUntouched (I1): посторонняя запись clientsTable %q исчезла", id)
		}
	}
}

// TestSyncconfFailureRestoresBackup — FailSyncconf задан → AddUser
// откатывает файлы к состоянию до, возвращает ошибку "состояние
// восстановлено", NewUser == nil.
func TestSyncconfFailureRestoresBackup(t *testing.T) {
	srv := fakesrv.New()
	sess := NewSessionWithRunner(srv, testCreds())
	c := awgContainer()

	beforeWG, ok := srv.File(c.Dir + "/wg0.conf")
	if !ok {
		t.Fatal("wg0.conf отсутствует в дефолтном фейке")
	}
	beforeTbl, ok := srv.File(c.Dir + "/clientsTable")
	if !ok {
		t.Fatal("clientsTable отсутствует в дефолтном фейке")
	}

	srv.FailSyncconf = fmt.Errorf("wg: syncconf: I/O error")

	newUser, err := sess.AddUser(c, "Carol")
	if err == nil {
		t.Fatal("AddUser: ожидалась ошибка (FailSyncconf)")
	}
	if !strings.Contains(err.Error(), "состояние восстановлено") {
		t.Errorf("текст ошибки не содержит «состояние восстановлено»: %v", err)
	}
	if newUser != nil {
		t.Errorf("NewUser = %+v, want nil", newUser)
	}

	afterWG, _ := srv.File(c.Dir + "/wg0.conf")
	if !bytes.Equal(afterWG, beforeWG) {
		t.Errorf("wg0.conf не восстановлен байт в байт:\nбыло:  %s\nстало: %s", beforeWG, afterWG)
	}
	afterTbl, _ := srv.File(c.Dir + "/clientsTable")
	if !bytes.Equal(afterTbl, beforeTbl) {
		t.Errorf("clientsTable не восстановлена байт в байт:\nбыло:  %s\nстало: %s", beforeTbl, afterTbl)
	}

	writeCount, syncCount := 0, 0
	for _, cmd := range srv.Commands() {
		if strings.Contains(cmd, "cat > ") {
			writeCount++
		}
		if strings.Contains(cmd, "syncconf") {
			syncCount++
		}
	}
	if writeCount != 4 {
		t.Errorf("cat > встретилось %d раз(а), want 4 (2 записи + 2 отката)", writeCount)
	}
	if syncCount != 2 {
		t.Errorf("syncconf встретился %d раз(а), want 2 (попытка применить + повторный при откате)", syncCount)
	}

	assertOthersUntouched(t, snapshotFiles(c, beforeWG, beforeTbl), srv, "")
}

// TestVerifyMissingPeerRestores — syncconf "применился" без ошибки, но
// рантайм не включил новый peer (DropPeerOnSync) → verify падает → restore
// → состояние до; ошибка возвращена.
func TestVerifyMissingPeerRestores(t *testing.T) {
	srv := fakesrv.New()
	sess := NewSessionWithRunner(srv, testCreds())
	c := awgContainer()

	beforeWG, _ := srv.File(c.Dir + "/wg0.conf")
	beforeTbl, _ := srv.File(c.Dir + "/clientsTable")

	plan, err := sess.PlanAddUser(c, "Carol")
	if err != nil {
		t.Fatalf("PlanAddUser: %v", err)
	}

	beforeKeys := peerPubKeysFromBytes(plan.wgBefore)
	newKey := ""
	for k := range peerPubKeysFromBytes(plan.wgAfter) {
		if !beforeKeys[k] {
			newKey = k
		}
	}
	if newKey == "" {
		t.Fatal("не удалось определить новый ключ Carol из плана")
	}
	srv.DropPeerOnSync = newKey

	if _, err := sess.Apply(plan); err == nil {
		t.Fatal("Apply: ожидалась ошибка (verify: peer не поднялся на сервере)")
	}

	afterWG, _ := srv.File(c.Dir + "/wg0.conf")
	afterTbl, _ := srv.File(c.Dir + "/clientsTable")
	if !bytes.Equal(afterWG, beforeWG) {
		t.Errorf("wg0.conf не восстановлен байт в байт")
	}
	if !bytes.Equal(afterTbl, beforeTbl) {
		t.Errorf("clientsTable не восстановлена байт в байт")
	}

	assertOthersUntouched(t, snapshotFiles(c, beforeWG, beforeTbl), srv, "")
}

// TestDryRunWritesNothing — Plan* только читает: Diff() показывает будущее
// изменение, но ни одной команды записи/sync/backup на сервер не уходит.
func TestDryRunWritesNothing(t *testing.T) {
	assertNoWrites := func(t *testing.T, srv *fakesrv.Server) {
		t.Helper()
		for _, cmd := range srv.Commands() {
			if strings.Contains(cmd, "cat > ") {
				t.Errorf("dry-run не должен писать: %q", cmd)
			}
			if strings.Contains(cmd, "syncconf") {
				t.Errorf("dry-run не должен вызывать syncconf: %q", cmd)
			}
			if strings.Contains(cmd, "backup") {
				t.Errorf("dry-run не должен делать backup: %q", cmd)
			}
		}
	}

	t.Run("PlanAddUser", func(t *testing.T) {
		srv := fakesrv.New()
		sess := NewSessionWithRunner(srv, testCreds())
		c := awgContainer()

		plan, err := sess.PlanAddUser(c, "Carol")
		if err != nil {
			t.Fatalf("PlanAddUser: %v", err)
		}
		wgDiff, tblDiff := plan.Diff()
		if !strings.Contains(wgDiff, "+PublicKey") {
			t.Errorf("wgDiff не содержит +PublicKey: %q", wgDiff)
		}
		if !strings.Contains(wgDiff, "+AllowedIPs") {
			t.Errorf("wgDiff не содержит +AllowedIPs: %q", wgDiff)
		}
		if tblDiff == "" {
			t.Error("tblDiff пуст, ожидалась новая запись")
		}
		assertNoWrites(t, srv)
	})

	t.Run("PlanDelete", func(t *testing.T) {
		srv := fakesrv.New()
		sess := NewSessionWithRunner(srv, testCreds())
		c := awgContainer()

		clients, err := sess.LoadClients(c)
		if err != nil || len(clients) == 0 {
			t.Fatalf("LoadClients: %v, %+v", err, clients)
		}
		plan, err := sess.PlanDelete(c, clients[0].ClientID)
		if err != nil {
			t.Fatalf("PlanDelete: %v", err)
		}
		wgDiff, tblDiff := plan.Diff()
		if wgDiff == "" {
			t.Error("wgDiff пуст, ожидалось удаление peer'а")
		}
		if tblDiff == "" {
			t.Error("tblDiff пуст, ожидалось удаление записи")
		}
		assertNoWrites(t, srv)
	})

	t.Run("PlanSetEnabled(false)", func(t *testing.T) {
		srv := fakesrv.New()
		sess := NewSessionWithRunner(srv, testCreds())
		c := awgContainer()

		clients, err := sess.LoadClients(c)
		if err != nil || len(clients) == 0 {
			t.Fatalf("LoadClients: %v, %+v", err, clients)
		}
		plan, err := sess.PlanSetEnabled(c, clients[0].ClientID, false)
		if err != nil {
			t.Fatalf("PlanSetEnabled(false): %v", err)
		}
		wgDiff, tblDiff := plan.Diff()
		if wgDiff == "" {
			t.Error("wgDiff пуст, ожидалось удаление peer'а из wg0.conf")
		}
		if tblDiff == "" {
			t.Error("tblDiff пуст, ожидалась пометка disabled")
		}
		assertNoWrites(t, srv)
	})
}

// TestParallelAddUsersDistinctIP — параллельные AddUser на одном Session
// сериализуются мьютексом (I5): все успешны, IP различны, wg0.conf и
// clientsTable содержат всех новых пользователей. Запускать с -race.
func TestParallelAddUsersDistinctIP(t *testing.T) {
	srv := fakesrv.New()
	sess := NewSessionWithRunner(srv, testCreds())
	c := awgContainer()

	const n = 8
	names := make([]string, n)
	for i := range names {
		names[i] = fmt.Sprintf("Parallel%d", i)
	}

	results := make([]*NewUser, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i], errs[i] = sess.AddUser(c, names[i])
		}(i)
	}
	wg.Wait()

	ips := map[string]bool{}
	for i, err := range errs {
		if err != nil {
			t.Fatalf("AddUser(%s): %v", names[i], err)
		}
		if ips[results[i].IP] {
			t.Errorf("повторный IP %q у %s", results[i].IP, names[i])
		}
		ips[results[i].IP] = true
	}

	clients, err := sess.LoadClients(c)
	if err != nil {
		t.Fatalf("LoadClients: %v", err)
	}
	if len(clients) != 2+n {
		t.Fatalf("clientsTable содержит %d записей, want %d (2 исходных + %d новых)", len(clients), 2+n, n)
	}
	present := map[string]bool{}
	for _, cl := range clients {
		present[cl.Name()] = true
	}
	for _, name := range names {
		if !present[name] {
			t.Errorf("имя %q отсутствует в clientsTable", name)
		}
	}

	wg0, ok := srv.File(c.Dir + "/wg0.conf")
	if !ok {
		t.Fatal("wg0.conf отсутствует")
	}
	peers := parseWgConf(string(wg0)).peers
	if len(peers) != 2+n {
		t.Errorf("wg0.conf содержит %d peer'ов, want %d", len(peers), 2+n)
	}
}

// TestRenameDoesNotSync — RenameUser не пишет wg0.conf и не вызывает
// syncconf (переименование не должно рвать соединения).
func TestRenameDoesNotSync(t *testing.T) {
	srv := fakesrv.New()
	sess := NewSessionWithRunner(srv, testCreds())
	c := awgContainer()

	clients, err := sess.LoadClients(c)
	if err != nil || len(clients) == 0 {
		t.Fatalf("LoadClients: %v, %+v", err, clients)
	}
	subject := clients[0].ClientID

	beforeWG, ok := srv.File(c.Dir + "/wg0.conf")
	if !ok {
		t.Fatal("wg0.conf отсутствует")
	}
	beforeTbl, ok := srv.File(c.Dir + "/clientsTable")
	if !ok {
		t.Fatal("clientsTable отсутствует")
	}

	if err := sess.RenameUser(c, subject, "NewName123"); err != nil {
		t.Fatalf("RenameUser: %v", err)
	}

	afterWG, _ := srv.File(c.Dir + "/wg0.conf")
	if !bytes.Equal(beforeWG, afterWG) {
		t.Error("wg0.conf изменился при RenameUser")
	}
	for _, cmd := range srv.Commands() {
		if strings.Contains(cmd, "syncconf") {
			t.Errorf("RenameUser не должен вызывать syncconf: %q", cmd)
		}
		if strings.Contains(cmd, "cat > ") && strings.Contains(cmd, "wg0.conf") {
			t.Errorf("RenameUser не должен писать wg0.conf: %q", cmd)
		}
	}

	assertOthersUntouched(t, snapshotFiles(c, beforeWG, beforeTbl), srv, subject)
}
