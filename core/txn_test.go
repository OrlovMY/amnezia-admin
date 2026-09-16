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
// меняют только операции над НИМИ САМИМИ. subjectIDs — ClientID тех, над
// кем была мутация (их самих сравнение не касается; пустая строка в списке
// игнорируется). Для wg0.conf: удаляем все subjectIDs (уже проверенным
// removePeerFromConf) из обоих снимков и сравниваем остаток байт в байт.
// Для clientsTable: сравниваем JSON каждой записи, кроме subjectIDs, и
// убеждаемся, что ни одна чужая запись не появилась и не пропала.
// Вариативность (BE-01/review changes-requested, Medium): один вызов
// исключает произвольное число субъектов — нужно для
// TestParallelAddUsersDistinctIP (8 новых пользователей разом), не только
// для одиночных мутаций.
func assertOthersUntouched(t *testing.T, before, after *fakesrv.Server, subjectIDs ...string) {
	t.Helper()
	c := awgContainer()

	ids := map[string]bool{}
	for _, id := range subjectIDs {
		if id != "" {
			ids[id] = true
		}
	}

	beforeWG, _ := before.File(c.Dir + "/wg0.conf")
	afterWG, _ := after.File(c.Dir + "/wg0.conf")
	beforeRest, afterRest := string(beforeWG), string(afterWG)
	for id := range ids {
		var err error
		beforeRest, err = removePeerFromConf(beforeRest, id)
		if err != nil {
			t.Fatalf("assertOthersUntouched: removePeerFromConf(before, %q): %v", id, err)
		}
		afterRest, err = removePeerFromConf(afterRest, id)
		if err != nil {
			t.Fatalf("assertOthersUntouched: removePeerFromConf(after, %q): %v", id, err)
		}
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
		if ids[cl.ClientID] {
			continue
		}
		b, _ := json.Marshal(cl)
		beforeByID[cl.ClientID] = b
	}
	seen := map[string]bool{}
	for _, cl := range afterClients {
		if ids[cl.ClientID] {
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
	// Строго ветка (а) restore(): файлы и рантайм совпали с прочитанным
	// состоянием (syncconf ни разу не менял рантайм — он проваливался с
	// самого первого вызова, поэтому проверять после отката нечего сверх
	// исходного). Проверяем точную подстроку «восстановлено и проверено», а
	// не более широкую «состояние восстановлено» — последняя совпала бы по
	// префиксу и с текстом ветки (б) («…применить их не удалось… исходная
	// причина…»), поэтому не различает ветки (review changes-requested,
	// круг 2, Low).
	if !strings.Contains(err.Error(), "восстановлено и проверено") {
		t.Errorf("текст ошибки не содержит «восстановлено и проверено» (ветка (а)): %v", err)
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
// clientsTable содержат всех новых пользователей; исходные два пользователя
// (I1) не задеты ни байтом (review changes-requested, Medium — раньше
// проверялось только "не упало", но не то, что чужие записи остались
// нетронутыми при параллельной нагрузке). Запускать с -race.
func TestParallelAddUsersDistinctIP(t *testing.T) {
	srv := fakesrv.New()
	sess := NewSessionWithRunner(srv, testCreds())
	c := awgContainer()

	beforeWG, ok := srv.File(c.Dir + "/wg0.conf")
	if !ok {
		t.Fatal("wg0.conf отсутствует")
	}
	beforeTbl, ok := srv.File(c.Dir + "/clientsTable")
	if !ok {
		t.Fatal("clientsTable отсутствует")
	}

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
	byName := map[string]string{}
	for _, cl := range clients {
		present[cl.Name()] = true
		byName[cl.Name()] = cl.ClientID
	}
	newIDs := make([]string, 0, n)
	for _, name := range names {
		if !present[name] {
			t.Errorf("имя %q отсутствует в clientsTable", name)
			continue
		}
		newIDs = append(newIDs, byName[name])
	}

	wg0, ok := srv.File(c.Dir + "/wg0.conf")
	if !ok {
		t.Fatal("wg0.conf отсутствует")
	}
	peers := parseWgConf(string(wg0)).peers
	if len(peers) != 2+n {
		t.Errorf("wg0.conf содержит %d peer'ов, want %d", len(peers), 2+n)
	}

	// I1: исходные два пользователя (Alice, Bob) — байт в байт как до, и в
	// wg0.conf, и в clientsTable, даже под параллельной нагрузкой на другие
	// имена. Исключаем из сравнения все 8 НОВЫХ ключей (а не исходные два) —
	// то, что должно остаться нетронутым, сравнивается напрямую.
	assertOthersUntouched(t, snapshotFiles(c, beforeWG, beforeTbl), srv, newIDs...)
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

// TestRestoreSyncFailureReportsRuntimeMismatch — SEC-01 (changes-requested,
// 2026-09-14): восстановление файлов не гарантирует восстановление
// рантайма, если повторный syncconf при откате падает ПОСЛЕ того, как
// первый (apply-time) syncconf успел частично примениться. Сценарий:
// PlanRekey → apply-time syncconf успешно применяется (call #1), но verify
// проваливается, потому что «сторонний» (не участвующий в rekey) peer не
// поднялся (DropPeerOnSync) → restore пишет файлы обратно к состоянию до,
// но его собственный повторный syncconf (call #2) падает (FailSyncconfFrom
// = 2) → рантайм остаётся таким, каким его оставил call #1: с НОВЫМ ключом
// рекея (он не был затронут хуком) и без стороннего peer'а — а файл
// откатился к состоянию "до". Ошибка обязана честно сказать «применить их
// не удалось», а не «восстановлено и проверено».
func TestRestoreSyncFailureReportsRuntimeMismatch(t *testing.T) {
	srv := fakesrv.New()
	sess := NewSessionWithRunner(srv, testCreds())
	c := awgContainer()

	clients, err := sess.LoadClients(c)
	if err != nil || len(clients) < 2 {
		t.Fatalf("LoadClients: %v, %+v (нужно минимум 2 клиента в дефолтном фейке)", err, clients)
	}
	subject := clients[0].ClientID   // рекеим этого
	bystander := clients[1].ClientID // а этот не должен пострадать, но "не поднимется" по хуку

	beforeWG, ok := srv.File(c.Dir + "/wg0.conf")
	if !ok {
		t.Fatal("wg0.conf отсутствует")
	}

	plan, err := sess.PlanRekey(c, subject)
	if err != nil {
		t.Fatalf("PlanRekey: %v", err)
	}
	beforeKeys := peerPubKeysFromBytes(plan.wgBefore)
	newKey := ""
	for k := range peerPubKeysFromBytes(plan.wgAfter) {
		if !beforeKeys[k] {
			newKey = k
		}
	}
	if newKey == "" {
		t.Fatal("не удалось определить новый ключ рекея из плана")
	}

	srv.DropPeerOnSync = bystander // call #1 "применяется", но bystander не поднимается
	srv.FailSyncconfFrom = 2       // call #2 (restore-time retry) падает

	_, err = sess.Apply(plan)
	if err == nil {
		t.Fatal("Apply: ожидалась ошибка")
	}
	if !strings.Contains(err.Error(), "применить их не удалось") {
		t.Errorf("текст ошибки не содержит «применить их не удалось»: %v", err)
	}
	if strings.Contains(err.Error(), "восстановлено и проверено") {
		t.Errorf("текст ошибки не должен утверждать «восстановлено и проверено»: %v", err)
	}

	afterWG, ok := srv.File(c.Dir + "/wg0.conf")
	if !ok || !bytes.Equal(afterWG, beforeWG) {
		t.Error("File(wg0.conf) != wgBefore после restore — файл обязан откатиться, даже если рантайм разошёлся")
	}

	runtime := map[string]bool{}
	for _, k := range srv.RuntimePeers() {
		runtime[k] = true
	}
	if !runtime[newKey] {
		t.Errorf("RuntimePeers() не содержит новый ключ рекея %q (рантайм должен был остаться в состоянии после call #1): %v", newKey, srv.RuntimePeers())
	}
	// Прямая фиксация потери доступа (review changes-requested, круг 2,
	// Low): старый ключ субъекта рекея тоже не должен быть в рантайме —
	// файл откатился к состоянию "до" (со старым ключом), а рантайм всё ещё
	// на "новом" ключе; ни один из двух активных наборов не содержит старый
	// ключ subject.
	if runtime[subject] {
		t.Errorf("RuntimePeers() содержит старый ключ субъекта рекея %q — он не должен быть активен ни в файле (уже заменён), ни в рантайме (заменён на call #1): %v", subject, srv.RuntimePeers())
	}
}

// TestPlanSubjectIsName — review changes-requested (Low): Plan.Subject
// обязан быть именем пользователя, а не публичным ключом, для всех пяти
// действий (раньше PlanDelete клал туда ClientID).
func TestPlanSubjectIsName(t *testing.T) {
	srv := fakesrv.New()
	sess := NewSessionWithRunner(srv, testCreds())
	c := awgContainer()

	clients, err := sess.LoadClients(c)
	if err != nil || len(clients) < 2 {
		t.Fatalf("LoadClients: %v, %+v (нужно минимум 2 клиента в дефолтном фейке)", err, clients)
	}
	keys := map[string]bool{}
	for _, cl := range clients {
		keys[cl.ClientID] = true
	}
	subject := clients[0].ClientID
	subjectName := clients[0].Name()

	checkSubject := func(t *testing.T, action, subj string) {
		t.Helper()
		if subj == "" {
			t.Errorf("%s: Subject пуст", action)
		}
		if keys[subj] {
			t.Errorf("%s: Subject = %q похож на публичный ключ, а не на имя", action, subj)
		}
	}

	pAdd, err := sess.PlanAddUser(c, "NewGuy")
	if err != nil {
		t.Fatalf("PlanAddUser: %v", err)
	}
	checkSubject(t, "add", pAdd.Subject)
	if pAdd.Subject != "NewGuy" {
		t.Errorf("add: Subject = %q, want %q", pAdd.Subject, "NewGuy")
	}

	pDel, err := sess.PlanDelete(c, subject)
	if err != nil {
		t.Fatalf("PlanDelete: %v", err)
	}
	checkSubject(t, "delete", pDel.Subject)
	if pDel.Subject != subjectName {
		t.Errorf("delete: Subject = %q, want %q", pDel.Subject, subjectName)
	}

	pRekey, err := sess.PlanRekey(c, subject)
	if err != nil {
		t.Fatalf("PlanRekey: %v", err)
	}
	checkSubject(t, "rekey", pRekey.Subject)
	if pRekey.Subject != subjectName {
		t.Errorf("rekey: Subject = %q, want %q", pRekey.Subject, subjectName)
	}

	pRename, err := sess.PlanRename(c, subject, "RenamedName")
	if err != nil {
		t.Fatalf("PlanRename: %v", err)
	}
	checkSubject(t, "rename", pRename.Subject)

	pDisable, err := sess.PlanSetEnabled(c, subject, false)
	if err != nil {
		t.Fatalf("PlanSetEnabled(false): %v", err)
	}
	checkSubject(t, "disable", pDisable.Subject)
	if pDisable.Subject != subjectName {
		t.Errorf("disable: Subject = %q, want %q", pDisable.Subject, subjectName)
	}
}

// TestRestoreTriesBothFilesIndependently — review changes-requested (круг 2,
// Medium): прошлая версия этого теста (FailWrite[wg0.conf] безусловно) была
// зелёной и на СТАРОМ restore() (он вообще не пытался писать clientsTable
// после провала wg0.conf) — assert bytes.Equal(clientsTable, tblBefore)
// проходил тривиально, потому что clientsTable к этому моменту ещё ни разу
// не менялась (apply даже не успел до неё дойти). Чтобы тест реально что-то
// доказывал, clientsTable должна быть ГРЯЗНОЙ (== tblAfter) к моменту
// отката: первая запись wg0.conf (apply-time) обязана пройти, затем
// clientsTable перезаписывается в tblAfter, и только ПОСЛЕ этого падает
// syncconf (это и валит Apply) — а откат wg0.conf (вторая запись по этому
// пути) проваливается через счётный хук FailWriteFrom. Тогда
// bytes.Equal(clientsTable, tblBefore) нетривиален: он проходит только если
// restore реально записал clientsTable обратно, невзирая на провал wg0.conf.
func TestRestoreTriesBothFilesIndependently(t *testing.T) {
	srv := fakesrv.New()
	sess := NewSessionWithRunner(srv, testCreds())
	c := awgContainer()

	plan, err := sess.PlanAddUser(c, "Carol")
	if err != nil {
		t.Fatalf("PlanAddUser: %v", err)
	}
	tblBefore := append([]byte{}, plan.tblBefore...)

	// Первая запись wg0.conf (apply) проходит; вторая (restore) — падает.
	srv.FailWriteFrom = map[string]int{c.Dir + "/wg0.conf": 2}
	// Apply валится ПОСЛЕ того, как clientsTable уже перезаписана в tblAfter
	// (syncWg вызывается после writeIn обоих файлов в applySteps).
	srv.FailSyncconf = fmt.Errorf("wg: syncconf: I/O error")

	_, err = sess.Apply(plan)
	if err == nil {
		t.Fatal("Apply: ожидалась ошибка")
	}
	if !strings.Contains(err.Error(), "восстановить не удалось") {
		t.Errorf("текст ошибки не про провал восстановления: %v", err)
	}
	if !strings.Contains(err.Error(), "wg0.conf") {
		t.Errorf("текст ошибки должен называть wg0.conf: %v", err)
	}
	if !strings.Contains(err.Error(), "clientsTable") {
		t.Errorf("текст ошибки должен называть clientsTable: %v", err)
	}

	afterTbl, ok := srv.File(c.Dir + "/clientsTable")
	if !ok {
		t.Fatal("clientsTable отсутствует")
	}
	// Нетривиально: clientsTable была грязной (tblAfter) прямо перед этим —
	// проходит, только если restore реально её переписал обратно.
	if !bytes.Equal(afterTbl, tblBefore) {
		t.Errorf("clientsTable должна была вернуться к состоянию до, даже когда wg0.conf не восстановился:\nбыло:  %s\nстало: %s", tblBefore, afterTbl)
	}

	// Порядок в Commands(): запись clientsTable при откате обязана идти
	// ПОСЛЕ второй (провалившейся) попытки записи wg0.conf.
	cmds := srv.Commands()
	wgWrites := 0
	failedWgIdx := -1
	for i, cmd := range cmds {
		if strings.Contains(cmd, "cat > ") && strings.Contains(cmd, "wg0.conf") {
			wgWrites++
			if wgWrites == 2 {
				failedWgIdx = i
			}
		}
	}
	if failedWgIdx < 0 {
		t.Fatal("не нашли вторую (restore-time) попытку записи wg0.conf в Commands()")
	}
	tblWriteAfter := false
	for _, cmd := range cmds[failedWgIdx+1:] {
		if strings.Contains(cmd, "cat > ") && strings.Contains(cmd, "clientsTable") {
			tblWriteAfter = true
			break
		}
	}
	if !tblWriteAfter {
		t.Error("запись clientsTable при откате не найдена ПОСЛЕ провалившейся (второй) записи wg0.conf")
	}
}
