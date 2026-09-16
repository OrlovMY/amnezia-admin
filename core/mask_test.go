package core

// TestPlanDiffMasksSecrets — SEC-01, review-reply PR-2Б круг 1 (2026-09-14,
// High, блокирует): предпросмотр (core.Plan.Diff — единственный потребитель
// CLI -dry-run и GUI «Показать изменения») не должен показывать ни
// PresharedKey/PrivateKey (wg0.conf), ни "psk" (clientsTable, disable) —
// ни для только что сгенерированного (ещё не применённого) секрета, ни для
// секретов уже действующих/посторонних пользователей: lineDiff не минимален
// (без LCS) и при rekey может случайно показать соседний, фактически
// неизменившийся peer-блок как "изменившийся" вместе с его PresharedKey.
// Решение владельца (форма, 14.09.2026): скрывать ВСЕГДА, без флага
// раскрытия.
//
// Тест обязан падать на 6d9288a (там Diff() секреты не маскирует) — прогон
// см. review-request.

import (
	"regexp"
	"strings"
	"testing"

	"amnezia-admin/internal/fakesrv"
)

// collectWgSecrets — все PresharedKey/PrivateKey, реально записанные в
// wg0.conf фейкового сервера ДО плана: если хоть один засветится в Diff() в
// открытом виде — тест обязан провалиться.
func collectWgSecrets(t *testing.T, srv *fakesrv.Server, c *Container) []string {
	t.Helper()
	wg0, ok := srv.File(c.Dir + "/wg0.conf")
	if !ok {
		t.Fatalf("нет wg0.conf в fakesrv")
	}
	conf := parseWgConf(string(wg0))
	var secrets []string
	if pk := conf.iface["PrivateKey"]; pk != "" {
		secrets = append(secrets, pk)
	}
	for _, p := range conf.peers {
		if psk := p["PresharedKey"]; psk != "" {
			secrets = append(secrets, psk)
		}
	}
	return secrets
}

func assertNoOpenSecrets(t *testing.T, label, diff string, secrets []string) {
	t.Helper()
	for _, s := range secrets {
		if s == "" {
			continue
		}
		if strings.Contains(diff, s) {
			t.Errorf("%s: diff содержит секрет в открытом виде: %q\ndiff:\n%s", label, s, diff)
		}
	}
}

func TestPlanDiffMasksSecrets(t *testing.T) {
	c := awgContainer()

	t.Run("add: ни старые, ни новый PSK не в открытом виде", func(t *testing.T) {
		srv := fakesrv.New()
		before := collectWgSecrets(t, srv, c)
		sess := NewSessionWithRunner(srv, testCreds())

		plan, err := sess.PlanAddUser(c, "Carol")
		if err != nil {
			t.Fatalf("PlanAddUser: %v", err)
		}
		// PSK нового (ещё не применённого) peer'а — из плана напрямую
		// (белый ящик: тест в package core).
		newConf := parseWgConf(string(plan.wgAfter))
		if len(newConf.peers) == 0 {
			t.Fatal("в wgAfter нет peer'ов")
		}
		newPSK := newConf.peers[len(newConf.peers)-1]["PresharedKey"]
		if newPSK == "" {
			t.Fatal("не удалось извлечь PSK нового peer'а из плана")
		}

		wgDiff, _ := plan.Diff()
		assertNoOpenSecrets(t, "add(старые)", wgDiff, before)
		if strings.Contains(wgDiff, newPSK) {
			t.Errorf("add: diff содержит НОВЫЙ PSK в открытом виде: %q\ndiff:\n%s", newPSK, wgDiff)
		}
		if !strings.Contains(wgDiff, "<скрыто>") {
			t.Errorf("add: diff не промаскирован (нет плейсхолдера \"<скрыто>\"): %q", wgDiff)
		}
	})

	t.Run("delete: PSK удаляемого и посторонних не в открытом виде", func(t *testing.T) {
		srv := fakesrv.New()
		secrets := collectWgSecrets(t, srv, c)
		sess := NewSessionWithRunner(srv, testCreds())

		clients, err := sess.LoadClients(c)
		if err != nil {
			t.Fatalf("LoadClients: %v", err)
		}
		if len(clients) == 0 {
			t.Fatal("fakesrv.New() должен дать хотя бы одного клиента")
		}
		plan, err := sess.PlanDelete(c, clients[0].ClientID)
		if err != nil {
			t.Fatalf("PlanDelete: %v", err)
		}
		wgDiff, _ := plan.Diff()
		assertNoOpenSecrets(t, "delete", wgDiff, secrets)
	})

	t.Run("rekey: PSK старого ключа субъекта, посторонних и нового PSK не в открытом виде", func(t *testing.T) {
		srv := fakesrv.New()
		secrets := collectWgSecrets(t, srv, c)
		sess := NewSessionWithRunner(srv, testCreds())

		clients, err := sess.LoadClients(c)
		if err != nil {
			t.Fatalf("LoadClients: %v", err)
		}
		if len(clients) == 0 {
			t.Fatal("fakesrv.New() должен дать хотя бы одного клиента")
		}
		plan, err := sess.PlanRekey(c, clients[0].ClientID)
		if err != nil {
			t.Fatalf("PlanRekey: %v", err)
		}
		// planRekeyLocked: removePeerFromConf (в середине) + buildPeerBlock
		// (в конец) — новый PSK берём как PSK последнего peer'а в wgAfter.
		newConf := parseWgConf(string(plan.wgAfter))
		if len(newConf.peers) == 0 {
			t.Fatal("в wgAfter нет peer'ов")
		}
		newPSK := newConf.peers[len(newConf.peers)-1]["PresharedKey"]

		wgDiff, _ := plan.Diff()
		assertNoOpenSecrets(t, "rekey(старые+посторонние)", wgDiff, secrets)
		if newPSK != "" && strings.Contains(wgDiff, newPSK) {
			t.Errorf("rekey: diff содержит НОВЫЙ PSK в открытом виде: %q\ndiff:\n%s", newPSK, wgDiff)
		}
		if !strings.Contains(wgDiff, "<скрыто>") {
			t.Errorf("rekey: diff не промаскирован (нет плейсхолдера \"<скрыто>\"): %q", wgDiff)
		}
	})

	// Не входит в обязательный список (add/del/rekey), но той же природы
	// утечки: planDisableLocked сохраняет PresharedKey под JSON-ключом "psk"
	// в clientsTable — маскировка обязана покрывать и это.
	t.Run("disable: PSK, сохраняемый в clientsTable, не в открытом виде", func(t *testing.T) {
		srv := fakesrv.New()
		secrets := collectWgSecrets(t, srv, c)
		sess := NewSessionWithRunner(srv, testCreds())

		clients, err := sess.LoadClients(c)
		if err != nil {
			t.Fatalf("LoadClients: %v", err)
		}
		if len(clients) == 0 {
			t.Fatal("fakesrv.New() должен дать хотя бы одного клиента")
		}
		plan, err := sess.PlanSetEnabled(c, clients[0].ClientID, false)
		if err != nil {
			t.Fatalf("PlanSetEnabled(false): %v", err)
		}
		_, tblDiff := plan.Diff()
		assertNoOpenSecrets(t, "disable(clientsTable)", tblDiff, secrets)
		if !strings.Contains(tblDiff, "<скрыто>") {
			t.Errorf("disable: clientsTable diff не промаскирован (нет плейсхолдера \"<скрыто>\"): %q", tblDiff)
		}
	})
}

// ---------- TestDiffNoStrayBase64 (review PR-2, carryover 2) ----------
//
// TestPlanDiffMasksSecrets выше проверяет ровно три известных поля по
// именам (PresharedKey/PrivateKey/psk) — она молчит, если появится НОВОЕ
// секретное поле с тем же форматом значения (base64, 32 байта → 44 символа
// с одним "="), которое ктo-то забудет добавить в reWgSecretLine/
// reTblSecretLine (core/txn.go:maskSecrets). PR-3 расширяет userData
// (userData.allowedIP уже не новость, но резерв IP делает clientsTable
// предметом этого PR) — эта проверка ловит будущие поля автоматически, не
// перечисляя их по имени: единственные base64-строки длины 44, которым
// разрешено остаться в открытом виде в Diff(), — значения под ключами
// PublicKey (wg0.conf) и "clientId" (clientsTable), потому что это не
// секреты, а публичные идентификаторы.
//
// Тест не привязан к конкретному найденному на fe5e013 багу (на fe5e013 он
// уже проходит — там нет ни одного нового секретного base64-поля, которое
// он мог бы поймать) — это защита на будущее, а не регресс на
// существующую дыру; прогон на fe5e013 задокументирован в отчёте.

// b64Run44 — максимальный по возможности run символов base64-алфавита
// (включая "="), затем фильтруется по длине 44 и ровно одному "=" в конце —
// именно так выглядит base64.StdEncoding 32 случайных байт (genKey/genPSK).
var b64Run44 = regexp.MustCompile(`[A-Za-z0-9+/=]+`)

// assertNoStrayBase64 проверяет, что каждая base64-строка длины 44 в diff
// встречается только на строке "PublicKey = …" (wg0.conf) или содержащей
// "clientId" (clientsTable) — на любой другой строке такая строка обязана
// быть секретом, который забыли замаскировать.
func assertNoStrayBase64(t *testing.T, label, diff string) {
	t.Helper()
	for _, line := range strings.Split(diff, "\n") {
		for _, run := range b64Run44.FindAllString(line, -1) {
			if len(run) != 44 || strings.Count(run, "=") != 1 || !strings.HasSuffix(run, "=") {
				continue
			}
			trimmed := strings.TrimSpace(line)
			trimmed = strings.TrimPrefix(trimmed, "-")
			trimmed = strings.TrimPrefix(trimmed, "+")
			trimmed = strings.TrimSpace(trimmed)
			allowed := strings.HasPrefix(trimmed, "PublicKey") || strings.Contains(trimmed, `"clientId"`)
			if !allowed {
				t.Errorf("%s: base64-строка длины 44 вне PublicKey/clientId не замаскирована: %q\nстрока diff: %q", label, run, line)
			}
		}
	}
}

func TestDiffNoStrayBase64(t *testing.T) {
	c := awgContainer()

	t.Run("add", func(t *testing.T) {
		srv := fakesrv.New()
		sess := NewSessionWithRunner(srv, testCreds())
		plan, err := sess.PlanAddUser(c, "Carol")
		if err != nil {
			t.Fatalf("PlanAddUser: %v", err)
		}
		wgDiff, tblDiff := plan.Diff()
		assertNoStrayBase64(t, "add/wg0.conf", wgDiff)
		assertNoStrayBase64(t, "add/clientsTable", tblDiff)
	})

	t.Run("delete", func(t *testing.T) {
		srv := fakesrv.New()
		sess := NewSessionWithRunner(srv, testCreds())
		clients, err := sess.LoadClients(c)
		if err != nil {
			t.Fatalf("LoadClients: %v", err)
		}
		plan, err := sess.PlanDelete(c, clients[0].ClientID)
		if err != nil {
			t.Fatalf("PlanDelete: %v", err)
		}
		wgDiff, tblDiff := plan.Diff()
		assertNoStrayBase64(t, "delete/wg0.conf", wgDiff)
		assertNoStrayBase64(t, "delete/clientsTable", tblDiff)
	})

	t.Run("rekey", func(t *testing.T) {
		srv := fakesrv.New()
		sess := NewSessionWithRunner(srv, testCreds())
		clients, err := sess.LoadClients(c)
		if err != nil {
			t.Fatalf("LoadClients: %v", err)
		}
		plan, err := sess.PlanRekey(c, clients[0].ClientID)
		if err != nil {
			t.Fatalf("PlanRekey: %v", err)
		}
		wgDiff, tblDiff := plan.Diff()
		assertNoStrayBase64(t, "rekey/wg0.conf", wgDiff)
		assertNoStrayBase64(t, "rekey/clientsTable", tblDiff)
	})

	t.Run("disable", func(t *testing.T) {
		srv := fakesrv.New()
		sess := NewSessionWithRunner(srv, testCreds())
		clients, err := sess.LoadClients(c)
		if err != nil {
			t.Fatalf("LoadClients: %v", err)
		}
		plan, err := sess.PlanSetEnabled(c, clients[0].ClientID, false)
		if err != nil {
			t.Fatalf("PlanSetEnabled(false): %v", err)
		}
		wgDiff, tblDiff := plan.Diff()
		assertNoStrayBase64(t, "disable/wg0.conf", wgDiff)
		assertNoStrayBase64(t, "disable/clientsTable", tblDiff)
	})
}
