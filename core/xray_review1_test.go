package core_test

// AL-01, ревью раунд 1: AU-LOGIC High-1/High-2, QA Н1.

import (
	"errors"
	"strings"
	"testing"

	"amnezia-admin/core"
	"amnezia-admin/internal/fakesrv"
)

// TestXRayRollbackRestartFailed — AU-LOGIC High-1, доезд: первый перезапуск
// удался (XRay жив с новым клиентом), проверка не удалась, откат записал
// файлы, второй перезапуск упал → не «восстановлено»: с каким server.json
// работает XRay, неизвестно.
func TestXRayRollbackRestartFailed(t *testing.T) {
	srv := fakesrv.NewXRay("master")
	sess, x := xraySession(t, srv)
	p, err := sess.PlanAddUser(x, "Carol")
	if err != nil {
		t.Fatal(err)
	}
	// первый перезапуск удался, xray жив; проверка не прочла server.json
	// (один отказ чтения) → откат; второй перезапуск падает, а живость
	// после него — «жив» (старый процесс с НОВЫМ файлом).
	srv.XRay.FailRestartFrom = 2
	srv.FailReadTimes = map[string]int{xrayConf: 1}
	_, err = sess.Apply(p)
	if srv.XRayRestarts() != 1 || !srv.XRayAlive() {
		t.Fatalf("стенд: перезапусков %d, жив %v", srv.XRayRestarts(), srv.XRayAlive())
	}
	if errors.Is(err, core.ErrRolledBack) || !errors.Is(err, core.ErrRollbackUnverified) {
		t.Fatalf("ждали «итог отката не проверен», получено %v", err)
	}
	if strings.Contains(err.Error(), "перезапущен с прежним") {
		t.Errorf("текст утверждает перезапуск: %v", err)
	}
	// перезапусков не было вовсе — «не перезапускался», без «перезапущен»
	srv2 := fakesrv.NewXRay("master")
	srv2.XRay.FailRestart = errors.New("Error response from daemon: boom")
	sess2, x2 := xraySession(t, srv2)
	_, err = xrayApply(sess2.PlanAddUser(x2, "Carol"))
	if !errors.Is(err, core.ErrRolledBack) || !strings.Contains(err.Error(), "не перезапускался") || strings.Contains(err.Error(), "перезапущен с прежним") {
		t.Fatalf("без перезапусков: %v", err)
	}
}

// TestXRayPrecheckDead — QA Н1: процесс xray мёртв уже до записи — отказ
// до записи, ни записи, ни перезапуска.
func TestXRayPrecheckDead(t *testing.T) {
	srv := fakesrv.NewXRay("dev")
	srv.XRay.DeadOnRestart = map[int]bool{1: true}
	sess, x := xraySession(t, srv)
	// уронить xray «прошлым» перезапуском — той же командой, что шлёт core
	if _, err := srv.Run("docker restart amnezia-xray", nil); err != nil || srv.XRayAlive() {
		t.Fatal("стенд: xray не упал")
	}
	before, writes := srv.XRayRestarts(), writeCmds(srv)
	_, err := xrayApply(sess.PlanAddUser(x, "Carol"))
	if !errors.Is(err, core.ErrWriteNotStarted) || !strings.Contains(err.Error(), "не работает уже сейчас") || srv.XRayRestarts() != before || writeCmds(srv) != writes {
		t.Fatalf("%v; перезапусков %d→%d; записей %d→%d", err, before, srv.XRayRestarts(), writes, writeCmds(srv))
	}
}

// TestXRayLinkFormat — AU-UX M4: ссылка в форме vless.cpp Serialize
// (amnezia-client 94b51df): type — только если network != tcp (у нас tcp —
// нет); порядок encryption, security, flow, sni, fp, pbk, sid; пустой
// spiderX не пишется; метка #AmneziaVPN.
func TestXRayLinkFormat(t *testing.T) {
	srv := fakesrv.NewXRay("dev")
	sess, x := xraySession(t, srv)
	nu, err := sess.XRayClientConfig(x, clientsOf(t, srv)["Bob"]["id"].(string))
	if err != nil {
		t.Fatal(err)
	}
	q := nu.Link[strings.Index(nu.Link, "?")+1 : strings.Index(nu.Link, "#")]
	var keys []string
	for _, kv := range strings.Split(q, "&") {
		keys = append(keys, strings.SplitN(kv, "=", 2)[0])
	}
	if got := strings.Join(keys, ","); got != "encryption,security,flow,sni,fp,pbk,sid" || strings.Contains(nu.Link, "type=") || !strings.HasSuffix(nu.Link, "#AmneziaVPN") {
		t.Fatalf("параметры %q в %q", got, nu.Link)
	}
}

// TestXRayRestartMeasuredNotByCode — AU-LOGIC р2 Medium-1: «перезапускался
// ли» решает время запуска контейнера, а не код выхода docker restart.
// Доезд: restart ВЫПОЛНИЛСЯ, но команда вернула ошибку (обрыв SSH после) —
// не «не перезапускался»; время запуска не прочитано — «неизвестно».
func TestXRayRestartMeasuredNotByCode(t *testing.T) {
	srv := fakesrv.NewXRay("master")
	srv.XRay.RestartThenFailFrom = 1
	sess, x := xraySession(t, srv)
	_, err := xrayApply(sess.PlanAddUser(x, "Carol"))
	if err == nil || strings.Contains(err.Error(), "не перезапускался") || srv.XRayRestarts() != 2 {
		t.Fatalf("перезапусков %d: %v", srv.XRayRestarts(), err)
	}
	srv2 := fakesrv.NewXRay("master")
	srv2.XRay.FailRestart = errors.New("boom")
	srv2.XRay.FailInspect = errors.New("inspect: timeout")
	sess2, x2 := xraySession(t, srv2)
	_, err = xrayApply(sess2.PlanAddUser(x2, "Carol"))
	if !errors.Is(err, core.ErrRollbackUnverified) || strings.Contains(err.Error(), "не перезапускался") {
		t.Fatalf("время запуска не прочитано: %v", err)
	}
}

// TestXRayWrappersRefuse — AU-LOGIC High-2: обёртки «план и сразу запись»
// для XRay с перезапуском отказывают; переименование — работает.
func TestXRayWrappersRefuse(t *testing.T) {
	srv := fakesrv.NewXRay("dev")
	sess, x := xraySession(t, srv)
	alice := clientsOf(t, srv)["Alice"]["id"].(string)
	for name, f := range map[string]func() error{
		"add":    func() error { _, err := sess.AddUser(x, "Carol"); return err },
		"delete": func() error { return sess.DeleteByID(x, alice) },
		"toggle": func() error { return sess.SetEnabled(x, alice, false) },
		"rekey":  func() error { _, err := sess.RegenerateUser(x, alice); return err },
	} {
		if err := f(); !errors.Is(err, core.ErrXRayNeedsConfirm) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if writeCmds(srv) != 0 || srv.XRayRestarts() != 0 {
		t.Fatalf("записей %d, перезапусков %d", writeCmds(srv), srv.XRayRestarts())
	}
	if err := sess.RenameUser(x, alice, "A"); err != nil {
		t.Fatal(err)
	}
}
