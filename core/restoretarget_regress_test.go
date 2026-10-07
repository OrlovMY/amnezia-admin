package core

// Регресс задачи владельца 07.10 (пользователи на новом сервере перед
// восстановлением). Файл намеренно использует только API ревизии 25e2377:
// на ней он компилируется и падает поведением (запись без подтверждения).

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"amnezia-admin/internal/fakesrv"
)

// tc — клиент, которого тест кладёт на новый сервер (WG): ключ, имя (""
// — нет записи в clientsTable, только [Peer]), адрес.
type tc struct{ id, name, addr string }

// setWGClients — новый сервер с ровно этими клиентами: [Interface] прежний,
// [Peer] и clientsTable — по списку.
func setWGClients(t *testing.T, srv *fakesrv.Server, cl []tc) {
	t.Helper()
	conf, _ := srv.File(awgDir + "/wg0.conf")
	head := string(conf)
	if i := strings.Index(head, "\n[Peer]"); i >= 0 {
		head = head[:i+1]
	}
	var b strings.Builder
	b.WriteString(head)
	tbl := []map[string]any{}
	for _, c := range cl {
		fmt.Fprintf(&b, "\n[Peer]\nPublicKey = %s\nPresharedKey = %s\nAllowedIPs = %s\n", c.id, fakesrv.RandUUID(), c.addr)
		if c.name != "" {
			tbl = append(tbl, map[string]any{"clientId": c.id, "userData": map[string]any{"clientName": c.name}})
		}
	}
	srv.SetFile(awgDir+"/wg0.conf", []byte(b.String()))
	j, _ := json.Marshal(tbl)
	srv.SetFile(awgDir+"/clientsTable", j)
}

// TestRestoreRefusesTargetUsersWithoutConfirm — доезд: на новом сервере
// есть пользователи; Restore без отдельного подтверждения — СТОП до
// автокопии, ни одной записи. Пустая цель — пишется без него. Опции — без
// поля TargetConfirmed (как у вызывающих до задачи): регресс падает на
// 25e2377 поведением, не компиляцией.
func TestRestoreRefusesTargetUsersWithoutConfirm(t *testing.T) {
	src, tgt := migrationPair(t)
	b := sourceBackup(t, src, "203.0.113.1")
	ts := NewSessionWithRunner(tgt, &ServerCreds{Host: "203.0.113.1"})
	rp := planFor(t, b, ts)
	dir := t.TempDir()
	_, outs, err := ts.Restore(rp, RestoreOptions{AutoCopyDir: dir, ToolVersion: "t", Now: backupNow, Resolve: okResolver, Layer: PlainLayer{}})
	if !errors.Is(err, ErrRestoreStopped) || outs != nil || writesOf(tgt) != 0 {
		t.Fatalf("без подтверждения: %v %+v записей %d", err, outs, writesOf(tgt))
	}
	if ents, _ := os.ReadDir(dir); len(ents) != 0 {
		t.Errorf("автокопия снята до отказа: %v", ents)
	}

	src2, tgt2 := migrationPair(t)
	b2 := sourceBackup(t, src2, "203.0.113.1")
	setWGClients(t, tgt2, nil)
	ts2 := NewSessionWithRunner(tgt2, &ServerCreds{Host: "203.0.113.1"})
	rp2 := planFor(t, b2, ts2)
	_, outs, err = ts2.Restore(rp2, RestoreOptions{AutoCopyDir: t.TempDir(), ToolVersion: "t", Now: backupNow, Resolve: okResolver, Layer: PlainLayer{}})
	if err != nil || len(outs) != 1 || outs[0].State != RestoreDone {
		t.Fatalf("пустая цель: %v %+v", err, outs)
	}
}
