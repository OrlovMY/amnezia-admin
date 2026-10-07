package main

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"fyne.io/fyne/v2/test"
	"fyne.io/fyne/v2/widget"

	"amnezia-admin/internal/fakesrv"
)

// setTargetUsers — на новом сервере ровно n клиентов User01…(новые ключи и
// адреса 10.8.1.100+).
func setTargetUsers(t *testing.T, srv *fakesrv.Server, n int) {
	t.Helper()
	conf, _ := srv.File("/opt/amnezia/awg/wg0.conf")
	head := string(conf)
	if i := strings.Index(head, "\n[Peer]"); i >= 0 {
		head = head[:i+1]
	}
	var b strings.Builder
	b.WriteString(head)
	tbl := []map[string]any{}
	for i := 0; i < n; i++ {
		id := fakesrv.RandUUID()
		fmt.Fprintf(&b, "\n[Peer]\nPublicKey = %s\nAllowedIPs = 10.8.1.%d/32\n", id, 100+i)
		tbl = append(tbl, map[string]any{"clientId": id, "userData": map[string]any{"clientName": fmt.Sprintf("User%02d", i+1)}})
	}
	srv.SetFile("/opt/amnezia/awg/wg0.conf", []byte(b.String()))
	j, _ := json.Marshal(tbl)
	srv.SetFile("/opt/amnezia/awg/clientsTable", j)
}

func guiFlocks(srv *fakesrv.Server) int {
	n := 0
	for _, c := range srv.Commands() {
		if strings.Contains(c, "flock -w") {
			n++
		}
	}
	return n
}

// TestGUIRestoreTargetUsers — пользователи на новом сервере: в окне —
// число и имена первым разделом; «Заменить данные» не пишет, а открывает
// отдельное окно с «Всё равно записать» (опасный стиль), окно по
// содержимому; длинный список свёрнут, число видно; пустая цель — без
// предупреждения и без лишнего окна.
func TestGUIRestoreTargetUsers(t *testing.T) {
	cases := []struct {
		name  string
		n     int // -1 — цель как у fakesrv (Alice, Bob: конфликты имени и адреса)
		count string
		fold  bool
		warn  bool
	}{
		{"пустая цель", 0, "", false, false},
		{"есть пользователи и конфликты", -1, "уже есть пользователи — 2", false, true},
		{"длинный список", 30, "уже есть пользователи — 30", true, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			u, _, tgt, p := guiMigration(t, "203.0.113.1")
			if c.n >= 0 {
				setTargetUsers(t, tgt, c.n)
			}
			b, compat, rp, planErr, err := u.restorePrepare(p)
			if err != nil || planErr != nil {
				t.Fatal(err, planErr)
			}
			v := u.restoreWindow(b, compat, rp, planErr)
			if got := strings.Contains(v.text, "ВНИМАНИЕ"); got != c.warn || (c.warn && !strings.Contains(v.text, c.count)) {
				t.Fatalf("предупреждение в окне = %v:\n%s", got, v.text)
			}
			if rp.NeedsTargetConfirm() != c.warn {
				t.Fatalf("подтверждение нужно = %v", rp.NeedsTargetConfirm())
			}
			if !c.warn {
				return // пустая цель: «Заменить» сразу пишет (TestGUIRestoreGates)
			}
			test.Tap(v.apply)
			if v.users == nil || guiFlocks(tgt) != 0 {
				t.Fatalf("«Заменить» не открыло подтверждение или записало: окно %v записей %d", v.users != nil, guiFlocks(tgt))
			}
			got := topOverlay(t, u)
			if !strings.Contains(got, "["+restoreForceText+"]") || !strings.Contains(got, c.count) || v.users.force.Importance != widget.DangerImportance {
				t.Fatalf("окно подтверждения:\n%s", got)
			}
			if (v.users.list != nil) != c.fold {
				t.Errorf("свёрнут ли список = %v", v.users.list != nil)
			}
			if c.fold {
				if v.users.list.Items[0].Open || strings.Contains(v.users.list.Items[0].Title, "30") == false {
					t.Errorf("длинный список: раскрыт=%v заголовок %q", v.users.list.Items[0].Open, v.users.list.Items[0].Title)
				}
			} else {
				for _, part := range []string{"Alice, Bob", "КОНФЛИКТ: имя «Alice»", "КОНФЛИКТ: адрес 10.8.1.2/32"} {
					if !strings.Contains(got, part) {
						t.Errorf("нет «%s»:\n%s", part, got)
					}
				}
			}
			win := u.win.Canvas().Size()
			if s := requestedSize[v.users.d]; s.Height >= win.Height-1 || s.Height < 100 {
				t.Errorf("окно не по содержимому: %v при окне %v", s, win)
			}
		})
	}
}
