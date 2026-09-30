package core

// Раунд 5 долгов (AU-LOGIC повторный: Н-4, М-5).

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"strings"
	"testing"

	"amnezia-admin/internal/fakesrv"
)

// dropPeer убирает из wg0.conf fakesrv блок [Peer] с ключом id.
func dropPeer(t *testing.T, srv *fakesrv.Server, id string) {
	t.Helper()
	wg, _ := srv.File(debtsWg0)
	blocks := strings.Split(string(wg), "\n\n")
	var out []string
	dropped := false
	for _, b := range blocks {
		if strings.Contains(b, "PublicKey = "+id) {
			dropped = true
			continue
		}
		out = append(out, b)
	}
	if !dropped {
		t.Fatal("проверка ПЕРЕСТАЛА ЧТО-ЛИБО ЗНАЧИТЬ: peer'а клиента в wg0.conf не было")
	}
	srv.SetFile(debtsWg0, []byte(strings.Join(out, "\n\n")))
}

// userDataOf — userData записи id из clientsTable fakesrv.
func userDataOf(t *testing.T, srv *fakesrv.Server, id string) map[string]any {
	t.Helper()
	raw, _ := srv.File(debtsTbl)
	var list []map[string]any
	if err := json.Unmarshal(raw, &list); err != nil {
		t.Fatal(err)
	}
	for _, e := range list {
		if e["clientId"] == id {
			return e["userData"].(map[string]any)
		}
	}
	t.Fatalf("записи %s нет", id)
	return nil
}

// TestDebtsDisableUnknownWithoutPeer — Н-4, ТЕСТ ДОЕЗДА и РАЗЛИЧЕНИЯ через
// Session и fakesrv. Таблица: поле disabled × peer в wg0.conf есть / нет.
//   - "true" строкой, peer'а нет: отключение ПРОХОДИТ, disabled=true (bool),
//     wg0.conf побайтно не изменён — доступ уже отрезан, правится запись;
//   - "true", peer есть: отключение проходит и peer убирается (обычный путь);
//   - известное состояние (false / поля нет) без peer'а: прежний отказ
//     «peer … не найден в wg0.conf», ничего не изменено — рассинхрон молча не
//     «чинится».
//
// На aab4da6 первый случай отказывал «peer не найден», а совет в отказах
// включения и перевыпуска обещал, что отключение исправит запись.
func TestDebtsDisableUnknownWithoutPeer(t *testing.T) {
	cases := []struct {
		name    string
		v       any
		peer    bool
		wantErr bool
	}{
		{`"true" без peer'а`, "true", false, false},
		{`"true" с peer'ом`, "true", true, false},
		{"false без peer'а", false, false, true},
		{"поля нет, без peer'а", nil, false, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv, id := withAliceDisabled(t, c.v)
			if !c.peer {
				dropPeer(t, srv, id)
			}
			wgBefore, _ := srv.File(debtsWg0)
			tblBefore, _ := srv.File(debtsTbl)
			err := a1bSession(srv).SetEnabled(awgContainer(), id, false)
			wgAfter, _ := srv.File(debtsWg0)
			tblAfter, _ := srv.File(debtsTbl)
			if c.wantErr {
				if err == nil || !strings.Contains(err.Error(), "не найден в wg0.conf") {
					t.Fatalf("известное состояние без peer'а: err=%v — ожидался прежний отказ «peer не найден»", err)
				}
				if string(wgAfter) != string(wgBefore) || string(tblAfter) != string(tblBefore) {
					t.Fatal("при отказе сервер изменён")
				}
				return
			}
			if err != nil {
				t.Fatalf("отключение отказало: %v", err)
			}
			if got := userDataOf(t, srv, id)["disabled"]; got != true {
				t.Errorf("disabled после отключения %#v, ожидалось true", got)
			}
			if c.peer {
				if strings.Contains(string(wgAfter), id) {
					t.Error("peer остался в wg0.conf после отключения")
				}
			} else if string(wgAfter) != string(wgBefore) {
				t.Errorf("wg0.conf изменён, хотя peer'а не было:\nбыло:\n%s\nстало:\n%s", wgBefore, wgAfter)
			}
		})
	}
}

// TestDebtsDisableRecordOnlyNote — Н-4: предпросмотр отключения без peer'а
// говорит прямо, что правится только запись; с peer'ом — не говорит.
// Новый API (Plan.Note) — на aab4da6 не компилируется; падение там
// доказывает TestDebtsDisableUnknownWithoutPeer.
func TestDebtsDisableRecordOnlyNote(t *testing.T) {
	for _, peer := range []bool{true, false} {
		srv, id := withAliceDisabled(t, "true")
		if !peer {
			dropPeer(t, srv, id)
		}
		p, err := a1bSession(srv).PlanSetEnabled(awgContainer(), id, false)
		if err != nil {
			t.Fatalf("peer=%v: план: %v", peer, err)
		}
		wgDiff, _ := p.Diff()
		switch {
		case !peer && p.Note() != NoteDisableRecordOnly:
			t.Errorf("без peer'а пояснение %q, ожидалось %q", p.Note(), NoteDisableRecordOnly)
		case !peer && wgDiff != "":
			t.Errorf("без peer'а план меняет wg0.conf:\n%s", wgDiff)
		case peer && p.Note() != "":
			t.Errorf("с peer'ом лишнее пояснение %q", p.Note())
		}
	}
}

// TestDebtsDisableKeepsUserData — М-5 (3): отключение (и с peer'ом, и
// без) не теряет и не переписывает поля userData. Все прежние ключи, кроме
// disabled, остаются с прежними значениями; добавляются только disabled,
// disabledAt и (при peer'е) psk, allowedIP. Подмена аудитора (потеря
// creationDate) роняет тест.
func TestDebtsDisableKeepsUserData(t *testing.T) {
	for _, peer := range []bool{true, false} {
		t.Run(fmt.Sprintf("peer=%v", peer), func(t *testing.T) {
			srv, id := withAliceDisabled(t, "true")
			raw, _ := srv.File(debtsTbl)
			var list []map[string]any
			json.Unmarshal(raw, &list)
			list[0]["userData"].(map[string]any)["custom"] = "чужое поле"
			out, _ := json.Marshal(list)
			srv.SetFile(debtsTbl, out)
			before := userDataOf(t, srv, id)
			if _, ok := before["creationDate"]; !ok {
				t.Fatal("проверка ПЕРЕСТАЛА ЧТО-ЛИБО ЗНАЧИТЬ: в записи нет creationDate")
			}
			if !peer {
				dropPeer(t, srv, id)
			}
			if err := a1bSession(srv).SetEnabled(awgContainer(), id, false); err != nil {
				t.Fatalf("отключение: %v", err)
			}
			after := userDataOf(t, srv, id)
			for k, v := range before {
				if k == "disabled" {
					continue
				}
				if fmt.Sprint(after[k]) != fmt.Sprint(v) {
					t.Errorf("поле %q: было %#v, стало %#v", k, v, after[k])
				}
			}
			allowed := map[string]bool{"disabled": true, "disabledAt": true, "psk": peer, "allowedIP": peer}
			for k := range after {
				if _, was := before[k]; !was && !allowed[k] {
					t.Errorf("отключение добавило поле %q", k)
				}
			}
		})
	}
}

// TestDebtsThrottleFaultDenied — М-5 (2): ошибка «нет прав» разбирается как
// FaultDenied, а не как повреждённый файл (совет «удалите» к ней не
// относится). Путь заведомо не каталог.
func TestDebtsThrottleFaultDenied(t *testing.T) {
	path := t.TempDir() + "/нет-такого/throttle.json"
	perm := &fs.PathError{Op: "open", Path: path, Err: fs.ErrPermission}
	cases := []struct {
		err     error
		corrupt bool
		want    ThrottleFault
	}{
		{perm, false, FaultDenied},
		{errors.New("иное"), false, FaultOther},
		{errors.New("битый JSON"), true, FaultCorrupt},
	}
	for _, c := range cases {
		got := newThrottleError("прочитать", path, c.err, c.corrupt).Fault
		if got != c.want {
			t.Errorf("%v (corrupt=%v): разбор %d, ожидался %d", c.err, c.corrupt, got, c.want)
		}
		// Второй, независимый сторож (выборка немоты): «повреждён» — только
		// когда содержимое действительно не разобрано.
		if got == FaultCorrupt && !c.corrupt {
			t.Errorf("%v: разобрано как «повреждён», хотя файл прочитан не был", c.err)
		}
	}
}
