package core

// Долг У1 (ДОЛГИ-ПРОДУКТ, 30.09.2026): поле disabled не типа bool — не
// «активен», а «неизвестно». Тесты пользуются только API c65420e
// (RegenerateUser, SetEnabled, AddUser, fakesrv) и падают там поведением.

import (
	"encoding/json"
	"strings"
	"testing"

	"amnezia-admin/internal/fakesrv"
)

const debtsTbl = "/opt/amnezia/awg/clientsTable"

// withAliceDisabled — fakesrv, у первой записи которого поле disabled
// равно v (nil — поля нет). extra — дополнительные записи таблицы.
func withAliceDisabled(t *testing.T, v any, extra ...map[string]any) (*fakesrv.Server, string) {
	t.Helper()
	srv := fakesrv.New()
	raw, _ := srv.File(debtsTbl)
	var list []map[string]any
	if err := json.Unmarshal(raw, &list); err != nil || len(list) == 0 {
		t.Fatalf("проверка ПЕРЕСТАЛА ЧТО-ЛИБО ЗНАЧИТЬ: clientsTable fakesrv: %v", err)
	}
	if v != nil {
		list[0]["userData"].(map[string]any)["disabled"] = v
	}
	list = append(list, extra...)
	out, _ := json.MarshalIndent(list, "", "    ")
	srv.SetFile(debtsTbl, out)
	return srv, list[0]["clientId"].(string)
}

// TestDebtsEnabledUnknownRefused — ТЕСТ РАЗЛИЧЕНИЯ и ДОЕЗДА через Session и
// fakesrv: disabled = false / true / "true" (строка) / 1. Перевыпуск и
// включение при неизвестном — отказ с причиной и шагом «отключите», таблица
// и wg0.conf не тронуты. На c65420e строка читалась как «активен»: rekey
// проходил и стирал поле, enable отвечал «уже активен». Отключение при
// неизвестном РАЗРЕШЕНО (раунд 4, решение ядра) — см.
// TestDebtsDisableUnknownWritesTrue.
func TestDebtsEnabledUnknownRefused(t *testing.T) {
	type op struct {
		name string
		do   func(s *Session, id string) error
	}
	ops := []op{
		{"rekey", func(s *Session, id string) error { _, err := s.RegenerateUser(awgContainer(), id); return err }},
		{"disable", func(s *Session, id string) error { return s.SetEnabled(awgContainer(), id, false) }},
		{"enable", func(s *Session, id string) error { return s.SetEnabled(awgContainer(), id, true) }},
	}
	cases := []struct {
		name  string
		v     any
		wantU bool // ожидается отказ «неизвестно»
	}{
		{"false — активен", false, false},
		{"true — отключён", true, false},
		{`"true" строкой — неизвестно`, "true", true},
		{"число — неизвестно", 1, true},
	}
	for _, c := range cases {
		for _, o := range ops {
			t.Run(c.name+"/"+o.name, func(t *testing.T) {
				srv, id := withAliceDisabled(t, c.v)
				tblBefore, _ := srv.File(debtsTbl)
				wgBefore, _ := srv.File(debtsWg0)
				err := o.do(a1bSession(srv), id)
				wantU := c.wantU && o.name != "disable"
				isUnknown := err != nil && strings.Contains(err.Error(), "неизвестно")
				if isUnknown != wantU {
					t.Fatalf("disabled=%#v, %s: err=%v; ожидался отказ «неизвестно»: %v", c.v, o.name, err, wantU)
				}
				if !wantU {
					return
				}
				// Раунд 4 (AU-UX High): отказ называет выполнимый шаг.
				if !strings.Contains(err.Error(), "Отключите пользователя — это исправит запись") {
					t.Errorf("отказ не говорит, что делать: %v", err)
				}
				tblAfter, _ := srv.File(debtsTbl)
				wgAfter, _ := srv.File(debtsWg0)
				if string(tblAfter) != string(tblBefore) || string(wgAfter) != string(wgBefore) {
					t.Fatal("при неизвестном состоянии сервер изменён")
				}
			})
		}
	}
}

// TestDebtsEnabledUnknownNoteText — дословный текст UX-01 (раунд 2, Т1):
// одна форма для одного и нескольких имён, «программа».
func TestDebtsEnabledUnknownNoteText(t *testing.T) {
	if got := EnabledUnknownNote(nil); got != "" {
		t.Fatalf("имён нет, а строка есть: %q", got)
	}
	const want = `Неизвестно, включены ли эти пользователи (поле disabled в clientsTable не true/false): "X", "Y". ` +
		"Включать и перевыпускать их программа не будет; чтобы исправить запись, отключите их (или удалите)."
	if got := EnabledUnknownNote([]string{"X", "Y"}); got != want {
		t.Fatalf("текст:\n%q\nожидался:\n%q", got, want)
	}
}

// TestDebtsEnabledUnknownKeepsReservedIP — ДОЕЗД до выдачи адреса: у Carol
// поле disabled испорчено, peer'а нет, в allowedIP — 10.8.1.4. Она может
// быть отключённой, и её адрес не выдаётся новому пользователю. На c65420e
// её запись читалась как «активна», резерв не учитывался, и Mallory
// получала 10.8.1.4.
func TestDebtsEnabledUnknownKeepsReservedIP(t *testing.T) {
	carol := map[string]any{"clientId": "CAROLPUB", "userData": map[string]any{
		"clientName": "Carol", "disabled": "yes", "allowedIP": "10.8.1.4/32", "psk": "x",
	}}
	srv, _ := withAliceDisabled(t, nil, carol)
	nu, err := a1bSession(srv).AddUser(awgContainer(), "Mallory")
	if err != nil {
		t.Fatalf("AddUser: %v", err)
	}
	if nu.IP == "10.8.1.4" {
		t.Fatal("адрес клиента с неизвестным состоянием выдан новому пользователю")
	}
}

// TestDebtsDisableUnknownWritesTrue — раунд 4 (AU-UX High, решение ядра):
// отключение клиента с испорченным полем disabled ПРОХОДИТ и пишет
// disabled=true (bool) — итог от прежней записи не зависит, запись
// исправлена; peer из wg0.conf убран. На f5951bc здесь был отказ, и отрезать
// доступ можно было только удалением.
func TestDebtsDisableUnknownWritesTrue(t *testing.T) {
	for _, v := range []any{"true", 1, "yes"} {
		srv, id := withAliceDisabled(t, v)
		if err := a1bSession(srv).SetEnabled(awgContainer(), id, false); err != nil {
			t.Fatalf("disabled=%#v: отключение отказало: %v", v, err)
		}
		raw, _ := srv.File(debtsTbl)
		var list []map[string]any
		if err := json.Unmarshal(raw, &list); err != nil {
			t.Fatal(err)
		}
		var got any = "записи нет"
		for _, e := range list {
			if e["clientId"] == id {
				got = e["userData"].(map[string]any)["disabled"]
			}
		}
		if got != true {
			t.Errorf("disabled=%#v: после отключения поле %#v, ожидалось true", v, got)
		}
		wg, _ := srv.File(debtsWg0)
		if strings.Contains(string(wg), id) {
			t.Errorf("disabled=%#v: peer остался в wg0.conf после отключения", v)
		}
	}
}
