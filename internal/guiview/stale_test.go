package guiview

import (
	"errors"
	"strings"
	"testing"

	"amnezia-admin/core"
)

// ---------- Место № 4 задания A1: молчаливое сохранение прежнего ----------
//
// ЧТО БЫЛО СОЗНАТЕЛЬНЫМ РЕШЕНИЕМ, А ЧТО ДЕФЕКТОМ. Сохранение таблицы при
// ошибке чтения — решение FIX-VIEW (Г2 п. 5), принятое владельцем на
// приёмке; оно НЕ отменяется: данные остаются, таблица не очищается, кнопки
// не блокируются. Аудит нашёл другое — статус НЕ ГОВОРИЛ, что данные
// старые. Чинится именно молчание.
//
// ПОЧЕМУ ТЕСТ СМОТРИТ НА БУЛЕВ ПРИЗНАК, А НЕ НА ТЕКСТ. Состояние, выведенное
// из строки интерфейса, — тот же антипаттерн, что чинит весь A1. Дословный
// текст проверяется отдельно (и он проверяется как текст), а состояние —
// полем StaleShown.

// TestStaleShownIsStateNotText — признак устаревания есть у ошибки чтения
// управляемого протокола и только у неё.
func TestStaleShownIsStateNotText(t *testing.T) {
	readErr := errors.New("чтение clientsTable: i/o timeout")
	managed := core.Container{Name: "amnezia-awg", Dir: "/opt/amnezia/awg", Proto: "AmneziaWG", Managed: true}
	viewOnly := core.Container{Name: "amnezia-xray", Dir: "/opt/amnezia/xray", Proto: "XRay", Managed: false}

	for _, tc := range []struct {
		name string
		c    core.Container
		err  error
		ok   bool
		want bool
	}{
		{"управляемый/ошибка чтения — данные прошлого чтения на экране", managed, readErr, false, true},
		{"управляемый/успех — данные свежие", managed, nil, true, false},
		{"управляемый/файла нет — не ошибка чтения", managed, nil, false, false},
		{"неуправляемый/ошибка — таблица очищается, сохранять нечего", viewOnly, readErr, false, false},
		{"неуправляемый/успех", viewOnly, nil, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := ViewState(tc.c, nil, tc.ok, tc.err)
			if v.StaleShown != tc.want {
				t.Errorf("StaleShown = %v, want %v (Status = %q)", v.StaleShown, tc.want, v.Status)
			}
		})
	}
}

// TestStaleStatusSaysSo — вторая половина: признак состояния есть, и статус
// о нём ГОВОРИТ. Порознь эти две проверки ничего не стоят: признак без
// текста человек не увидит, текст без признака нельзя проверить иначе как
// по строке интерфейса.
func TestStaleStatusSaysSo(t *testing.T) {
	readErr := errors.New("чтение clientsTable: i/o timeout")
	managed := core.Container{Name: "amnezia-awg", Dir: "/opt/amnezia/awg", Proto: "AmneziaWG", Managed: true}

	v := ViewState(managed, nil, false, readErr)
	want := "Ошибка: " + readErr.Error() + " · показаны данные прошлого чтения."
	if v.Status != want {
		t.Errorf("Status = %q, want %q", v.Status, want)
	}
	if !v.StaleShown {
		t.Fatal("StaleShown = false при ошибке чтения управляемого протокола")
	}

	ok := ViewState(managed, nil, true, nil)
	if strings.Contains(ok.Status, "прошлого чтения") {
		t.Errorf("статус успешного чтения говорит об устаревании: %q — "+
			"предупреждение, которое видно всегда, не видно никогда", ok.Status)
	}
	if ok.StaleShown {
		t.Error("StaleShown = true при успешном чтении")
	}
}
