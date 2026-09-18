package guiview_test

import (
	"errors"
	"strings"
	"testing"

	"amnezia-admin/core"
	"amnezia-admin/internal/fakesrv"
	"amnezia-admin/internal/guiview"
)

// ---------- Места № 1, № 2, № 4 задания A1 (GUI) ----------
//
// Пакет тестируется ВНЕШНИМ тестовым пакетом guiview_test, потому что здесь
// нужен fakesrv (тест доезда), а сам guiview его не импортирует.
//
// ПОЧЕМУ ТЕКСТ КАРТОЧКИ И ЯЧЕЙКИ ТРАФИКА ЖИВУТ В guiview, А НЕ В cmd/gui.
// В cmd/gui нет ни одного исполняемого теста (запуск требует дисплея и
// холодной сборки с cgo), поэтому строка, написанная там, не проверяется
// ничем. Тот же довод уже применён к тексту предупреждения (A3а) и к
// решениям ViewState (FIX-VIEW). Что cmd/gui зовёт именно эти функции и
// именно на свежих данных, доказывает структурный сторож cardguard_test.go.

// failWgShow — транспорт поверх fakesrv, отказывающий ровно на `wg show wg0
// dump`: тем же путём, что в бою, а не присваиванием в тесте.
type failWgShow struct {
	inner *fakesrv.Server
	err   error
}

func (f *failWgShow) Run(cmd string, stdin []byte) (string, error) {
	if strings.Contains(cmd, "wg show wg0 dump") {
		return "", f.err
	}
	return f.inner.Run(cmd, stdin)
}

func wgContainer() *core.Container {
	return &core.Container{Name: "amnezia-awg", Dir: "/opt/amnezia/awg", Proto: "AmneziaWG", Managed: true}
}

// TestDeleteCardActivityThreeStates — ТЕСТ РАЗЛИЧЕНИЯ места № 1: три
// состояния, три РАЗНЫХ дословных текста. Сравнение целиком, не Contains:
// Contains прошёл бы и на тексте, куда "не удалось" дописали рядом с
// "подключений не было".
func TestDeleteCardActivityThreeStates(t *testing.T) {
	const id = "peer-1"
	for _, tc := range []struct {
		name string
		hs   map[string]string
		err  error
		want string
	}{
		{
			name: "есть активность",
			hs:   map[string]string{id: "2026-09-18 21:40"},
			want: "⚠ У этого клиента была активность!\nПоследнее подключение: 2026-09-18 21:40",
		},
		{
			name: "подключений не было",
			hs:   map[string]string{id: "—"},
			want: "Подключений не было.",
		},
		{
			name: "ключа нет в ответе сервера",
			hs:   map[string]string{"другой": "2026-09-18 21:40"},
			want: "Подключений не было.",
		},
		{
			name: "не удалось узнать",
			hs:   nil,
			err:  errors.New("wg show wg0 dump: ssh: connection reset"),
			want: "Не удалось получить данные о подключениях.\nНеизвестно, пользуется ли клиент этим доступом прямо сейчас.",
		},
		{
			name: "ошибка важнее непустой карты",
			hs:   map[string]string{id: "—"},
			err:  errors.New("wg show wg0 dump: ssh: connection reset"),
			want: "Не удалось получить данные о подключениях.\nНеизвестно, пользуется ли клиент этим доступом прямо сейчас.",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := guiview.DeleteCardActivity(tc.hs, id, tc.err)
			if got != tc.want {
				t.Errorf("DeleteCardActivity = %q\n              want %q", got, tc.want)
			}
		})
	}
}

// TestDeleteCardActivityStatesDiffer — различитель: три состояния обязаны
// давать три РАЗНЫХ текста. Без этой проверки подмена, сводящая "не удалось"
// к "подключений не было", прошла бы, если бы кто-то заодно поправил
// ожидание в таблице выше.
func TestDeleteCardActivityStatesDiffer(t *testing.T) {
	const id = "peer-1"
	was := guiview.DeleteCardActivity(map[string]string{id: "2026-09-18 21:40"}, id, nil)
	none := guiview.DeleteCardActivity(map[string]string{id: "—"}, id, nil)
	unknown := guiview.DeleteCardActivity(nil, id, errors.New("boom"))
	if was == none || none == unknown || was == unknown {
		t.Fatalf("состояния карточки удаления неразличимы: было=%q нет=%q не-удалось=%q", was, none, unknown)
	}
}

// TestDeleteCardActivityArrivesFromServer — ТЕСТ ДОЕЗДА места № 1: отказ
// сервера возникает боевым путём (транспорт отказывает на `wg show`), идёт
// через core.Session.GetHandshakes и доходит до текста карточки как "не
// удалось". Сконструированная в тесте ошибка (таблица выше) доказывает, что
// печать умеет печатать; этот тест доказывает, что ей есть что напечатать.
func TestDeleteCardActivityArrivesFromServer(t *testing.T) {
	sess := core.NewSessionWithRunner(
		&failWgShow{inner: fakesrv.New(), err: errors.New("ssh: connection reset")},
		&core.ServerCreds{Host: "1.2.3.4", User: "root", Password: "x"})

	hs, err := sess.GetHandshakes(wgContainer())
	got := guiview.DeleteCardActivity(hs, "peer-1", err)
	const want = "Не удалось получить данные о подключениях.\nНеизвестно, пользуется ли клиент этим доступом прямо сейчас."
	if got != want {
		t.Errorf("отказ сервера не доехал до карточки: %q, want %q", got, want)
	}
}

// TestDeleteCardActivityFreshDataArrives — вторая сторона доезда: на
// ИСПРАВНОМ сервере карточка получает настоящий ответ, а не "не удалось".
// Без неё правка "всегда печатать не удалось" прошла бы зелёной.
func TestDeleteCardActivityFreshDataArrives(t *testing.T) {
	srv := fakesrv.New()
	sess := core.NewSessionWithRunner(srv, &core.ServerCreds{Host: "1.2.3.4", User: "root", Password: "x"})

	hs, err := sess.GetHandshakes(wgContainer())
	if err != nil {
		t.Fatalf("исправный сервер: %v", err)
	}
	var anyPeer string
	for pub := range hs {
		anyPeer = pub
		break
	}
	if anyPeer == "" {
		t.Fatal("тест перестал что-либо проверять: fakesrv не вернул ни одного peer'а")
	}
	if got, want := guiview.DeleteCardActivity(hs, anyPeer, nil), "Подключений не было."; got != want {
		t.Errorf("свежий ответ сервера: %q, want %q", got, want)
	}
}

// TestTrafficTextThreeStates — ТЕСТ РАЗЛИЧЕНИЯ места № 2: "не удалось
// получить статистику" отличимо от измеренного нуля. До правки ошибка
// GetPeerStats отбрасывалась (if … statErr == nil), карта оставалась пустой,
// и человек читал "0 B / 0 B" как измеренную величину.
func TestTrafficTextThreeStates(t *testing.T) {
	for _, tc := range []struct {
		name        string
		canManage   bool
		statsFailed bool
		st          core.PeerStat
		want        string
	}{
		{"неуправляемый протокол", false, false, core.PeerStat{}, "—"},
		{"измеренный ноль", true, false, core.PeerStat{}, "0 B / 0 B"},
		{"измеренный трафик", true, false, core.PeerStat{RxBytes: 2048, TxBytes: 1000}, "2.0 KB / 1.0 KB"},
		{"статистику получить не удалось", true, true, core.PeerStat{}, "?"},
		{"не удалось — прежние числа не печатаются", true, true, core.PeerStat{RxBytes: 2048, TxBytes: 1000}, "?"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := guiview.TrafficText(tc.canManage, tc.statsFailed, tc.st)
			if got != tc.want {
				t.Errorf("TrafficText = %q, want %q", got, tc.want)
			}
		})
	}
	if guiview.TrafficText(true, true, core.PeerStat{}) == guiview.TrafficText(true, false, core.PeerStat{}) {
		t.Fatal("\"не удалось получить\" неотличимо от измеренного нуля — ровно тот дефект, который чинится")
	}
}

// TestTrafficTextArrivesFromServer — ТЕСТ ДОЕЗДА места № 2: отказ `wg show`
// приходит боевым путём из core.Session.GetPeerStats и превращается в "?",
// а не в "0 B / 0 B".
func TestTrafficTextArrivesFromServer(t *testing.T) {
	sess := core.NewSessionWithRunner(
		&failWgShow{inner: fakesrv.New(), err: errors.New("ssh: connection reset")},
		&core.ServerCreds{Host: "1.2.3.4", User: "root", Password: "x"})

	stats, err := sess.GetPeerStats(wgContainer())
	if err == nil {
		t.Fatal("тест перестал что-либо проверять: GetPeerStats не вернула ошибку на отказавшем транспорте")
	}
	if got, want := guiview.TrafficText(true, err != nil, stats["peer-1"]), "?"; got != want {
		t.Errorf("отказ сервера не доехал до ячейки трафика: %q, want %q", got, want)
	}

	srv := fakesrv.New()
	ok := core.NewSessionWithRunner(srv, &core.ServerCreds{Host: "1.2.3.4", User: "root", Password: "x"})
	stats, err = ok.GetPeerStats(wgContainer())
	if err != nil {
		t.Fatalf("исправный сервер: %v", err)
	}
	var anyPeer string
	for pub := range stats {
		anyPeer = pub
		break
	}
	if anyPeer == "" {
		t.Fatal("тест перестал что-либо проверять: fakesrv не вернул ни одного peer'а")
	}
	if got, want := guiview.TrafficText(true, err != nil, stats[anyPeer]), "0 B / 0 B"; got != want {
		t.Errorf("исправный сервер: %q, want %q — измеренный ноль обязан остаться нулём", got, want)
	}
}
