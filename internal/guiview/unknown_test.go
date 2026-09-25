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
		name     string
		hs       map[string]string
		err      error
		disabled bool
		want     string
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
			// До задания НЕЗНАНИЕ-ТРАФИК здесь стояло ожидание
			// «Подключений не было.» — таблица закрепляла дефект.
			name: "ключа нет в ответе сервера",
			hs:   map[string]string{"другой": "2026-09-18 21:40"},
			want: "Клиента нет в статистике сервера: сейчас сервер его не принимает.\nБыли ли подключения раньше — неизвестно.",
		},
		{
			name:     "отключённого нет в ответе — отключён, а не «нет в статистике»",
			hs:       map[string]string{"другой": "—"},
			disabled: true,
			want:     "Клиент отключён: сервер его сейчас не принимает.\nБыли ли подключения до отключения — неизвестно.",
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
			got := guiview.DeleteCardActivity(tc.hs, id, tc.err, tc.disabled)
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
	was := guiview.DeleteCardActivity(map[string]string{id: "2026-09-18 21:40"}, id, nil, false)
	none := guiview.DeleteCardActivity(map[string]string{id: "—"}, id, nil, false)
	unknown := guiview.DeleteCardActivity(nil, id, errors.New("boom"), false)
	absent := guiview.DeleteCardActivity(map[string]string{}, id, nil, false)
	disabled := guiview.DeleteCardActivity(map[string]string{}, id, nil, true)
	if disabled == absent || disabled == none || disabled == unknown {
		t.Fatalf("«отключён» неотличимо от другого состояния: отключён=%q нет-в-ответе=%q", disabled, absent)
	}
	if was == none || none == unknown || was == unknown {
		t.Fatalf("состояния карточки удаления неразличимы: было=%q нет=%q не-удалось=%q", was, none, unknown)
	}
	if absent == none || absent == unknown || absent == was {
		t.Fatalf("«клиента нет в статистике» неотличимо от другого состояния: нет-в-ответе=%q нет=%q не-удалось=%q",
			absent, none, unknown)
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
	got := guiview.DeleteCardActivity(hs, "peer-1", err, false)
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
	if got, want := guiview.DeleteCardActivity(hs, anyPeer, nil, false), "Подключений не было."; got != want {
		t.Errorf("свежий ответ сервера: %q, want %q", got, want)
	}
}

// TestActivityTextThreeStates — ТЕСТ РАЗЛИЧЕНИЯ ячейки активности: «запрос
// не удался» отличимо и от «не подключался» («—» в ответе сервера), и от
// «не спрашивали» («—» у неуправляемого протокола). Текст этой ячейки
// переехал из cmd/gui в guiview по ревью BE-01: ветка «?» была написана
// литералом там, где её не проверяет ни один тест.
func TestActivityTextThreeStates(t *testing.T) {
	for _, tc := range []struct {
		name                        string
		canManage, failed, disabled bool
		hs                          string
		want                        string
	}{
		{"неуправляемый протокол — не спрашивали", false, false, false, "", "—"},
		{"неуправляемый и при отказе — по-прежнему не спрашивали", false, true, false, "", "—"},
		{"отключённый клиент", true, false, true, "2026-09-18 21:40", "отключён"},
		{"сервер ответил: подключался", true, false, false, "2026-09-18 21:40", "2026-09-18 21:40"},
		{"сервер ответил: не подключался", true, false, false, "—", "—"},
		{"ключа нет в ответе — про него не знаем", true, false, false, "", "?"},
		{"запрос не удался", true, true, false, "", "?"},
		{"запрос не удался — прежнее значение не печатается", true, true, false, "2026-09-18 21:40", "?"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := guiview.ActivityText(tc.canManage, tc.failed, tc.disabled, tc.hs)
			if got != tc.want {
				t.Errorf("ActivityText = %q, want %q", got, tc.want)
			}
		})
	}
	if guiview.ActivityText(true, true, false, "2026-09-18 21:40") ==
		guiview.ActivityText(true, false, false, "2026-09-18 21:40") {
		t.Fatal("«узнать не удалось» неотличимо от свежей даты подключения")
	}
	if guiview.ActivityText(true, true, false, "") == guiview.ActivityText(true, false, false, "—") {
		t.Fatal("«узнать не удалось» неотличимо от «не подключался»")
	}
}

// TestActivityTextArrivesFromServer — ТЕСТ ДОЕЗДА той же ячейки: отказ
// приходит боевым путём из core.Session.GetHandshakes.
func TestActivityTextArrivesFromServer(t *testing.T) {
	sess := core.NewSessionWithRunner(
		&failWgShow{inner: fakesrv.New(), err: errors.New("ssh: connection reset")},
		&core.ServerCreds{Host: "1.2.3.4", User: "root", Password: "x"})

	hs, err := sess.GetHandshakes(wgContainer())
	if err == nil {
		t.Fatal("тест перестал что-либо проверять: GetHandshakes не вернула ошибку на отказавшем транспорте")
	}
	if got, want := guiview.ActivityText(true, err != nil, false, hs["peer-1"]), "?"; got != want {
		t.Errorf("отказ сервера не доехал до ячейки активности: %q, want %q", got, want)
	}

	ok := core.NewSessionWithRunner(fakesrv.New(), &core.ServerCreds{Host: "1.2.3.4", User: "root", Password: "x"})
	hs, err = ok.GetHandshakes(wgContainer())
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
	if got, want := guiview.ActivityText(true, err != nil, false, hs[anyPeer]), "—"; got != want {
		t.Errorf("исправный сервер: %q, want %q — ответ «не подключался» обязан остаться собой", got, want)
	}
}

// reading — показание клиента id из карты stats, собранное тем же
// core.ReadPeer, что в бою (cmd/gui.rowFor).
func reading(stats map[string]core.PeerStat, failed bool, id string) core.PeerReading {
	return core.ReadPeer(stats, failed, id)
}

// TestTrafficTextThreeStates — ТЕСТ РАЗЛИЧЕНИЯ ячейки трафика (A1, место
// № 2; НЕЗНАНИЕ-ТРАФИК, место № 1): «запрос не удался», «клиента нет в
// ответе сервера», «измерен ноль» и «не спрашивали» — разные тексты, а
// честный измеренный ноль остаётся «0 B / 0 B».
func TestTrafficTextThreeStates(t *testing.T) {
	stats := map[string]core.PeerStat{
		"zero": {},
		"busy": {RxBytes: 2048, TxBytes: 1000},
	}
	for _, tc := range []struct {
		name      string
		canManage bool
		disabled  bool
		r         core.PeerReading
		want      string
	}{
		{"неуправляемый протокол", false, false, reading(stats, false, "zero"), "—"},
		{"измеренный ноль — настоящий ноль", true, false, reading(stats, false, "zero"), "0 B / 0 B"},
		{"измеренный трафик", true, false, reading(stats, false, "busy"), "2.0 KB / 1.0 KB"},
		{"клиента нет в ответе сервера", true, false, reading(stats, false, "gone"), "?"},
		{"статистику получить не удалось", true, false, reading(nil, true, "zero"), "?"},
		{"не удалось — прежние числа не печатаются", true, false, reading(stats, true, "busy"), "?"},
		{"отключённый клиент — как в колонке активности", true, true, reading(stats, false, "gone"), "отключён"},
		{"незаполненное показание — не ноль", true, false, core.PeerReading{}, "?"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := guiview.TrafficText(tc.canManage, tc.disabled, tc.r)
			if got != tc.want {
				t.Errorf("TrafficText = %q, want %q", got, tc.want)
			}
		})
	}
	zero := guiview.TrafficText(true, false, reading(stats, false, "zero"))
	if guiview.TrafficText(true, false, reading(stats, false, "gone")) == zero {
		t.Fatal("«клиента нет в статистике» неотличимо от измеренного нуля — ровно тот дефект, который чинится")
	}
	if guiview.TrafficText(true, false, reading(nil, true, "zero")) == zero {
		t.Fatal("\"не удалось получить\" неотличимо от измеренного нуля")
	}
}

// TestTrafficTextArrivesFromServer — ТЕСТ ДОЕЗДА отказа: `wg show`
// отказывает боевым путём, core.Session.GetPeerStats возвращает ошибку, и
// ячейка — «?», а не «0 B / 0 B».
func TestTrafficTextArrivesFromServer(t *testing.T) {
	sess := core.NewSessionWithRunner(
		&failWgShow{inner: fakesrv.New(), err: errors.New("ssh: connection reset")},
		&core.ServerCreds{Host: "1.2.3.4", User: "root", Password: "x"})

	stats, err := sess.GetPeerStats(wgContainer())
	if err == nil {
		t.Fatal("тест перестал что-либо проверять: GetPeerStats не вернула ошибку на отказавшем транспорте")
	}
	if got, want := guiview.TrafficText(true, false, core.ReadPeer(stats, err != nil, "peer-1")), "?"; got != want {
		t.Errorf("отказ сервера не доехал до ячейки трафика: %q, want %q", got, want)
	}
}

// desync воспроизводит БОЕВОЙ рассинхрон (см. core/peerread_test.go,
// TestPeerAbsentInBattleDesync): сначала штатно добавлен Carol, затем рекей
// первого клиента падает, и откат возвращает файлы, но не рантайм. Итог:
// subject и bystander включены, есть в clientsTable и ОТСУТСТВУЮТ в
// ответе `wg show`; Carol в ответе есть с нулевым трафиком — честный ноль.
func desync(t *testing.T) (sess *core.Session, subject, bystander, carol string) {
	t.Helper()
	srv := fakesrv.New()
	sess = core.NewSessionWithRunner(srv, &core.ServerCreds{Host: "1.2.3.4", User: "root", Password: "x"})
	c := wgContainer()
	add, err := sess.PlanAddUser(c, "Carol")
	if err != nil {
		t.Fatalf("PlanAddUser: %v", err)
	}
	if _, err := sess.Apply(add); err != nil {
		t.Fatalf("Apply(Carol): %v", err)
	}
	clients, err := sess.LoadClients(c)
	if err != nil || len(clients) != 3 {
		t.Fatalf("LoadClients: %v, %d", err, len(clients))
	}
	for _, cl := range clients {
		if cl.Name() == "Carol" {
			carol = cl.ClientID
		} else if subject == "" {
			subject = cl.ClientID
		} else {
			bystander = cl.ClientID
		}
	}
	p, err := sess.PlanRekey(c, subject)
	if err != nil {
		t.Fatalf("PlanRekey: %v", err)
	}
	srv.DropPeerOnSync = bystander
	srv.FailSyncconfFrom = 3 // #1 — Carol, #2 — рекей, #3 — повтор при откате
	if _, err := sess.Apply(p); err == nil {
		t.Fatal("Apply(рекей): ожидалась ошибка — рассинхрон не воспроизвёлся")
	}
	srv.DropPeerOnSync, srv.FailSyncconfFrom = "", 0
	return sess, subject, bystander, carol
}

// TestTrafficTextAbsentArrivesFromServer — ТЕСТ ДОЕЗДА «клиента нет в
// статистике» (НЕЗНАНИЕ-ТРАФИК, место № 1): отсутствие возникает боевым
// путём, настоящий GetPeerStats отвечает БЕЗ ошибки, и всё равно ячейка
// включённого клиента — «?», а у присутствующего Carol — честный ноль.
func TestTrafficTextAbsentArrivesFromServer(t *testing.T) {
	sess, subject, bystander, carol := desync(t)
	stats, err := sess.GetPeerStats(wgContainer())
	if err != nil {
		t.Fatalf("GetPeerStats после рассинхрона: %v — сервер обязан ОТВЕТИТЬ, иначе проверяется не тот случай", err)
	}
	for _, id := range []string{subject, bystander} {
		if got := guiview.TrafficText(true, false, core.ReadPeer(stats, false, id)); got != "?" {
			t.Errorf("включённый клиент, которого нет в ответе сервера: %q, want \"?\"", got)
		}
	}
	if got := guiview.TrafficText(true, false, core.ReadPeer(stats, false, carol)); got != "0 B / 0 B" {
		t.Errorf("клиент, который есть в ответе с нулём: %q, want \"0 B / 0 B\" — честный ноль обязан остаться нулём", got)
	}
}

// TestDeleteCardActivityAbsentArrivesFromServer — место № 4 (найдено при
// сверке): карточка удаления при клиенте, которого нет в ответе сервера,
// писала «Подключений не было.». Боевой путь — тот же рассинхрон.
func TestDeleteCardActivityAbsentArrivesFromServer(t *testing.T) {
	sess, subject, _, carol := desync(t)
	hs, err := sess.GetHandshakes(wgContainer())
	if err != nil {
		t.Fatalf("GetHandshakes: %v", err)
	}
	const want = "Клиента нет в статистике сервера: сейчас сервер его не принимает.\n" +
		"Были ли подключения раньше — неизвестно."
	if got := guiview.DeleteCardActivity(hs, subject, nil, false); got != want {
		t.Errorf("карточка удаления клиента, которого нет в ответе сервера:\n%q\nwant\n%q", got, want)
	}
	if got := guiview.DeleteCardActivity(hs, carol, nil, false); got != "Подключений не было." {
		t.Errorf("клиент есть в ответе и не подключался: %q, want \"Подключений не было.\"", got)
	}
}
