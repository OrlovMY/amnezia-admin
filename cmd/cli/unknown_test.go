package main

import (
	"errors"
	"strings"
	"testing"

	"amnezia-admin/core"
	"amnezia-admin/internal/fakesrv"
)

// ---------- Место № 5 задания A1: карточка CLI перед необратимым действием ----------
//
// ТОТ ЖЕ ДЕФЕКТ, ЧТО В GUI, ТОЛЬКО В КОНСОЛИ. buildCard подставляла «—» и
// когда клиент не подключался, и когда статистику получить не удалось:
// GetHandshakes глотала ошибку и возвращала пустую карту. Карточка печатается
// перед del/rekey/toggle — то есть перед НЕОБРАТИМЫМ действием.

// failWgShow — транспорт поверх fakesrv, отказывающий ровно на `wg show wg0
// dump`: ошибка приходит тем же путём, что в бою.
type failWgShow struct {
	inner  *fakesrv.Server
	err    error
	called bool
}

func (f *failWgShow) Run(cmd string, stdin []byte) (string, error) {
	if strings.Contains(cmd, "wg show wg0 dump") {
		f.called = true
		return "", f.err
	}
	return f.inner.Run(cmd, stdin)
}

func a1Container() *core.Container {
	return &core.Container{Name: "amnezia-awg", Dir: "/opt/amnezia/awg", Proto: "AmneziaWG", Managed: true}
}

func a1Creds() *core.ServerCreds {
	return &core.ServerCreds{Host: "1.2.3.4", User: "root", Password: "x"}
}

// TestCardLastSeenThreeStates — ТЕСТ РАЗЛИЧЕНИЯ места № 5: три состояния
// поля «Последнее подключение» дают три РАЗНЫЕ строки карточки. Сравнение
// строк целиком, а не Contains: Contains прошёл бы и на тексте, где «не
// удалось» дописано рядом с прежним «—».
func TestCardLastSeenThreeStates(t *testing.T) {
	base := testCard()

	was := base
	was.LastSeen = "2024-05-06 07:08"
	none := base
	none.LastSeen = "—"
	unknown := base
	unknown.LastSeen = "—"
	unknown.LastSeenUnknown = true

	for _, tc := range []struct {
		name string
		card ActionCard
		want string
	}{
		{"была активность", was, "  Последнее подключение:  2024-05-06 07:08"},
		{"подключений не было", none, "  Последнее подключение:  —"},
		{"узнать не удалось", unknown, "  Последнее подключение:  не удалось получить данные"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			line := lastSeenLineOf(t, renderCard(tc.card))
			if line != tc.want {
				t.Errorf("строка карточки = %q\n                want %q", line, tc.want)
			}
		})
	}

	// Различитель: три состояния — три разные карточки целиком.
	a, b, c := renderCard(was), renderCard(none), renderCard(unknown)
	if a == b || b == c || a == c {
		t.Fatal("состояния карточки CLI неразличимы — «не знаем» снова выглядит как «не подключался»")
	}

	// И предупреждение о незнании стоит ровно там, где стоит предупреждение
	// об активности, — иначе его не увидит тот, кто смотрит на эту строку.
	const warnUnknown = "⚠ Внимание: статистику с сервера получить не удалось — неизвестно, пользуется ли клиент этим доступом."
	const warnActivity = "⚠ Внимание: у этого клиента была активность."
	if !strings.Contains(c, warnUnknown) {
		t.Errorf("карточка «узнать не удалось» без предупреждения:\n%s", c)
	}
	if strings.Contains(c, warnActivity) {
		t.Errorf("карточка «узнать не удалось» утверждает про активность:\n%s", c)
	}
	if !strings.Contains(a, warnActivity) {
		t.Errorf("карточка «была активность» потеряла предупреждение:\n%s", a)
	}
	if strings.Contains(b, warnUnknown) || strings.Contains(b, warnActivity) {
		t.Errorf("карточка «подключений не было» предупреждает о том, чего нет:\n%s", b)
	}
}

// TestBuildCardUnknownArrivesFromServer — ТЕСТ ДОЕЗДА места № 5: отказ
// сервера возникает боевым путём (транспорт отказывает на `wg show`), идёт
// через core.Session.GetHandshakes и доезжает до карточки признаком
// LastSeenUnknown и её текстом.
func TestBuildCardUnknownArrivesFromServer(t *testing.T) {
	r := &failWgShow{inner: fakesrv.New(), err: errors.New("ssh: connection reset")}
	sess := core.NewSessionWithRunner(r, a1Creds())
	cl := core.ClientEntry{ClientID: "k1", UserData: map[string]any{"clientName": "Alice"}}

	card := buildCard(sess, a1Container(), cl, "удалить")
	if !r.called {
		t.Fatal("тест ПЕРЕСТАЛ ЧТО-ЛИБО ПРОВЕРЯТЬ: buildCard не спрашивал сервер вовсе")
	}
	if !card.LastSeenUnknown {
		t.Fatalf("LastSeenUnknown = false при отказе сервера: карточка перед необратимым действием "+
			"снова печатает %q и не отличает «не подключался» от «не знаем»", card.LastSeen)
	}
	if got, want := lastSeenLineOf(t, renderCard(card)), "  Последнее подключение:  не удалось получить данные"; got != want {
		t.Errorf("строка карточки = %q, want %q", got, want)
	}
}

// TestBuildCardFreshDataArrives — вторая сторона доезда: на ИСПРАВНОМ
// сервере признак незнания НЕ выставляется. Без неё правка «всегда писать
// не удалось» прошла бы зелёной.
func TestBuildCardFreshDataArrives(t *testing.T) {
	// До задания НЕЗНАНИЕ-ТРАФИК тест брал ключ "k1", которого НЕТ среди
	// peer'ов fakesrv, и требовал «—» — то есть закреплял дефект: отсутствие
	// в ответе печаталось «не подключался». Теперь клиент берётся из
	// настоящей clientsTable fakesrv и в ответе есть.
	srv := fakesrv.New()
	sess := core.NewSessionWithRunner(srv, a1Creds())
	clients, err := sess.LoadClients(a1Container())
	if err != nil || len(clients) == 0 {
		t.Fatalf("LoadClients: %v, %d", err, len(clients))
	}
	cl := clients[0]

	card := buildCard(sess, a1Container(), cl, "удалить")
	if card.LastSeenUnknown || card.LastSeenAbsent {
		t.Fatalf("на исправном сервере клиент из ответа: Unknown=%v Absent=%v", card.LastSeenUnknown, card.LastSeenAbsent)
	}
	if card.LastSeen != "—" {
		t.Errorf("LastSeen = %q, want \"—\" (клиент есть в ответе fakesrv без рукопожатия — "+
			"ответ означает «не подключался»)", card.LastSeen)
	}
}

// cliDesync — боевой рассинхрон на fakesrv (см. core/peerread_test.go):
// штатно добавлен Carol, рекей первого клиента не применился, откат вернул
// файлы, но не рантайм. Возвращает сессию и имена включённых клиентов,
// которых нет в ответе `wg show`; Carol в ответе есть с нулём.
func cliDesync(t *testing.T) (*core.Session, []string) {
	t.Helper()
	srv := fakesrv.New()
	sess := core.NewSessionWithRunner(srv, a1Creds())
	c := a1Container()
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
	var subject, bystander string
	var absent []string
	for _, cl := range clients {
		switch {
		case cl.Name() == "Carol":
		case subject == "":
			subject = cl.ClientID
			absent = append(absent, cl.Name())
		default:
			bystander = cl.ClientID
			absent = append(absent, cl.Name())
		}
	}
	p, err := sess.PlanRekey(c, subject)
	if err != nil {
		t.Fatalf("PlanRekey: %v", err)
	}
	srv.DropPeerOnSync = bystander
	srv.FailSyncconfFrom = 3
	if _, err := sess.Apply(p); err == nil {
		t.Fatal("Apply(рекей): ожидалась ошибка — рассинхрон не воспроизвёлся")
	}
	srv.DropPeerOnSync, srv.FailSyncconfFrom = "", 0
	return sess, absent
}

// TestCardAbsentDiffersFromNone — ТЕСТ РАЗЛИЧЕНИЯ карточки CLI (место № 4):
// «клиента нет в ответе» — своя строка, отличная и от «—», и от «не
// удалось».
func TestCardAbsentDiffersFromNone(t *testing.T) {
	none := testCard()
	none.LastSeen = "—"
	absent := none
	absent.LastSeenAbsent = true
	unknown := none
	unknown.LastSeenUnknown = true
	if got, want := lastSeenLineOf(t, renderCard(absent)),
		"  Последнее подключение:  нет в статистике сервера (сейчас сервер его не принимает)"; got != want {
		t.Errorf("строка карточки = %q\n                want %q", got, want)
	}
	if renderCard(absent) == renderCard(none) || renderCard(absent) == renderCard(unknown) {
		t.Fatal("«клиента нет в статистике» неотличимо от «не подключался» или от «не удалось»")
	}
}

// TestBuildCardAbsentArrivesFromServer — ТЕСТ ДОЕЗДА места № 4: клиент
// отсутствует в ответе боевым путём (рассинхрон), GetHandshakes отвечает
// БЕЗ ошибки, и карточка говорит «нет в статистике», а не «—».
func TestBuildCardAbsentArrivesFromServer(t *testing.T) {
	sess, absent := cliDesync(t)
	clients, err := sess.LoadClients(a1Container())
	if err != nil {
		t.Fatal(err)
	}
	for _, cl := range clients {
		card := buildCard(sess, a1Container(), cl, "удалить")
		isAbsent := cl.Name() != "Carol"
		if card.LastSeenUnknown {
			t.Fatalf("%s: LastSeenUnknown на ответившем сервере — проверяется не тот случай", cl.Name())
		}
		if card.LastSeenAbsent != isAbsent {
			t.Errorf("%s: LastSeenAbsent = %v, want %v (нет в ответе: %v)", cl.Name(), card.LastSeenAbsent, isAbsent, absent)
		}
	}
}

// ---------- Место № 2 задания НЕЗНАНИЕ-ТРАФИК: таблица `list` в CLI ----------

// TestListCellsThreeStates — ТЕСТ РАЗЛИЧЕНИЯ ячеек таблицы list: «запрос не
// удался», «клиента нет в ответе», «измерен ноль» и «отключён» — разные
// тексты; честный ноль остаётся «0 B / 0 B» и «—».
func TestListCellsThreeStates(t *testing.T) {
	stats := map[string]core.PeerStat{"zero": {}, "busy": {RxBytes: 2048, TxBytes: 1000}}
	for _, tc := range []struct {
		name          string
		disabled      bool
		r             core.PeerReading
		wantAct, want string
	}{
		{"измерен ноль", false, core.ReadPeer(stats, false, "zero"), "—", "0 B / 0 B"},
		{"измерен трафик", false, core.ReadPeer(stats, false, "busy"), "—", "2.0 KB / 1.0 KB"},
		{"клиента нет в ответе", false, core.ReadPeer(stats, false, "gone"), "?", "?"},
		{"запрос не удался", false, core.ReadPeer(nil, true, "zero"), "?", "?"},
		{"отключён", true, core.ReadPeer(stats, false, "gone"), "(откл.)", "(откл.)"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := listActivityText(tc.disabled, tc.r); got != tc.wantAct {
				t.Errorf("активность = %q, want %q", got, tc.wantAct)
			}
			if got := listTrafficText(tc.disabled, tc.r); got != tc.want {
				t.Errorf("трафик = %q, want %q", got, tc.want)
			}
		})
	}
	failed, absent := listStatsNote(true, 0), listStatsNote(false, 2)
	if failed == "" || absent == "" || failed == absent || listStatsNote(false, 0) != "" {
		t.Errorf("пояснение под таблицей: отказ=%q нет-в-ответе=%q норма=%q — причины обязаны различаться, "+
			"а при полном ответе пояснения нет", failed, absent, listStatsNote(false, 0))
	}
}

// listOut — вывод НАСТОЯЩЕГО listUsers (без цвета: вывод не в терминал) и
// строка таблицы клиента name.
func listRow(t *testing.T, out, name string) string {
	t.Helper()
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, name) {
			return line
		}
	}
	t.Fatalf("в выводе list нет строки %q:\n%s", name, out)
	return ""
}

func runList(t *testing.T, sess *core.Session) string {
	t.Helper()
	var b strings.Builder
	if _, err := listUsers(&b, sess, a1Container()); err != nil {
		t.Fatalf("listUsers: %v", err)
	}
	return b.String()
}

// TestListAbsentArrivesFromServer — ТЕСТ ДОЕЗДА «клиента нет в
// статистике» по пути list: рассинхрон на fakesrv, настоящий GetPeerStats
// отвечает без ошибки, строки отсутствующих — «?», Carol — честный ноль, и
// под таблицей названа причина.
func TestListAbsentArrivesFromServer(t *testing.T) {
	sess, absent := cliDesync(t)
	out := runList(t, sess)
	for _, name := range absent {
		row := listRow(t, out, name)
		if strings.Contains(row, "0 B / 0 B") || strings.Contains(row, " — ") {
			t.Errorf("строка отсутствующего в статистике %q утверждает измерение:\n%s", name, row)
		}
		if strings.Count(row, "?") < 2 {
			t.Errorf("строка отсутствующего в статистике %q без «?» в активности и трафике:\n%s", name, row)
		}
	}
	if row := listRow(t, out, "Carol"); !strings.Contains(row, "0 B / 0 B") {
		t.Errorf("Carol есть в статистике с нулём — честный ноль потерян:\n%s", row)
	}
	if !strings.Contains(out, "Нет в статистике сервера: 2 ") {
		t.Errorf("под таблицей не названа причина «?» (нет в статистике: 2):\n%s", out)
	}
}

// TestListFailedArrivesFromServer — ТЕСТ ДОЕЗДА отказа по пути list:
// транспорт отказывает на `wg show` — ошибка больше не отбрасывается.
func TestListFailedArrivesFromServer(t *testing.T) {
	r := &failWgShow{inner: fakesrv.New(), err: errors.New("ssh: connection reset")}
	out := runList(t, core.NewSessionWithRunner(r, a1Creds()))
	if !r.called {
		t.Fatal("тест ПЕРЕСТАЛ ЧТО-ЛИБО ПРОВЕРЯТЬ: list не спрашивал статистику")
	}
	if strings.Contains(out, "0 B / 0 B") {
		t.Errorf("отказ статистики печатается измеренным нулём:\n%s", out)
	}
	if !strings.Contains(out, "Статистику с сервера получить не удалось") {
		t.Errorf("под таблицей не сказано, что статистику получить не удалось:\n%s", out)
	}
	if strings.Contains(out, "Нет в статистике сервера") {
		t.Errorf("при отказе запроса названа чужая причина:\n%s", out)
	}
}

// TestListMeasuredZeroStaysZero — исправный сервер: все клиенты в ответе с
// нулём; «?» и пояснений нет. Без этой стороны правка «всегда „?“» прошла бы.
func TestListMeasuredZeroStaysZero(t *testing.T) {
	out := runList(t, core.NewSessionWithRunner(fakesrv.New(), a1Creds()))
	if strings.Count(out, "0 B / 0 B") != 2 || strings.Contains(out, "?") {
		t.Errorf("исправный сервер: ожидались два честных «0 B / 0 B» и ни одного «?»:\n%s", out)
	}
}

// lastSeenLineOf достаёт из карточки строку «Последнее подключение» без
// ANSI-раскраски: тест сверяет текст, а не то, включён ли цвет в консоли.
func lastSeenLineOf(t *testing.T, card string) string {
	t.Helper()
	for _, line := range strings.Split(card, "\n") {
		if strings.Contains(line, "Последнее подключение:") {
			return strings.TrimRight(line, "\r")
		}
	}
	t.Fatalf("сторож ПЕРЕСТАЛ ЧТО-ЛИБО ПРОВЕРЯТЬ: в карточке нет строки «Последнее подключение»:\n%s", card)
	return ""
}
