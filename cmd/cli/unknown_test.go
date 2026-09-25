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

// TestCardLastSeenStates — ТЕСТ ПЕЧАТИ карточки: каждый исход
// core.ClassifyLastSeen даёт свою строку «Последнее подключение» и своё
// предупреждение (или его отсутствие). Сравнение строк целиком. Само
// правило классификации проверяет core.TestClassifyLastSeenTable, и
// ClassifyLastSeen зовут и buildCard, и GUI — единственное место.
func TestCardLastSeenStates(t *testing.T) {
	const (
		warnUnknown  = "⚠ Внимание: статистику с сервера получить не удалось — неизвестно, пользуется ли клиент этим доступом."
		warnActivity = "⚠ Внимание: у этого клиента была активность."
		warnAbsent   = "⚠ Клиента нет в статистике сервера — неизвестно, подключался ли он раньше."
	)
	all := []string{warnUnknown, warnActivity, warnAbsent}
	for _, tc := range []struct {
		name, line, warn string
		seen             core.LastSeen
	}{
		{"была активность", "  Последнее подключение:  2024-05-06 07:08", warnActivity,
			core.LastSeen{State: core.SeenWas, When: "2024-05-06 07:08"}},
		{"подключений не было", "  Последнее подключение:  —", "", core.LastSeen{State: core.SeenNever}},
		{"узнать не удалось", "  Последнее подключение:  не удалось получить данные", warnUnknown,
			core.LastSeen{State: core.SeenFailed}},
		{"нет в ответе сервера", "  Последнее подключение:  нет в статистике сервера (сейчас сервер его не принимает)",
			warnAbsent, core.LastSeen{State: core.SeenAbsent}},
		{"клиент отключён", "  Последнее подключение:  неизвестно (клиент отключён)", "",
			core.LastSeen{State: core.SeenDisabled}},
		{"незаполненный исход — незнание, не «—»", "  Последнее подключение:  не удалось получить данные",
			warnUnknown, core.LastSeen{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			card := testCard()
			card.Seen = tc.seen
			out := renderCard(card)
			if line := lastSeenLineOf(t, out); line != tc.line {
				t.Errorf("строка карточки = %q\n                want %q", line, tc.line)
			}
			for _, w := range all {
				if has := strings.Contains(out, w); has != (w == tc.warn) {
					t.Errorf("предупреждение %q: есть=%v, ожидалось %v\n%s", w, has, w == tc.warn, out)
				}
			}
		})
	}
}

// cardFor — карточка НАСТОЯЩЕГО buildCard для клиента name из настоящей
// clientsTable сессии.
func cardFor(t *testing.T, sess *core.Session, name string) ActionCard {
	t.Helper()
	clients, err := sess.LoadClients(a1Container())
	if err != nil {
		t.Fatal(err)
	}
	for _, cl := range clients {
		if cl.Name() == name {
			return buildCard(sess, a1Container(), cl, "удалить")
		}
	}
	t.Fatalf("клиента %q нет в clientsTable", name)
	return ActionCard{}
}

// TestBuildCardUnknownArrivesFromServer — ТЕСТ ДОЕЗДА отказа: транспорт
// отказывает на `wg show`, GetHandshakes возвращает ошибку, и исход
// карточки — SeenFailed.
func TestBuildCardUnknownArrivesFromServer(t *testing.T) {
	r := &failWgShow{inner: fakesrv.New(), err: errors.New("ssh: connection reset")}
	sess := core.NewSessionWithRunner(r, a1Creds())
	card := cardFor(t, sess, "Alice")
	if !r.called {
		t.Fatal("тест ПЕРЕСТАЛ ЧТО-ЛИБО ПРОВЕРЯТЬ: buildCard не спрашивал сервер вовсе")
	}
	if card.Seen.State != core.SeenFailed {
		t.Fatalf("исход при отказе сервера = %d, want SeenFailed", card.Seen.State)
	}
	if got, want := lastSeenLineOf(t, renderCard(card)), "  Последнее подключение:  не удалось получить данные"; got != want {
		t.Errorf("строка карточки = %q, want %q", got, want)
	}
}

// TestBuildCardFreshDataArrives — исправный сервер: клиент из ответа без
// рукопожатия — «не подключался». До задания НЕЗНАНИЕ-ТРАФИК тест брал
// ключ "k1", которого у fakesrv нет, и требовал «—», то есть закреплял
// дефект.
func TestBuildCardFreshDataArrives(t *testing.T) {
	card := cardFor(t, core.NewSessionWithRunner(fakesrv.New(), a1Creds()), "Alice")
	if card.Seen.State != core.SeenNever {
		t.Fatalf("исход = %d, want SeenNever (клиент есть в ответе fakesrv без рукопожатия)", card.Seen.State)
	}
}

// TestBuildCardDisabledArrivesFromServer — ТЕСТ ДОЕЗДА «отключён»: клиент
// отключён настоящими PlanSetEnabled/Apply (его peer вырезан из рантайма),
// карточка включения говорит «неизвестно (клиент отключён)», а не «нет в
// статистике сервера».
func TestBuildCardDisabledArrivesFromServer(t *testing.T) {
	sess := cliDisabled(t)
	card := cardFor(t, sess, "Alice")
	if card.Seen.State != core.SeenDisabled {
		t.Fatalf("отключённый клиент: исход = %d, want SeenDisabled", card.Seen.State)
	}
	if got, want := lastSeenLineOf(t, renderCard(card)), "  Последнее подключение:  неизвестно (клиент отключён)"; got != want {
		t.Errorf("строка карточки = %q, want %q", got, want)
	}
}

// cliDisabled — Alice отключена настоящими PlanSetEnabled/Apply на fakesrv.
func cliDisabled(t *testing.T) *core.Session {
	t.Helper()
	sess := core.NewSessionWithRunner(fakesrv.New(), a1Creds())
	clients, err := sess.LoadClients(a1Container())
	if err != nil || len(clients) < 2 || clients[0].Name() != "Alice" {
		t.Fatalf("LoadClients: %v, %+v", err, clients)
	}
	p, err := sess.PlanSetEnabled(a1Container(), clients[0].ClientID, false)
	if err != nil {
		t.Fatalf("PlanSetEnabled: %v", err)
	}
	if _, err := sess.Apply(p); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	return sess
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

// TestBuildCardAbsentArrivesFromServer — ТЕСТ ДОЕЗДА «нет в ответе»:
// клиент отсутствует боевым путём (рассинхрон), GetHandshakes отвечает БЕЗ
// ошибки, и исход карточки включённого клиента — SeenAbsent; у Carol из
// ответа — SeenNever.
func TestBuildCardAbsentArrivesFromServer(t *testing.T) {
	sess, absent := cliDesync(t)
	for _, name := range absent {
		if st := cardFor(t, sess, name).Seen.State; st != core.SeenAbsent {
			t.Errorf("%s: исход = %d, want SeenAbsent", name, st)
		}
	}
	if st := cardFor(t, sess, "Carol").Seen.State; st != core.SeenNever {
		t.Errorf("Carol: исход = %d, want SeenNever", st)
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
	// Сортировка list (core.SortByActivity): неизвестные — после всех
	// измеренных, даже после «не подключался» (блокер 2 ревью).
	if row := listRow(t, out, "Carol"); !strings.HasPrefix(row, "1 ") {
		t.Errorf("Carol — единственный измеренный — не первой строкой: неизвестные отсортированы как ноль:\n%s", out)
	}
	if row := listRow(t, out, "Carol"); !strings.Contains(row, "0 B / 0 B") {
		t.Errorf("Carol есть в статистике с нулём — честный ноль потерян:\n%s", row)
	}
	if !strings.Contains(out, "Клиентов нет в статистике сервера: 2.") {
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
	if strings.Contains(out, "Клиентов нет в статистике сервера") {
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

// TestListDisabledArrivesFromServer — ТЕСТ ДОЕЗДА отключённого по пути list
// (дыры D1 и D3 ревью QA-01): Alice отключена настоящими PlanSetEnabled/
// Apply и отсутствует в ответе `wg show`. В её строке — «(откл.)» в
// активности И в трафике, ни «?», ни «0 B / 0 B»; под таблицей НЕТ строки
// «Клиентов нет в статистике»: отсутствие отключённого — штатное.
func TestListDisabledArrivesFromServer(t *testing.T) {
	out := runList(t, cliDisabled(t))
	row := listRow(t, out, "Alice")
	if strings.Count(row, "(откл.)") != 2 {
		t.Errorf("строка отключённой Alice: ожидалось «(откл.)» в активности и в трафике:\n%s", row)
	}
	if strings.Contains(row, "?") || strings.Contains(row, "0 B / 0 B") {
		t.Errorf("строка отключённой Alice утверждает незнание или измерение:\n%s", row)
	}
	if strings.Contains(out, "Клиентов нет в статистике сервера") {
		t.Errorf("отключённый клиент посчитан в строку-причину «нет в статистике»:\n%s", out)
	}
	if row := listRow(t, out, "Bob"); !strings.Contains(row, "0 B / 0 B") {
		t.Errorf("включённый Bob в ответе с нулём — честный ноль потерян:\n%s", row)
	}
}
