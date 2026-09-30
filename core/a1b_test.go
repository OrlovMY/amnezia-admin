package core

// Тесты A1б (сплошная сверка по четырём признакам CLAUDE.md) для core. Все
// пользуются только API, существовавшим на f0febbd (Session через
// NewSessionWithRunner, LoadClients, AddUser, GetPeerStats, ReadPeer,
// fakesrv), поэтому на f0febbd они компилируются и ПАДАЮТ поведением.

import (
	"encoding/json"
	"strings"
	"testing"

	"amnezia-admin/internal/fakesrv"
)

// rewriteRunner — настоящий fakesrv, у которого ответ на команды, содержащие
// match, подменён reply. Это «подставной ответ сервера» боевым путём: всё
// остальное (CAS, запись, verify) идёт через fakesrv как есть.
type rewriteRunner struct {
	inner *fakesrv.Server
	match string
	reply func(real string) string
}

func (r *rewriteRunner) Run(cmd string, stdin []byte) (string, error) {
	out, err := r.inner.Run(cmd, stdin)
	if err == nil && strings.Contains(cmd, r.match) {
		return r.reply(out), nil
	}
	return out, err
}

func a1bSession(r Runner) *Session {
	return NewSessionWithRunner(r, &ServerCreds{Host: "203.0.113.10", User: "root", Password: "x"})
}

const probeCmd = "test -f"

// ---------- 1. probeClientsTable: «не yes» ≠ «нет файла» (признак 1) ----------

// TestA1bProbeReplyThreeStates — ТЕСТ РАЗЛИЧЕНИЯ. Ответ пробы «yes» —
// таблица есть; «no» — таблицы нет, это штатно (пустой список, без ошибки);
// всё прочее — НЕ ЗНАЕМ, и это ошибка. На f0febbd пустой и посторонний
// ответ давали пустой список без ошибки — то есть «пользователей нет».
func TestA1bProbeReplyThreeStates(t *testing.T) {
	cases := []struct {
		name    string
		reply   string
		wantErr bool
		wantN   int
	}{
		{"yes — таблица есть", "yes\n", false, 2},
		{"no — таблицы нет по существу", "no\n", false, 0},
		{"пустой ответ — не знаем", "", true, 0},
		{"посторонний ответ — не знаем", "OCI runtime exec failed\n", true, 0},
		{"оба слова — не знаем", "yes\nno\n", true, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rep := c.reply
			s := a1bSession(&rewriteRunner{inner: fakesrv.New(), match: probeCmd, reply: func(string) string { return rep }})
			clients, err := s.LoadClients(awgContainer())
			if c.wantErr {
				if err == nil {
					t.Fatalf("ответ пробы %q прочитан как ответ: %d пользователей, без ошибки — "+
						"«узнать не удалось» выдано за «таблицы нет»", c.reply, len(clients))
				}
				return
			}
			if err != nil {
				t.Fatalf("ответ %q: неожиданная ошибка %v", c.reply, err)
			}
			if len(clients) != c.wantN {
				t.Fatalf("ответ %q: %d пользователей, ожидалось %d", c.reply, len(clients), c.wantN)
			}
		})
	}
}

// TestA1bProbeGarbageDoesNotWipeTable — ТЕСТ ДОЕЗДА до необратимого
// действия. Сервер ответил на пробу пустотой (вывод съеден), а таблица на
// месте. На f0febbd AddUser принимал это за «таблицы нет», CAS повторял ту
// же пробу и пропускал запись, и clientsTable перезаписывалась таблицей из
// ОДНОГО нового пользователя — Alice и Bob стирались. Ровно Critical аудита
// 2026-09-14, вернувшийся через третий исход пробы.
func TestA1bProbeGarbageDoesNotWipeTable(t *testing.T) {
	srv := fakesrv.New()
	before, ok := srv.File("/opt/amnezia/awg/clientsTable")
	if !ok {
		t.Fatal("тест перестал что-либо проверять: у fakesrv нет clientsTable")
	}
	s := a1bSession(&rewriteRunner{inner: srv, match: probeCmd, reply: func(string) string { return "" }})
	// Сверяется ПРИЧИНА (ревью QA-01, п.2): AddUser, упавший по любой другой
	// причине, прошёл бы проверку «есть ошибка».
	switch _, err := s.AddUser(awgContainer(), "Mallory"); {
	case err == nil:
		t.Error("AddUser завершился успехом, хотя есть ли clientsTable, неизвестно")
	case !strings.Contains(err.Error(), "непонятный ответ сервера") ||
		!strings.Contains(err.Error(), "/opt/amnezia/awg/clientsTable, неизвестно"):
		t.Errorf("AddUser упал не по причине пробы: %v", err)
	}
	after, _ := srv.File("/opt/amnezia/awg/clientsTable")
	if string(after) != string(before) {
		var list []ClientEntry
		_ = json.Unmarshal(after, &list)
		t.Fatalf("clientsTable перезаписана при неизвестном ответе пробы: было 2 записи, стало %d — "+
			"существующие пользователи стёрты", len(list))
	}
}

// ---------- 2. parsePeerStats: неразобранное ≠ ноль (признак 2) ----------

// corruptFirstPeer портит в ответе `wg show` первое поле number (0 — время
// рукопожатия, 1 — принято, 2 — передано) первой строки peer'а, либо, при
// number < 0, обрезает строку до четырёх полей.
func corruptFirstPeer(number int) func(string) string {
	return func(real string) string {
		lines := strings.Split(real, "\n")
		for i := 1; i < len(lines); i++ {
			f := strings.Split(lines[i], "\t")
			if len(f) < 8 {
				continue
			}
			if number < 0 {
				lines[i] = strings.Join(f[:4], "\t")
			} else {
				f[4+number] = "n/a"
				lines[i] = strings.Join(f, "\t")
			}
			break
		}
		return strings.Join(lines, "\n")
	}
}

// TestA1bUnparsedStatsIsNotZero — ТЕСТ РАЗЛИЧЕНИЯ: неразобранный ответ
// `wg show` — «статистику получить не удалось» (ошибка и core.PeerFailed),
// а не «измерено: ноль» и не «нет в ответе». Честный нулевой ответ остаётся
// измеренным нулём. На f0febbd ParseInt-ошибка давала 0, короткая строка
// пропускалась молча, и GetPeerStats отвечал без ошибки.
func TestA1bUnparsedStatsIsNotZero(t *testing.T) {
	cases := []struct {
		name    string
		corrupt func(string) string
	}{
		{"время рукопожатия не число", corruptFirstPeer(0)},
		{"принято байт не число", corruptFirstPeer(1)},
		{"передано байт не число", corruptFirstPeer(2)},
		{"строка peer'а короче восьми полей", corruptFirstPeer(-1)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := a1bSession(&rewriteRunner{inner: fakesrv.New(), match: "wg show wg0 dump", reply: c.corrupt})
			stats, err := s.GetPeerStats(awgContainer())
			if err == nil {
				t.Fatalf("неразобранный ответ принят как статистика (%d peer'ов) — "+
					"непонятое поле уезжает к человеку нулём", len(stats))
			}
			clients, lerr := s.LoadClients(awgContainer())
			if lerr != nil || len(clients) == 0 {
				t.Fatalf("LoadClients: %v", lerr)
			}
			if st := ReadPeer(stats, err != nil, clients[0].ClientID).State; st != PeerFailed {
				t.Errorf("показание клиента = %v, ожидалось PeerFailed", st)
			}
		})
	}

	// Честный ноль — измерение, а не незнание.
	s := a1bSession(fakesrv.New())
	stats, err := s.GetPeerStats(awgContainer())
	if err != nil {
		t.Fatalf("исправный ответ: %v", err)
	}
	clients, _ := s.LoadClients(awgContainer())
	r := ReadPeer(stats, false, clients[0].ClientID)
	if st, ok := r.Measured(); !ok || st.RxBytes != 0 || !st.LastHandshake.IsZero() {
		t.Errorf("исправный нулевой ответ: %+v, %v — ожидался измеренный ноль", st, ok)
	}
}

// TestA1bUnparsedStatsReachesDeleteCard — ТЕСТ ДОЕЗДА до решения об
// удалении: карточка (ClassifyLastSeen поверх GetHandshakes, как в
// cmd/cli.buildCard и guiview.DeleteCardActivity) при неразобранном ответе
// говорит «не удалось», а не «не подключался». На f0febbd непонятое время
// рукопожатия становилось нулём, то есть «—» — «подключений не было».
func TestA1bUnparsedStatsReachesDeleteCard(t *testing.T) {
	srv := fakesrv.New()
	clients, err := a1bSession(srv).LoadClients(awgContainer())
	if err != nil || len(clients) == 0 {
		t.Fatalf("LoadClients: %v", err)
	}
	s := a1bSession(&rewriteRunner{inner: srv, match: "wg show wg0 dump", reply: corruptFirstPeer(0)})
	hs, hsErr := s.GetHandshakes(awgContainer())
	for _, cl := range clients {
		if got := ClassifyLastSeen(hs, hsErr, cl.ClientID, cl.Disabled()).State; got != SeenFailed {
			t.Errorf("клиент %q: исход карточки %v, ожидался SeenFailed — неразобранный ответ сервера "+
				"выдан за знание", cl.Name(), got)
		}
	}
}
