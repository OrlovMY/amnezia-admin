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
	srv := fakesrv.New()
	sess := core.NewSessionWithRunner(srv, a1Creds())
	cl := core.ClientEntry{ClientID: "k1", UserData: map[string]any{"clientName": "Alice"}}

	card := buildCard(sess, a1Container(), cl, "удалить")
	if card.LastSeenUnknown {
		t.Fatal("LastSeenUnknown = true на исправном сервере")
	}
	if card.LastSeen != "—" {
		t.Errorf("LastSeen = %q, want \"—\" (клиента k1 нет среди peer'ов fakesrv — сервер ОТВЕТИЛ, "+
			"и ответ означает «не подключался»)", card.LastSeen)
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
