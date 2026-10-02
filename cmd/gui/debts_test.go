package main

// Долги продукта до релиза (ДОЛГИ-ПРОДУКТ, 30.09.2026) — GUI. Тесты этого
// файла пользуются только API, существовавшим на c65420e, и поэтому
// компилируются там и падают поведением (см. ОТЧЁТ-ДОЛГИ-ПРОДУКТ.md).

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"fyne.io/fyne/v2/test"
	"fyne.io/fyne/v2/widget"

	"amnezia-admin/core"
	"amnezia-admin/internal/fakesrv"
)

// localNetworkTime подменяет пул хостов сетевого времени локальным
// HTTP-сервером на эфемерном порту 127.0.0.1: net/http сам ставит заголовок
// Date. Наружу тест не ходит.
func localNetworkTime(t *testing.T) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	t.Cleanup(srv.Close)
	saved := core.NetworkTimeHosts
	core.NetworkTimeHosts = []string{srv.URL}
	t.Cleanup(func() { core.NetworkTimeHosts = saved })
}

// pinDialogWith открывает НАСТОЯЩИЙ диалог пин-кода, дождавшись ответа о
// сетевом времени (и, значит, первой проверки счётчика).
func pinDialogWith(t *testing.T, prep func(dir string)) (*ui, *widget.Button) {
	t.Helper()
	localNetworkTime(t)
	dir := vaultDirForTest(t)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	prep(dir)
	u := focusTestUI(t)
	t.Cleanup(func() { waitGUIGoroutines(t) })
	u.showConnectScreen("")
	u.showVaultPinDialog(filepath.Join(dir, "нет.avlt"), "Сервер 1", widget.NewButton("", nil), widget.NewLabel(""))
	waitGUIGoroutines(t)
	pop := topPopup(t, u.win.Canvas())
	return u, buttonByText(t, pop, "Открыть")
}

func pinDialogTexts(t *testing.T, u *ui) string {
	t.Helper()
	return strings.Join(visibleTexts(topPopup(t, u.win.Canvas())), " | ")
}

// addTableEntry дописывает в clientsTable fakesrv запись (без peer'а в
// wg0.conf).
func addTableEntry(t *testing.T, srv *fakesrv.Server, entry map[string]any) {
	t.Helper()
	const path = "/opt/amnezia/awg/clientsTable"
	raw, _ := srv.File(path)
	var list []map[string]any
	if err := json.Unmarshal(raw, &list); err != nil {
		t.Fatal(err)
	}
	out, _ := json.Marshal(append(list, entry))
	srv.SetFile(path, out)
}

// TestDebtsStatusNamesCauseOfUnknown — У7 (и У1 в GUI), ТЕСТ РАЗЛИЧЕНИЯ и
// ДОЕЗДА через настоящий refresh() против fakesrv: строка состояния
// называет причину «?» — запрос статистики не удался (с причиной) или
// клиента нет в ответе сервера, — и клиента с испорченным полем disabled.
// Штатный случай — без этих строк. На c65420e строка состояния во всех
// случаях была «Пользователей: N · …».
func TestDebtsStatusNamesCauseOfUnknown(t *testing.T) {
	c := &core.Container{Name: "amnezia-awg", Dir: "/opt/amnezia/awg", Proto: "AmneziaWG", Support: core.SupportYes}
	creds := &core.ServerCreds{Host: "203.0.113.10", User: "root", Password: "x"}
	const (
		failNote    = "Статистику с сервера получить не удалось"
		absentNote  = "Клиентов нет в статистике сервера: 1."
		unknownNote = "Неизвестно, включены ли эти пользователи"
	)
	cases := []struct {
		name   string
		runner func() core.Runner
		want   []string
	}{
		{"штатно", func() core.Runner { return fakesrv.New() }, nil},
		{"статистика не получена", func() core.Runner {
			return &countingRunner{inner: fakesrv.New(), okWgShow: 0}
		}, []string{failNote, "нажмите «Обновить» позже", "имитированный обрыв связи"}},
		{"клиента нет в ответе", func() core.Runner {
			srv := fakesrv.New()
			addTableEntry(t, srv, map[string]any{"clientId": "GHOSTPUB", "userData": map[string]any{"clientName": "Призрак"}})
			return srv
		}, []string{absentNote}},
		{"поле disabled испорчено", func() core.Runner {
			srv := fakesrv.New()
			addTableEntry(t, srv, map[string]any{"clientId": "ODDPUB", "userData": map[string]any{
				"clientName": "Странный", "disabled": "yes", "allowedIP": "10.8.1.9/32"}})
			return srv
		}, []string{unknownNote, `"Странный"`}},
	}
	all := []string{failNote, absentNote, unknownNote}
	for _, cs := range cases {
		t.Run(cs.name, func(t *testing.T) {
			u := refreshedUI(t, core.NewSessionWithRunner(cs.runner(), creds), c)
			st := u.status.Text
			for _, w := range cs.want {
				if !strings.Contains(st, w) {
					t.Errorf("в строке состояния нет %q: %q", w, st)
				}
			}
			for _, n := range all {
				wanted := false
				for _, w := range cs.want {
					wanted = wanted || w == n
				}
				if !wanted && strings.Contains(st, n) {
					t.Errorf("в строке состояния лишнее %q: %q", n, st)
				}
			}
		})
	}
}

// TestDebtsRowShowsEnabledUnknown — раунд 2 (QA п.5, «чинить в типе»):
// третье состояние видно в САМОЙ строке таблицы, а не только в строке
// состояния. Боевой путь: refresh() против fakesrv, ячейка — настоящий
// UpdateCell. Различение: false — активен («—», рукопожатий не было), true —
// «отключён», "yes" — «вкл/откл: ?». На c65420e "yes" давал «—», как у
// активного.
func TestDebtsRowShowsEnabledUnknown(t *testing.T) {
	c := &core.Container{Name: "amnezia-awg", Dir: "/opt/amnezia/awg", Proto: "AmneziaWG", Support: core.SupportYes}
	creds := &core.ServerCreds{Host: "203.0.113.10", User: "root", Password: "x"}
	for _, cs := range []struct {
		v    any
		want string
	}{{false, "—"}, {true, "отключён"}, {"yes", "— · вкл/откл: ?"}} {
		srv := fakesrv.New()
		const path = "/opt/amnezia/awg/clientsTable"
		raw, _ := srv.File(path)
		var list []map[string]any
		if err := json.Unmarshal(raw, &list); err != nil || len(list) == 0 {
			t.Fatalf("подготовка: %v", err)
		}
		list[0]["userData"].(map[string]any)["disabled"] = cs.v
		out, _ := json.Marshal(list)
		srv.SetFile(path, out)
		u := refreshedUI(t, core.NewSessionWithRunner(srv, creds), c)
		row := -1
		for i, cl := range u.clients {
			if cl.Name() == "Alice" {
				row = i
			}
		}
		if row < 0 {
			t.Fatalf("проверка ПЕРЕСТАЛА ЧТО-ЛИБО ЗНАЧИТЬ: Alice нет в таблице")
		}
		if got := cellText(u, row, 3); got != cs.want {
			t.Errorf("disabled=%#v: «Активность» = %q, ожидалось %q", cs.v, got, cs.want)
		}
	}
}

// TestDebtsPinThrottleUnreadableClosesInput — Н8, ТЕСТ РАЗЛИЧЕНИЯ и ДОЕЗДА
// по чтению. «Файла счётчика нет» (штатно: ввод открыт) ≠ «файл есть, но
// повреждён или не читается» (ввод закрыт, названы причина и путь). На
// c65420e LoadThrottle читал битый файл как ноль попыток — кнопка
// «Открыть» включалась, блокировка сбрасывалась. Файл — настоящий, путь до
// диалога — боевой (acquireOnlineTime).
func TestDebtsPinThrottleUnreadableClosesInput(t *testing.T) {
	cases := []struct {
		name   string
		prep   func(dir string)
		closed bool
	}{
		{"файла нет — ввод открыт", func(string) {}, false},
		{"файл повреждён", func(dir string) {
			os.WriteFile(filepath.Join(dir, "throttle.json"), []byte("{"), 0o600)
		}, true},
		{"на месте файла каталог", func(dir string) {
			os.Mkdir(filepath.Join(dir, "throttle.json"), 0o700)
		}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			u, open := pinDialogWith(t, c.prep)
			texts := pinDialogTexts(t, u)
			if !c.closed {
				if open.Disabled() {
					t.Fatalf("счётчика нет (штатно), а ввод пина закрыт: %s", texts)
				}
				return
			}
			if !open.Disabled() {
				t.Fatalf("счётчик попыток не прочитан, а кнопка «Открыть» доступна — "+
					"неизвестное число попыток выдано за ноль: %s", texts)
			}
			if !strings.Contains(texts, "счётчик попыток") || !strings.Contains(texts, "throttle.json") {
				t.Errorf("причина и путь не названы: %s", texts)
			}
			// Раунд 4 (Н-1): совет по сути — различение повреждённого файла
			// и папки на его месте.
			want := map[string]string{"файл повреждён": "удалите его, он повреждён",
				"на месте файла каталог": "на месте файла — папка"}[c.name]
			if !strings.Contains(texts, want) {
				t.Errorf("совет не по сути, ожидалось %q: %s", want, texts)
			}
		})
	}
}

// TestDebtsToggleUnknownOffersDisable — раунд 4 (AU-UX High, решение ядра):
// «Вкл/Выкл» на клиенте с испорченным disabled открывает вопрос об
// ОТКЛЮЧЕНИИ, а «Перевыпустить» — отказ с шагом «Отключите пользователя».
// Боевой путь: refresh() против fakesrv, настоящие toggleSelected и
// regenerateSelected. На f5951bc «Вкл/Выкл» давал отказ.
func TestDebtsToggleUnknownOffersDisable(t *testing.T) {
	c := &core.Container{Name: "amnezia-awg", Dir: "/opt/amnezia/awg", Proto: "AmneziaWG", Support: core.SupportYes}
	creds := &core.ServerCreds{Host: "203.0.113.10", User: "root", Password: "x"}
	srv := fakesrv.New()
	const path = "/opt/amnezia/awg/clientsTable"
	raw, _ := srv.File(path)
	var list []map[string]any
	if err := json.Unmarshal(raw, &list); err != nil || len(list) == 0 {
		t.Fatalf("подготовка: %v", err)
	}
	list[0]["userData"].(map[string]any)["disabled"] = "yes"
	out, _ := json.Marshal(list)
	srv.SetFile(path, out)
	u := refreshedUI(t, core.NewSessionWithRunner(srv, creds), c)
	u.selectedRow = -1
	for i, cl := range u.clients {
		if cl.EnabledState() == core.EnabledUnknown {
			u.selectedRow = i
		}
	}
	if u.selectedRow < 0 {
		t.Fatal("проверка ПЕРЕСТАЛА ЧТО-ЛИБО ЗНАЧИТЬ: клиента с неизвестным состоянием нет")
	}
	u.toggleSelected()
	texts := strings.Join(visibleTexts(u.win.Canvas().Overlays().Top()), " | ")
	if !strings.Contains(texts, "Отключить пользователя?") || strings.Contains(texts, "неизвестно:") {
		t.Fatalf("«Вкл/Выкл» при неизвестном состоянии — не вопрос об отключении: %s", texts)
	}
	u.win.Canvas().Overlays().Top().Hide()
	u.win.Canvas().Overlays().Remove(u.win.Canvas().Overlays().Top())
	u.regenerateSelected()
	texts = strings.Join(visibleTexts(u.win.Canvas().Overlays().Top()), " | ")
	if !strings.Contains(texts, "Отключите пользователя — это исправит запись") {
		t.Fatalf("«Перевыпустить» при неизвестном состоянии — не отказ с шагом: %s", texts)
	}
}

// TestDebtsPinThrottleSaveFailClosesInput — Н8, ДОЕЗД по записи. Счётчик
// читается, но записать его нельзя (на месте временного файла — каталог).
// Неверная попытка (файла хранилища нет — ветка неудачи) на c65420e
// показывала «Осталось попыток: 9» и снова включала «Открыть», хотя
// счётчик не сохранён. Теперь ввод закрыт.
func TestDebtsPinThrottleSaveFailClosesInput(t *testing.T) {
	u, open := pinDialogWith(t, func(dir string) {
		os.Mkdir(filepath.Join(dir, "throttle.json.tmp"), 0o700)
	})
	if open.Disabled() {
		t.Fatalf("проверка ПЕРЕСТАЛА ЧТО-ЛИБО ЗНАЧИТЬ: до попытки ввод уже закрыт: %s", pinDialogTexts(t, u))
	}
	passwordEntry(t, topPopup(t, u.win.Canvas()), 0).SetText("1111")
	test.Tap(open)
	waitGUIGoroutines(t)
	texts := pinDialogTexts(t, u)
	if strings.Contains(texts, "Осталось попыток") {
		t.Errorf("счётчик не сохранён, а человеку сказано, сколько попыток осталось: %s", texts)
	}
	if !open.Disabled() {
		t.Fatalf("счётчик не сохранён, а ввод пина снова открыт: %s", texts)
	}
	if !strings.Contains(texts, "сохранить счётчик попыток") {
		t.Errorf("причина не названа: %s", texts)
	}
	// Раунд 4 (AU-LOGIC Н-1): назван ИМЕННО тот путь, что не записался —
	// временный throttle.json.tmp (на его месте папка), а не throttle.json,
	// которого нет; совет — по сути, без «удалите его, он повреждён».
	tmp := filepath.Join(core.DefaultVaultDir(), "throttle.json.tmp")
	if !strings.Contains(texts, "Файл: "+tmp+".") {
		t.Errorf("назван не тот файл (ожидался %s): %s", tmp, texts)
	}
	if !strings.Contains(texts, "на месте файла — папка") || strings.Contains(texts, "он повреждён") {
		t.Errorf("совет не по сути (на месте .tmp папка): %s", texts)
	}
}
