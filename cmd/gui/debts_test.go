package main

// Долги продукта до релиза (ДОЛГИ-ПРОДУКТ, 30.09.2026) — GUI. Тесты этого
// файла пользуются только API, существовавшим на c65420e, и поэтому
// компилируются там и падают поведением (см. ОТЧЁТ-ДОЛГИ-ПРОДУКТ.md).

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"fyne.io/fyne/v2/test"
	"fyne.io/fyne/v2/widget"

	"amnezia-admin/core"
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
		})
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
}
