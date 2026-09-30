package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"fyne.io/fyne/v2/widget"

	"amnezia-admin/core"
	"amnezia-admin/internal/guiview"
)

// Осмотр форм (verify-in-ui) для видимых добавок ДОЛГИ-ПРОДУКТ. Отдельным
// файлом: guiview.LoadedStatus и guiview.PinThrottleUnknown на c65420e нет,
// а debts_test.go обязан там компилироваться.

// ---------- У7: главное окно, длинная причина «?» в строке состояния ----------

var debtsLongStatsErr = errors.New(`команда "docker exec -i amnezia-awg sh -c 'wg show wg0 dump'": ` +
	strings.Repeat("ssh: handshake failed: read tcp 192.0.2.1:50123->203.0.113.10:22: ", 3) + "connection reset by peer")

// debtsLoadedStatus — худший по длине случай: отказ статистики с длинной
// ошибкой и клиент с длинным именем, у которого поле disabled испорчено.
func debtsLoadedStatus(clients []core.ClientEntry) string {
	clients = append(append([]core.ClientEntry(nil), clients...), core.ClientEntry{
		ClientID: repeatKey('W'), UserData: map[string]any{
			"clientName": "Планшет с очень длинным именем для проверки переноса", "disabled": "yes"}})
	return guiview.LoadedStatus("Пользователей: 4 · трафик и активность — с момента перезапуска сервера",
		clients, nil, debtsLongStatsErr)
}

func openMainLongStatus(t *testing.T, u *ui, sized func()) osmotrScene {
	osmotrMain(u)
	u.status.SetText(debtsLoadedStatus(u.clients))
	sized()
	c := u.win.Canvas()
	return osmotrScene{root: c.Content(), canvas: c, mins: osmotrFrame(c.Content(), nil)}
}

// openMainEnabledUnknown — главное окно, у «Телефона Анны» поле disabled
// испорчено: в «Активности» — guiview.EnabledUnknownCell (раунд 2, QA п.5).
func openMainEnabledUnknown(t *testing.T, u *ui, sized func()) osmotrScene {
	osmotrMain(u)
	u.clients[1].UserData["disabled"] = "yes"
	u.status.SetText(guiview.LoadedStatus("Пользователей: 3 · трафик и активность — с момента перезапуска сервера",
		u.clients, u.peerStats, nil))
	u.table.Refresh()
	sized()
	if got := cellText(u, 1, 3); got != guiview.EnabledUnknownCell {
		t.Fatalf("проверка ПЕРЕСТАЛА ЧТО-ЛИБО ЗНАЧИТЬ: «Активность» строки 2 — %q", got)
	}
	c := u.win.Canvas()
	return osmotrScene{root: c.Content(), canvas: c, mins: osmotrFrame(c.Content(), nil)}
}

func invMainWithStatus(status string) []string {
	inv := append([]string(nil), invMain...)
	inv[len(inv)-1] = "подпись:" + firstLine(status) // последняя — строка состояния
	return inv
}

// ---------- Н8: диалог пин-кода, счётчик попыток не читается ----------

func openPinThrottleUnknown(t *testing.T, u *ui, sized func()) osmotrScene {
	localNetworkTime(t)
	dir := vaultDirForTest(t)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	if err := os.WriteFile(filepath.Join(dir, "throttle.json"), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { waitGUIGoroutines(t) })
	u.showConnectScreen("")
	sized()
	u.showVaultPinDialog(filepath.Join(dir, "нет.avlt"), "Сервер 1", widget.NewButton("", nil), widget.NewLabel(""))
	waitGUIGoroutines(t)
	c := u.win.Canvas()
	pop := topPopup(t, c)
	mins := osmotrFrame(pop, nil)
	passwordEntry(t, pop, 0).SetText(typedCyrillicPin)
	return osmotrScene{root: pop, canvas: c, mins: mins}
}

func invPinThrottleUnknown() []string {
	inv := append([]string(nil), invPinBase...)
	for i, s := range inv {
		if s == "подпись:Подключение к интернету не обнаружено." {
			inv[i] = "подпись:" + firstLine(guiview.PinThrottleUnknown(&core.ThrottleError{Op: "прочитать", Err: errors.New("x")}))
		}
	}
	return inv
}

func init() {
	osmotrForms = append(osmotrForms,
		osmotrForm{name: "(г) главное окно, включён ли клиент — неизвестно", open: openMainEnabledUnknown,
			inventory: invMainWithStatus("Пользователей: 3 · трафик и активность — с момента перезапуска сервера")},
		osmotrForm{name: "(г) главное окно, причина «?» в строке состояния", open: openMainLongStatus,
			inventory: invMainWithStatus(debtsLoadedStatus(nil))},
		osmotrForm{name: "(б) пин-код, счётчик попыток не читается", open: openPinThrottleUnknown,
			inventory: invPinThrottleUnknown(), width: 412},
	)
}
