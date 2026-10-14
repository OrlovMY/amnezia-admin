package main

// Аудит F1 по PR #57: ТЕСТЫ ДОЕЗДА атомарного учёта неудач пина в GUI —
// основной диалог пина (main.go, submit) и второй диалог (clienthost.go,
// throttledVaultDecrypt). Неудачи из нескольких окон одновременно
// засчитываются все. Подмена «LoadThrottle → RegisterFailure → SaveThrottle
// без общего замка» в любом из двух мест роняет свой тест.

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"fyne.io/fyne/v2/test"
	"fyne.io/fyne/v2/widget"

	"amnezia-admin/core"
)

const parallelPinWindows = 9 // ниже порога блокировки: счётчик не обнуляется

// barrierDecrypt — vaultDecrypt, который отвечает «неверный пин» только
// когда до него дошли все n окон: неудачи пишутся одновременно.
func barrierDecrypt(t *testing.T, n int) {
	t.Helper()
	old := vaultDecrypt
	t.Cleanup(func() { vaultDecrypt = old })
	var mu sync.Mutex
	arrived := 0
	all := make(chan struct{})
	vaultDecrypt = func(string, string) (core.VaultPayload, core.VaultInfo, error) {
		mu.Lock()
		arrived++
		if arrived == n {
			close(all)
		}
		mu.Unlock()
		select {
		case <-all:
		case <-time.After(10 * time.Second):
		}
		return core.VaultPayload{}, core.VaultInfo{}, core.ErrVaultBadPinOrCorrupt
	}
}

// serialUI — обращения диалога пина к виджетам по одному (аудит р2 H1): в
// тестовом драйвере fyne.Do синхронен, а в продукте — очередь потока
// интерфейса. Параллельны остаются расшифровка и запись неудачи.
func serialUI(t *testing.T) {
	t.Helper()
	old := uiDo
	t.Cleanup(func() { uiDo = old })
	var mu sync.Mutex
	uiDo = func(f func()) {
		mu.Lock()
		defer mu.Unlock()
		old(f)
	}
}

// TestPinDialogParallelFailuresAllCounted — доезд через настоящий диалог
// пина: N окон, в каждом «Открыть» с неверным пином одновременно → N.
func TestPinDialogParallelFailuresAllCounted(t *testing.T) {
	localNetworkTime(t)
	a := test.NewApp()
	t.Cleanup(a.Quit)
	serialUI(t)
	oldDir := pinVaultDir
	t.Cleanup(func() { pinVaultDir = oldDir })
	for round := 0; round < 3; round++ {
		dir := t.TempDir()
		pinVaultDir = func() string { return dir }
		path := filepath.Join(dir, "a.avlt")
		barrierDecrypt(t, parallelPinWindows)
		var btns []*widget.Button
		for i := 0; i < parallelPinWindows; i++ {
			w := test.NewWindow(nil)
			t.Cleanup(w.Close)
			u := &ui{win: w, selectedRow: -1}
			u.showConnectScreen("")
			u.showVaultPinDialog(path, "Сервер 1", widget.NewButton("", nil), widget.NewLabel(""))
			waitGUIGoroutines(t)
			b := buttonByText(t, topPopup(t, w.Canvas()), "Открыть")
			if b.Disabled() {
				t.Fatalf("проверка ничего не значит: «Открыть» выключена в окне %d", i)
			}
			btns = append(btns, b)
		}
		for _, b := range btns {
			test.Tap(b)
		}
		waitGUIGoroutines(t)
		st, err := core.LoadThrottle(dir, "a.avlt")
		if err != nil {
			t.Fatal(err)
		}
		if st.Fails != parallelPinWindows {
			t.Fatalf("раунд %d: %d окон с неверным пином, а в счётчике %d — неудачи потеряны", round, parallelPinWindows, st.Fails)
		}
	}
}

// TestClientHostParallelFailuresAllCounted — доезд через второй диалог
// пина (throttledVaultDecrypt): N одновременных неудач → N.
func TestClientHostParallelFailuresAllCounted(t *testing.T) {
	for round := 0; round < 3; round++ {
		path := stubPinThrottle(t, []byte("не хранилище"))
		barrierDecrypt(t, parallelPinWindows)
		var wg sync.WaitGroup
		for i := 0; i < parallelPinWindows; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if _, _, err := throttledVaultDecrypt(path, "wrong"); err == nil {
					t.Error("неверный пин принят")
				}
			}()
		}
		wg.Wait()
		st, err := core.LoadThrottle(filepath.Dir(path), "a.avlt")
		if err != nil {
			t.Fatal(err)
		}
		if st.Fails != parallelPinWindows {
			t.Fatalf("раунд %d: %d одновременных неудач, а в счётчике %d — неудачи потеряны", round, parallelPinWindows, st.Fails)
		}
		_ = os.Remove(path)
	}
}

// pinDialogReady — настоящий диалог пина над хранилищем в своём каталоге,
// дождавшись первой проверки счётчика; кнопка «Открыть», кнопка входа и
// подпись состояния входа (attemptConnect пишет в них).
func pinDialogReady(t *testing.T) (*ui, *widget.Button, *widget.Button, *widget.Label) {
	t.Helper()
	localNetworkTime(t)
	dir := t.TempDir()
	oldDir := pinVaultDir
	t.Cleanup(func() { pinVaultDir = oldDir })
	pinVaultDir = func() string { return dir }
	u := focusTestUI(t)
	t.Cleanup(func() { waitGUIGoroutines(t) })
	u.showConnectScreen("")
	connectBtn, info := widget.NewButton("", nil), widget.NewLabel("")
	u.showVaultPinDialog(filepath.Join(dir, "a.avlt"), "Сервер 1", connectBtn, info)
	waitGUIGoroutines(t)
	return u, buttonByText(t, topPopup(t, u.win.Canvas()), "Открыть"), connectBtn, info
}

// blockingLoad — loadThrottle, который ждёт release (как замок, занятый
// другим окном). entered закрывается при первом входе.
func blockingLoad(t *testing.T) (entered, release chan struct{}) {
	t.Helper()
	old := loadThrottle
	entered, release = make(chan struct{}), make(chan struct{})
	var once sync.Once
	loadThrottle = func(dir, name string) (core.ThrottleState, error) {
		once.Do(func() { close(entered) })
		<-release
		return old(dir, name)
	}
	t.Cleanup(func() { loadThrottle = old })
	return
}

// TestPinSubmitDoesNotBlockUI — регресс аудита F2/M1: пока счётчик занят
// (заглушка держит чтение), нажатие «Открыть» возвращается сразу, в окне —
// текст ожидания, кнопка выключена. Подмена «читать счётчик в submit до
// goSafe» вешает нажатие — тест падает по таймауту.
func TestPinSubmitDoesNotBlockUI(t *testing.T) {
	u, open, _, _ := pinDialogReady(t)
	if open.Disabled() {
		t.Fatal("проверка ничего не значит: «Открыть» выключена")
	}
	entered, release := blockingLoad(t)
	released := false
	defer func() {
		if !released {
			close(release)
		}
	}()
	done := make(chan struct{})
	go func() { test.Tap(open); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		close(release)
		released = true
		<-done
		t.Fatal("нажатие «Открыть» ждало счётчик в потоке интерфейса — окно висит")
	}
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("проверка ничего не значит: счётчик не читался")
	}
	if txt := pinDialogTexts(t, u); !strings.Contains(txt, pinThrottleWaitText) || !open.Disabled() {
		t.Errorf("во время ожидания счётчика: «Открыть» выключена=%v, текст: %s", open.Disabled(), txt)
	}
	close(release)
	released = true
	waitGUIGoroutines(t)
}

// TestPinAcquireShowsWaitWhileLoading — регресс M1 для acquireOnlineTime:
// пока счётчик читается при открытии, в окне — текст ожидания, а не
// «Проверка подключения...». Подмена «чтение внутри fyne.Do» роняет.
func TestPinAcquireShowsWaitWhileLoading(t *testing.T) {
	localNetworkTime(t)
	dir := t.TempDir()
	oldDir := pinVaultDir
	t.Cleanup(func() { pinVaultDir = oldDir })
	pinVaultDir = func() string { return dir }
	entered, release := blockingLoad(t)
	u := focusTestUI(t)
	u.showConnectScreen("")
	u.showVaultPinDialog(filepath.Join(dir, "a.avlt"), "Сервер 1", widget.NewButton("", nil), widget.NewLabel(""))
	select {
	case <-entered:
	case <-time.After(10 * time.Second):
		close(release)
		t.Fatal("проверка ничего не значит: счётчик не читался")
	}
	txt := pinDialogTexts(t, u)
	open := buttonByText(t, topPopup(t, u.win.Canvas()), "Открыть")
	dis := open.Disabled()
	close(release)
	waitGUIGoroutines(t)
	if !strings.Contains(txt, pinThrottleWaitText) || !dis {
		t.Errorf("во время чтения счётчика: «Открыть» выключена=%v, текст: %s", dis, txt)
	}
}

// TestPinCancelDuringDecryptNoLogin — решение ядра (аудит р2): «Отмена»,
// пока идёт расшифровка, — входа нет, даже если пин верный.
func TestPinCancelDuringDecryptNoLogin(t *testing.T) {
	u, open, connectBtn, info := pinDialogReady(t)
	old := vaultDecrypt
	t.Cleanup(func() { vaultDecrypt = old })
	entered, release := make(chan struct{}), make(chan struct{})
	vaultDecrypt = func(string, string) (core.VaultPayload, core.VaultInfo, error) {
		close(entered)
		<-release
		return core.VaultPayload{Key: "vpn://не-ключ"}, core.VaultInfo{}, nil
	}
	test.Tap(open)
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		close(release)
		t.Fatal("проверка ничего не значит: расшифровка не началась")
	}
	test.Tap(buttonByText(t, topPopup(t, u.win.Canvas()), "Отмена"))
	close(release)
	waitGUIGoroutines(t)
	if connectBtn.Disabled() || info.Text != "" {
		t.Fatalf("после «Отмена» начался вход: кнопка выключена=%v, «%s»", connectBtn.Disabled(), info.Text)
	}
}
