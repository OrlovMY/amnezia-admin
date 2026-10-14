package main

// Аудит F1 по PR #57: ТЕСТЫ ДОЕЗДА атомарного учёта неудач пина в GUI —
// основной диалог пина (main.go, submit) и второй диалог (clienthost.go,
// throttledVaultDecrypt). Неудачи из нескольких окон одновременно
// засчитываются все. Подмена «LoadThrottle → RegisterFailure → SaveThrottle
// без общего замка» в любом из двух мест роняет свой тест.

import (
	"os"
	"path/filepath"
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

// TestPinDialogParallelFailuresAllCounted — доезд через настоящий диалог
// пина: N окон, в каждом «Открыть» с неверным пином одновременно → N.
func TestPinDialogParallelFailuresAllCounted(t *testing.T) {
	localNetworkTime(t)
	a := test.NewApp()
	t.Cleanup(a.Quit)
	for round := 0; round < 3; round++ {
		dir := t.TempDir()
		oldDir := pinVaultDir
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
		pinVaultDir = oldDir
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
