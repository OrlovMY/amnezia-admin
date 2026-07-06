package core

import (
	"os"
	"testing"
	"time"
)

func TestRegisterFailureBelowThreshold(t *testing.T) {
	now := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)
	st := ThrottleState{}
	for i := 0; i < 9; i++ {
		st = RegisterFailure(st, now)
	}
	if st.Fails != 9 {
		t.Fatalf("Fails = %d, want 9", st.Fails)
	}
	if blocked, _ := CheckThrottle(st, now); blocked {
		t.Error("9 неудач не должны блокировать")
	}
	if !st.BlockedUntil.IsZero() {
		t.Errorf("BlockedUntil = %v, want zero (ещё не заблокирован)", st.BlockedUntil)
	}
}

func TestRegisterFailureTenthBlocks(t *testing.T) {
	now := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)
	st := ThrottleState{}
	for i := 0; i < 9; i++ {
		st = RegisterFailure(st, now)
	}
	st = RegisterFailure(st, now) // 10-я
	if st.Fails != 0 {
		t.Errorf("Fails после блокировки = %d, want 0 (сброшен)", st.Fails)
	}
	want := now.Add(5 * time.Minute)
	if !st.BlockedUntil.Equal(want) {
		t.Errorf("BlockedUntil = %v, want %v", st.BlockedUntil, want)
	}
}

func TestCheckThrottleBlockedAndRemaining(t *testing.T) {
	now := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)
	st := ThrottleState{BlockedUntil: now.Add(3 * time.Minute)}

	blocked, remaining := CheckThrottle(st, now)
	if !blocked {
		t.Fatal("expected blocked = true")
	}
	if remaining != 3*time.Minute {
		t.Errorf("remaining = %v, want 3m", remaining)
	}
}

func TestCheckThrottleAfterExpiry(t *testing.T) {
	now := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)
	st := ThrottleState{BlockedUntil: now.Add(-1 * time.Second)} // истекла секунду назад
	blocked, remaining := CheckThrottle(st, now)
	if blocked {
		t.Error("истёкшая блокировка не должна считаться активной")
	}
	if remaining != 0 {
		t.Errorf("remaining = %v, want 0", remaining)
	}
}

func TestRegisterSuccessResets(t *testing.T) {
	got := RegisterSuccess()
	want := ThrottleState{}
	if got != want {
		t.Errorf("RegisterSuccess() = %+v, want zero value", got)
	}
}

func TestLoadThrottleMissingOrCorrupt(t *testing.T) {
	dir := t.TempDir()

	t.Run("missing file", func(t *testing.T) {
		st := LoadThrottle(dir, "nonexistent.avlt")
		if st != (ThrottleState{}) {
			t.Errorf("LoadThrottle(missing) = %+v, want zero value", st)
		}
	})

	t.Run("corrupt file", func(t *testing.T) {
		badDir := t.TempDir()
		path := throttleFilePath(badDir)
		if err := os.WriteFile(path, []byte("{not valid json"), 0600); err != nil {
			t.Fatalf("os.WriteFile: %v", err)
		}
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("паника на битом throttle.json: %v", r)
			}
		}()
		st := LoadThrottle(badDir, "whatever.avlt")
		if st != (ThrottleState{}) {
			t.Errorf("LoadThrottle(corrupt) = %+v, want zero value", st)
		}
	})
}

func TestSaveLoadRoundtrip(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2024, 6, 15, 10, 30, 0, 0, time.UTC)
	st := ThrottleState{Fails: 4, BlockedUntil: now}

	if err := SaveThrottle(dir, "a1b2c3d4.avlt", st); err != nil {
		t.Fatalf("SaveThrottle: %v", err)
	}
	got := LoadThrottle(dir, "a1b2c3d4.avlt")
	if got.Fails != st.Fails {
		t.Errorf("Fails = %d, want %d", got.Fails, st.Fails)
	}
	if !got.BlockedUntil.Equal(st.BlockedUntil) {
		t.Errorf("BlockedUntil = %v, want %v", got.BlockedUntil, st.BlockedUntil)
	}
}

func TestPerVaultIsolation(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2024, 6, 15, 10, 30, 0, 0, time.UTC)

	stA := ThrottleState{Fails: 0, BlockedUntil: now.Add(5 * time.Minute)}
	if err := SaveThrottle(dir, "vaultA.avlt", stA); err != nil {
		t.Fatalf("SaveThrottle(A): %v", err)
	}
	stB := ThrottleState{Fails: 3}
	if err := SaveThrottle(dir, "vaultB.avlt", stB); err != nil {
		t.Fatalf("SaveThrottle(B): %v", err)
	}

	gotA := LoadThrottle(dir, "vaultA.avlt")
	if !gotA.BlockedUntil.Equal(stA.BlockedUntil) {
		t.Errorf("vaultA заблокирован некорректно: %+v", gotA)
	}
	gotB := LoadThrottle(dir, "vaultB.avlt")
	if gotB.Fails != 3 || !gotB.BlockedUntil.IsZero() {
		t.Errorf("vaultB не должен быть затронут блокировкой vaultA: %+v", gotB)
	}

	// повторное сохранение A не должно стереть B
	stA2 := RegisterFailure(stA, now)
	if err := SaveThrottle(dir, "vaultA.avlt", stA2); err != nil {
		t.Fatalf("SaveThrottle(A2): %v", err)
	}
	gotB2 := LoadThrottle(dir, "vaultB.avlt")
	if gotB2.Fails != 3 {
		t.Errorf("vaultB испорчен повторной записью vaultA: %+v", gotB2)
	}
}
