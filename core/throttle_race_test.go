package core

// Ревью SEC (fix/review-nits): одновременные неудачи пина из нескольких окон
// засчитываются ВСЕ. Прежде LoadThrottle → RegisterFailure → SaveThrottle шли
// без замка, и две одновременные неудачи могли учесться как одна.

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// TestThrottleConcurrentFailuresAllCounted — ТЕСТ РАЗЛИЧЕНИЯ: N параллельных
// неудач (каждая — свой дескриптор замка, как отдельное окно/процесс) дают
// ровно N в файле. Подмена lockThrottle на «fn без замка» роняет его.
func TestThrottleConcurrentFailuresAllCounted(t *testing.T) {
	const n = throttleMaxFails - 1 // ниже порога: счётчик не обнуляется
	for round := 0; round < 5; round++ {
		dir := t.TempDir()
		now := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)
		var wg sync.WaitGroup
		start := make(chan struct{})
		errs := make(chan error, n)
		for i := 0; i < n; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				if _, err := RecordThrottleFailure(dir, "a.avlt", now); err != nil {
					errs <- err
				}
			}()
		}
		close(start)
		wg.Wait()
		close(errs)
		for err := range errs {
			t.Errorf("неудача не учтена: %v", err)
		}
		st, err := LoadThrottle(dir, "a.avlt")
		if err != nil {
			t.Fatal(err)
		}
		if st.Fails != n {
			t.Fatalf("раунд %d: %d параллельных неудач, а в счётчике %d — часть потеряна", round, n, st.Fails)
		}
	}
}

// TestThrottleLockBusyFailsClosed — ТЕСТ ТРЕТЬЕГО СОСТОЯНИЯ: замок держит
// другой (окно, процесс) дольше throttleLockWait — неудача НЕ записана без
// замка и не выдана за учтённую: ошибка *ThrottleError, файл не тронут.
func TestThrottleLockBusyFailsClosed(t *testing.T) {
	dir := t.TempDir()
	old := throttleLockWait
	throttleLockWait = 50 * time.Millisecond
	t.Cleanup(func() { throttleLockWait = old })
	lf, err := os.OpenFile(filepath.Join(dir, throttleLockName), os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer lf.Close()
	if busy, err := tryLockFile(lf); err != nil || busy {
		t.Fatalf("проверка ничего не значит: замок не взят (%v, %v)", busy, err)
	}
	defer unlockFile(lf)
	_, err = RecordThrottleFailure(dir, "a.avlt", time.Now())
	var te *ThrottleError
	if !asThrottleError(err, &te) {
		t.Fatalf("замок занят, а ошибка %v — ждали *ThrottleError", err)
	}
	if te.Fault != FaultBusy {
		t.Errorf("замок занят, а разбор %d — ждали FaultBusy (совет про другое окно)", te.Fault)
	}
	if _, serr := os.Stat(throttleFilePath(dir)); !os.IsNotExist(serr) {
		t.Fatalf("при занятом замке throttle.json записан (%v)", serr)
	}
}

func asThrottleError(err error, te **ThrottleError) bool {
	e, ok := err.(*ThrottleError)
	if ok {
		*te = e
	}
	return ok
}

// TestThrottleNoLockFileReadOpenWriteClosed — каталог, где файл замка не
// создать (на его месте папка — модель «только для чтения», одинаковая на
// трёх ОС). ЧТЕНИЕ счётчика проходит без замка и даёт записанное значение
// (раньше чтение тоже проходило; это не потеря учёта). ЗАПИСЬ неудачи без
// замка не делается: *ThrottleError с путём замка, счётчик не изменён.
func TestThrottleNoLockFileReadOpenWriteClosed(t *testing.T) {
	dir := t.TempDir()
	if err := SaveThrottle(dir, "a.avlt", ThrottleState{Fails: 3}); err != nil {
		t.Fatal(err)
	}
	lock := filepath.Join(dir, throttleLockName)
	if err := os.Remove(lock); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(lock, 0o700); err != nil {
		t.Fatal(err)
	}
	st, err := LoadThrottle(dir, "a.avlt")
	if err != nil || st.Fails != 3 {
		t.Fatalf("чтение без файла замка: %+v, %v — ждали 3 попытки без ошибки", st, err)
	}
	_, err = RecordThrottleFailure(dir, "a.avlt", time.Now())
	var te *ThrottleError
	if !asThrottleError(err, &te) || te.Path != lock || te.Op != throttleOpWrite {
		t.Fatalf("запись без замка: %v — ждали *ThrottleError «сохранить» по %s", err, lock)
	}
	if st, _ := LoadThrottle(dir, "a.avlt"); st.Fails != 3 {
		t.Fatalf("счётчик изменён без замка: %+v", st)
	}
}
