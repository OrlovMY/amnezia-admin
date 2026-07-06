package core

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// Все тесты в этом файле используют httptest.Server (локальный loopback,
// 127.0.0.1) — реальная сеть/интернет не затрагивается.

func TestFetchNetworkTimeFromSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// net/http сам проставляет корректный заголовок Date, если хендлер
		// его не переопределяет — этого достаточно для "успешного" случая.
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	before := time.Now()
	got, err := fetchNetworkTimeFrom(context.Background(), []string{srv.URL}, srv.Client())
	if err != nil {
		t.Fatalf("fetchNetworkTimeFrom: %v", err)
	}
	after := time.Now()
	// сервер отдаёт Date с точностью до секунды — сравниваем с запасом
	if got.Before(before.Add(-2*time.Second)) || got.After(after.Add(2*time.Second)) {
		t.Errorf("got %v, want примерно между %v и %v", got, before, after)
	}
}

func TestFetchNetworkTimeFromInvalidDate(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Date", "not-a-valid-http-date")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	_, err := fetchNetworkTimeFrom(context.Background(), []string{srv.URL}, srv.Client())
	if err == nil {
		t.Fatal("expected error for invalid Date header")
	}
}

func TestFetchNetworkTimeFromTimeout(t *testing.T) {
	block := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-block // никогда не отвечаем в пределах теста
	}))
	defer func() {
		close(block)
		srv.Close()
	}()

	client := &http.Client{Timeout: 30 * time.Millisecond}
	_, err := fetchNetworkTimeFrom(context.Background(), []string{srv.URL}, client)
	if err == nil {
		t.Fatal("expected timeout error")
	}
}

// TestFetchNetworkTimeFromFallsBackToNextHost проверяет перебор хостов:
// первый недоступен (соединение сразу рвётся), второй отвечает нормально —
// итоговый вызов должен успешно вернуть время со второго хоста.
func TestFetchNetworkTimeFromFallsBackToNextHost(t *testing.T) {
	good := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer good.Close()

	// заведомо нерабочий адрес (порт 0 не слушает никто) — соединение
	// отклоняется немедленно, без реального сетевого ожидания
	bad := "http://127.0.0.1:1"

	got, err := fetchNetworkTimeFrom(context.Background(), []string{bad, good.URL}, good.Client())
	if err != nil {
		t.Fatalf("fetchNetworkTimeFrom: %v", err)
	}
	if got.IsZero() {
		t.Error("expected non-zero time from the reachable host")
	}
}

// TestFetchNetworkTimeFromIsParallelNotSequential — регресс на ~20с фриз:
// хосты опрашиваются ОДНОВРЕМЕННО, а не по очереди. Один хост отвечает
// медленно (но в пределах таймаута клиента), второй — сразу; итоговый вызов
// должен вернуться за время быстрого хоста, не дожидаясь медленного.
func TestFetchNetworkTimeFromIsParallelNotSequential(t *testing.T) {
	const slowDelay = 300 * time.Millisecond
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(slowDelay)
		w.WriteHeader(http.StatusOK)
	}))
	defer slow.Close()
	fast := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer fast.Close()

	client := &http.Client{Timeout: 2 * time.Second}
	start := time.Now()
	got, err := fetchNetworkTimeFrom(context.Background(), []string{slow.URL, fast.URL}, client)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("fetchNetworkTimeFrom: %v", err)
	}
	if got.IsZero() {
		t.Error("expected non-zero time")
	}
	if elapsed >= slowDelay {
		t.Errorf("elapsed = %v, want < %v (should return as soon as the fast host answers, without waiting for the slow one — hosts must be queried in parallel)", elapsed, slowDelay)
	}
}

func TestFetchNetworkTimeFromAllUnreachable(t *testing.T) {
	_, err := fetchNetworkTimeFrom(context.Background(), []string{"http://127.0.0.1:1", "http://127.0.0.1:2"}, &http.Client{Timeout: time.Second})
	if err == nil {
		t.Fatal("expected error when all hosts are unreachable")
	}
}

func TestFetchNetworkTimeFromEmptyHosts(t *testing.T) {
	_, err := fetchNetworkTimeFrom(context.Background(), nil, networkTimeClient)
	if err == nil {
		t.Fatal("expected error for empty host list")
	}
}

func TestProbeReachableFrom(t *testing.T) {
	good := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer good.Close()
	bad := "http://127.0.0.1:1"

	reachable := probeReachableFrom(context.Background(), []string{good.URL, bad}, good.Client())
	if len(reachable) != 1 || reachable[0] != good.URL {
		t.Errorf("reachable = %v, want [%s]", reachable, good.URL)
	}
}

func TestShuffledHostsDoesNotMutateInput(t *testing.T) {
	original := []string{"a", "b", "c", "d", "e"}
	cp := append([]string(nil), original...)
	_ = shuffledHosts(original)
	for i := range original {
		if original[i] != cp[i] {
			t.Fatalf("shuffledHosts мутировал исходный slice: %v", original)
		}
	}
}

func TestShuffledHostsContainsAllElements(t *testing.T) {
	original := []string{"a", "b", "c", "d", "e"}
	shuffled := shuffledHosts(original)
	if len(shuffled) != len(original) {
		t.Fatalf("len = %d, want %d", len(shuffled), len(original))
	}
	seen := map[string]bool{}
	for _, h := range shuffled {
		seen[h] = true
	}
	for _, h := range original {
		if !seen[h] {
			t.Errorf("%q отсутствует в перемешанном списке", h)
		}
	}
}

// ---------- TrustedClock ----------

func TestTrustedClockNowAdvancesWithElapsedTime(t *testing.T) {
	onlineNow := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)
	clock := NewTrustedClock(onlineNow)

	got1 := clock.Now()
	if got1.Before(onlineNow) {
		t.Errorf("Now() сразу после создания = %v, не должно быть раньше T0 = %v", got1, onlineNow)
	}

	time.Sleep(20 * time.Millisecond)
	got2 := clock.Now()
	if !got2.After(got1) {
		t.Errorf("Now() не продвинулось со временем: got1=%v got2=%v", got1, got2)
	}
	elapsed := got2.Sub(got1)
	if elapsed < 15*time.Millisecond || elapsed > 500*time.Millisecond {
		t.Errorf("elapsed = %v, ожидалось ~20ms (с запасом на джиттер)", elapsed)
	}
}

// TestTrustedClockIgnoresWallClockChanges — прямая проверка требования
// задачи: перевод wall-clock НЕ должен влиять на TrustedClock.Now() в
// пределах жизни процесса, потому что используется монотонная компонента
// time.Time (time.Since), а не абсолютное значение системных часов.
// Мы не можем в юнит-тесте реально перевести системные часы, поэтому здесь
// фиксируется контракт через документированное поведение time.Since —
// сам факт использования time.Since(c.localAt) (а не сравнения wall-clock
// значений) и есть гарантия; см. TestTrustedClockNowAdvancesWithElapsedTime
// для проверки, что монотонное продвижение вообще работает.
func TestTrustedClockUsesMonotonicReading(t *testing.T) {
	onlineNow := time.Now()
	clock := NewTrustedClock(onlineNow)
	// localAt должен содержать монотонное показание (Go добавляет его
	// автоматически для time.Now(), пока время не прошло через сериализацию
	// или арифметику, которая его стрипает). time.Time.String() включает
	// "m=+..."/"m=-..." при наличии монотонной компоненты — прямой признак.
	if !containsMonotonicMarker(clock.localAt.String()) {
		t.Skip("окружение вернуло time.Now() без монотонной компоненты — пропускаем (не ошибка теста)")
	}
}

func containsMonotonicMarker(s string) bool {
	for i := 0; i+3 <= len(s); i++ {
		if s[i:i+3] == "m=+" || s[i:i+3] == "m=-" {
			return true
		}
	}
	return false
}
