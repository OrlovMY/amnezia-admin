package core

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"sort"
	"strings"
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
// Тест был устроен наоборот и потому не мог упасть: единственной его строкой
// был t.Skip по тому самому значению, которое он обязан проверять. Оба исхода
// были зелёными, и подмена, стирающая монотонную компоненту у localAt,
// проходила как «пропуск, не ошибка теста» — то есть тест пропускал себя
// ровно в том случае, который обязан ловить. Проверено прогоном до починки:
// подмена `localAt: time.Now().Truncate(time.Millisecond)` компилируется, весь
// пакет core на ней зелёный, а этот тест давал SKIP.
//
// Устройство после починки, и разница в одном: предикат пропуска проверяет
// СРЕДУ, а не проверяемый объект.
//  1. сначала выясняется, даёт ли монотонную компоненту собственный time.Now()
//     этой платформы;
//  2. даёт — дальше безусловное утверждение по clock.localAt, без единого
//     t.Skip: отсутствие монотонной компоненты у localAt здесь провал, а не
//     повод промолчать;
//  3. пропуск допустим только там, где монотонности нет у самой платформы, и
//     тогда в сообщении названа платформа — чтобы пропуск был читаемым фактом,
//     а не пустой строкой в журнале.
func TestTrustedClockUsesMonotonicReading(t *testing.T) {
	// Шаг 1 — про среду, а не про clock. Если монотонного показания не даёт
	// сама платформа, проверять у localAt нечего, и это единственная законная
	// причина пропустить тест.
	if !containsMonotonicMarker(time.Now().String()) {
		t.Skipf("платформа %s/%s не даёт монотонной компоненты у собственного time.Now() — "+
			"проверять у localAt нечего; пропуск назван, чтобы он был виден в журнале",
			runtime.GOOS, runtime.GOARCH)
	}

	onlineNow := time.Now()
	clock := NewTrustedClock(onlineNow)

	// Шаг 2 — безусловное утверждение. localAt обязан содержать монотонное
	// показание: Go добавляет его для time.Now() и стрипает, как только время
	// проходит через сериализацию или арифметику (Round, Truncate, Unix,
	// маршалинг). Именно на этом держится TrustedClock.Now(): она считает
	// time.Since(c.localAt), и без монотонной компоненты перевод системных
	// часов начал бы влиять на результат — то самое, от чего защищает
	// контракт. time.Time.String() включает "m=+..."/"m=-..." при наличии
	// монотонной компоненты — прямой признак.
	if !containsMonotonicMarker(clock.localAt.String()) {
		t.Fatalf("clock.localAt = %s — без монотонной компоненты (m=+/m=-), хотя time.Now() "+
			"на платформе %s/%s её даёт.\n"+
			"  Значит localAt прошёл через арифметику или сериализацию, которая её стрипает,\n"+
			"  и точка отсчёта TrustedClock перестала быть монотонной.",
			clock.localAt.String(), runtime.GOOS, runtime.GOARCH)
	}
}

// Что этот тест НЕ доказывает — названо здесь, потому что завышенное
// достижение опаснее скромного.
//
// Тест выше сторожит ПОЛЕ localAt, а не КОНТРАКТ. Монотонность можно стереть
// этажом ниже, уже внутри Now() — `time.Since(c.localAt.Round(0))` или счёт по
// wall-clock, — и тест выше остаётся зелёным, хотя защита от перевода
// системных часов снята полностью. Проверено прогоном: на подмене
// `return c.onlineAt.Add(time.Since(c.localAt.Round(0)))` тест выше даёт PASS.
//
// Почему это не закрыто утверждением о поведении, а закрыто сторожем исходника.
// Поведенческий различитель потребовал бы TrustedClock, у которого wall-часть
// localAt сдвинута относительно монотонной: при монотонном счёте Now() дал бы
// примерно onlineAt, при wall-счёте уехал бы на час. Такой time.Time публичным
// API построить НЕЛЬЗЯ, и это проверено прогоном, а не рассуждением: Add
// сдвигает ОБЕ части сразу (`m=+0.004` → `m=+3600.004`), а Round/Truncate/UTC/
// Local монотонную компоненту стирают. Предложенное утверждение было
// прогнано в обеих версиях — на чистом Now() и на подменённом — и дало
// ОДИНАКОВЫЙ результат (уход на 1h0m0s), то есть не различает их вовсе.
// Развести wall и монотонные часы можно только реальным переводом системных
// часов, а в юнит-тесте этого нет.
//
// Поэтому контракт сторожится там, где он записан, — в исходнике, закрытым
// списком допустимых тел Now(), тем же приёмом, что применён к меткам раннеров
// и к условиям `if:` в internal/ciguard: перечислить все неверные способы
// посчитать время нельзя, перечислить единственный верный — можно. Законное
// изменение Now() от этого не запрещено, оно становится видимым в диффе
// отдельной строкой с причиной.
//
// Граница этого сторожа — ИЗМЕРЕННАЯ, а не прикинутая (ревью, MEDIUM-3;
// прежняя формулировка была неточна В ОБЕ СТОРОНЫ сразу: занижала достигнутое и
// не называла настоящую щель).
//
// Сторож читает ТЕЛО МЕТОДА. Он поймает ЛЮБОЕ изменение самого тела, включая
// вынос вычисления в функцию-помощника: тело при этом меняется, а список
// закрыт, значит красный. Прежде это было объявлено непокрытым — неверно,
// достижение занижалось.
//
// И он НЕ ПОЙМАЕТ подмену смысла БЕЗ изменения текста — переопределение
// импортируемого `time` (`type Time = time.Time` плюс свой wall-based Since в
// собственном пакете, одна строка импорта). Проверено прогоном: зелёный. Как
// дефект безопасности это низко — такого никто не закоммитит «не заметив», а
// весь смысл признака раздела Д в правдоподобии, — но читающий эту шапку обязан
// получить верное представление о том, что прикрыто, а что нет.
var allowedTrustedClockNowBodies = map[string]string{
	"return c.onlineAt.Add(time.Since(c.localAt))": "монотонный счёт: time.Since по localAt, " +
		"у которого монотонная компонента цела, поэтому перевод системных часов на результат не влияет",
}

func TestTrustedClockNowCountsFromMonotonicReading(t *testing.T) {
	if len(allowedTrustedClockNowBodies) == 0 {
		t.Fatalf("закрытый список allowedTrustedClockNowBodies пуст — тест перестал что-либо проверять")
	}

	src, err := os.ReadFile("onlinetime.go")
	if err != nil {
		t.Fatalf("не прочитать onlinetime.go: %v", err)
	}

	const head = "func (c TrustedClock) Now() time.Time {"
	i := strings.Index(string(src), head)
	if i < 0 {
		t.Fatalf("в onlinetime.go не найден метод %q — тест перестал что-либо проверять "+
			"(метод переименовали, сменили приёмник или перенесли в другой файл)", head)
	}
	rest := string(src)[i+len(head):]
	j := strings.Index(rest, "\n}")
	if j < 0 {
		t.Fatalf("в onlinetime.go не найден конец тела %s — тест перестал что-либо проверять", head)
	}

	// Тело нормализуется: shell-комментариев тут нет, но есть Go-комментарии,
	// отступы и переносы — они к смыслу не относятся.
	var kept []string
	for _, line := range strings.Split(rest[:j], "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "//") {
			continue
		}
		kept = append(kept, line)
	}
	body := strings.Join(strings.Fields(strings.Join(kept, " ")), " ")

	if why, ok := allowedTrustedClockNowBodies[body]; !ok {
		t.Fatalf("тело TrustedClock.Now() изменилось и НЕ входит в закрытый список допустимых:\n"+
			"  найдено:  %s\n"+
			"  допустимо: %v\n"+
			"  Здесь держится защита от перевода системных часов, и стереть её можно одной вставкой\n"+
			"  (.Round(0), .UTC(), счёт по wall-clock) — тест, сторожащий только поле localAt, этого не видит.\n"+
			"  Изменение законно? Внеси новое тело в allowedTrustedClockNowBodies отдельной строкой\n"+
			"  с причиной — тогда оно видно в диффе, а не проходит молча.",
			body, keysOf(allowedTrustedClockNowBodies))
	} else {
		t.Logf("тело Now() допущено списком: %s", why)
	}
}

func keysOf(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func containsMonotonicMarker(s string) bool {
	for i := 0; i+3 <= len(s); i++ {
		if s[i:i+3] == "m=+" || s[i:i+3] == "m=-" {
			return true
		}
	}
	return false
}
