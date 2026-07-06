// Файл onlinetime.go — источник "доверенного" времени для throttle
// vault-пина, устойчивый к переводу локальных часов пользователем.
//
// Идея: NTP не используем (спуфится, plaintext UDP). Вместо этого берём
// заголовок HTTP `Date` из ответа TLS-аутентифицированного HTTPS-хоста —
// подделать его без компрометации сертификата целевого домена нельзя, а
// сам факт запроса неотличим от обычного фонового HTTPS-трафика (privacy).
// Хосты — крупные CDN/сервисы, которые в любом случае держат точные часы и
// не заметят единичного HEAD-запроса на общем фоне. Мы НЕ раскрываем в UI,
// что это источник времени.
package core

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"net/http"
	"time"
)

// NetworkTimeHosts — пул репутабельных HTTPS-хостов для получения времени
// из заголовка Date. Все — крупные, стабильные, с корректными TLS-сертификатами.
var NetworkTimeHosts = []string{
	"https://www.cloudflare.com",
	"https://www.google.com",
	"https://www.microsoft.com",
	"https://www.apple.com",
	"https://github.com",
}

// networkTimeClient — HTTP-клиент по умолчанию для FetchNetworkTime/ProbeReachable;
// таймаут короткий — недоступность одного хоста не должна надолго блокировать UI.
var networkTimeClient = &http.Client{Timeout: 4 * time.Second}

// ErrNoNetworkTime возвращается, если ни один хост из пула не ответил.
// Текст сообщения намеренно не упоминает "серверы времени" — приложению
// просто не удалось убедиться в наличии интернета.
var ErrNoNetworkTime = errors.New("подключение к интернету не обнаружено")

// FetchNetworkTime получает текущее время, опрашивая ВСЕ хосты пула
// ПАРАЛЛЕЛЬНО и возвращая ответ первого, кто прислал корректный заголовок
// Date. Общее время операции ограничено дедлайном переданного ctx (вызывающий
// код, например GUI, должен передать context.WithTimeout(..., ~8s)) — при
// последовательном переборе 5 хостов с таймаутом по 4с на каждый худший
// случай мог доходить до ~20с; параллельный опрос ограничивает его
// дедлайном ctx независимо от числа хостов. Остальные ещё не ответившие
// запросы отменяются, как только получен первый успешный ответ (или как
// только становится известно, что все хосты недоступны).
func FetchNetworkTime(ctx context.Context) (time.Time, error) {
	return fetchNetworkTimeFrom(ctx, NetworkTimeHosts, networkTimeClient)
}

// ProbeReachable проверяет пул хостов параллельно и возвращает те, что
// ответили в течение таймаута клиента. Используется опционально (например,
// на старте приложения), чтобы FetchNetworkTime мог сразу пробовать заведомо
// достижимые хосты, а не тратить время на заведомо недоступные (например,
// при подключении через сеть, блокирующую часть CDN).
func ProbeReachable(ctx context.Context) []string {
	return probeReachableFrom(ctx, NetworkTimeHosts, networkTimeClient)
}

// fetchNetworkTimeFrom опрашивает hosts параллельно (не последовательно —
// см. комментарий к FetchNetworkTime) и возвращает первый успешный ответ.
// Как только получен успех (или выяснено, что все хосты отказали), внутренний
// derived-context отменяется, чтобы не держать зря ещё не завершившиеся
// запросы к остальным хостам.
func fetchNetworkTimeFrom(ctx context.Context, hosts []string, client *http.Client) (time.Time, error) {
	if len(hosts) == 0 {
		return time.Time{}, ErrNoNetworkTime
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	type result struct {
		t   time.Time
		err error
	}
	ch := make(chan result, len(hosts))
	for _, host := range shuffledHosts(hosts) {
		go func(host string) {
			t, err := fetchDateFromHost(ctx, host, client)
			ch <- result{t, err}
		}(host)
	}

	var lastErr error
	for i := 0; i < len(hosts); i++ {
		r := <-ch
		if r.err == nil {
			return r.t, nil
		}
		lastErr = r.err
	}
	return time.Time{}, fmt.Errorf("%w: %v", ErrNoNetworkTime, lastErr)
}

func probeReachableFrom(ctx context.Context, hosts []string, client *http.Client) []string {
	type result struct {
		host string
		ok   bool
	}
	ch := make(chan result, len(hosts))
	for _, h := range hosts {
		go func(host string) {
			_, err := fetchDateFromHost(ctx, host, client)
			ch <- result{host, err == nil}
		}(h)
	}
	var reachable []string
	for range hosts {
		r := <-ch
		if r.ok {
			reachable = append(reachable, r.host)
		}
	}
	return reachable
}

// fetchDateFromHost делает HEAD-запрос к host и парсит заголовок Date.
// http.ParseTime — стандартный разбор HTTP-времени: пробует RFC1123
// (== http.TimeFormat, основной формат) и два устаревших формата-фолбэка
// (RFC850, ANSI C), которые изредка ещё встречаются у некоторых серверов.
func fetchDateFromHost(ctx context.Context, host string, client *http.Client) (time.Time, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, host, nil)
	if err != nil {
		return time.Time{}, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return time.Time{}, err
	}
	defer resp.Body.Close()

	dateHeader := resp.Header.Get("Date")
	if dateHeader == "" {
		return time.Time{}, fmt.Errorf("%s: в ответе нет заголовка Date", host)
	}
	t, err := http.ParseTime(dateHeader)
	if err != nil {
		return time.Time{}, fmt.Errorf("%s: некорректный формат Date %q: %w", host, dateHeader, err)
	}
	return t, nil
}

// shuffledHosts возвращает новый slice с перемешанным порядком хостов
// (math/rand — выбор источника не является защитным механизмом, поэтому
// криптостойкий ГПСЧ не нужен). Не мутирует исходный slice.
func shuffledHosts(hosts []string) []string {
	out := make([]string, len(hosts))
	copy(out, hosts)
	rand.Shuffle(len(out), func(i, j int) { out[i], out[j] = out[j], out[i] })
	return out
}

// ---------- TrustedClock: T0 (онлайн-время) + монотонное смещение ----------

// TrustedClock фиксирует момент получения онлайн-времени (T0) вместе с
// локальной монотонной точкой отсчёта (time.Now(), которая в Go всегда несёт
// монотонное показание, пока процесс жив) и позволяет затем многократно
// получать "доверенное сейчас" БЕЗ повторных сетевых запросов:
//
//	доверенное_сейчас = T0 + время_прошедшее_по_монотонным_часам
//
// Перевод wall-clock пользователем (вперёд/назад) НЕ влияет на результат,
// потому что time.Since использует монотонную компоненту, а не wall-clock,
// пока сравниваемые time.Time получены в рамках одного процесса. Это даёт:
// один сетевой запрос на сессию диалога, устойчивость к переводу часов,
// минимальный сетевой след.
//
// Ограничение (see also README/отчёт BE-02): это закрывает ТОЛЬКО перевод
// системных часов. Удаление throttle.json или откат его резервной копии
// по-прежнему сбрасывает счётчик попыток — привязать состояние
// криптографически к времени без доверенного внешнего хранилища нельзя.
// TrustedClock — anti-casual слой, а не защита от целенаправленной атаки на
// файловую систему.
type TrustedClock struct {
	onlineAt time.Time // T0 — онлайн-время на момент фиксации
	localAt  time.Time // time.Now() в тот же момент (монотонная точка отсчёта)
}

// NewTrustedClock фиксирует онлайн-время onlineNow как T0 "сейчас".
func NewTrustedClock(onlineNow time.Time) TrustedClock {
	return TrustedClock{onlineAt: onlineNow, localAt: time.Now()}
}

// Now возвращает T0 + время, прошедшее по монотонным часам с момента
// фиксации — не требует повторного сетевого запроса.
func (c TrustedClock) Now() time.Time {
	return c.onlineAt.Add(time.Since(c.localAt))
}
