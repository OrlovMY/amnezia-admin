package canary

import (
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"strings"
)

// Правка П0 (живой стенд 89.22.229.78, решение ядра): приложение Amnezia
// при установке протокола само создаёт клиента администратора — «сервер
// пуст» на обычной установке невыполним. С флагом -server-ip (второй фактор
// против боевого сервера вместе с -not-production) П0 допускает уже
// существующих клиентов, снимает их снимок и в конце (П0-итог) сверяет, что
// они не изменились.

// MaxExisting — сколько уже существующих клиентов допускает П0 с
// -server-ip. Обоснование: на свежей установке приложение Amnezia создаёт
// одного клиента администратора на КАЖДЫЙ протокол (на стенде — по одному
// у amnezia-wireguard и amnezia-awg2); запас — на повторную установку
// протокола или второе устройство владельца. Больше трёх на одном
// контейнере — признак сервера, которым пользуются люди: СТОП.
const MaxExisting = 3

// CheckServerIP — -server-ip против адреса из ключа (hostName) ДО
// подключения. Совпало — nil. Host — имя: сверяются его адреса.
func CheckServerIP(flagIP, host string) error {
	want := net.ParseIP(strings.TrimSpace(flagIP))
	if want == nil {
		return fmt.Errorf("-server-ip %q — не IP-адрес", flagIP)
	}
	if ip := net.ParseIP(strings.TrimSpace(host)); ip != nil {
		if ip.Equal(want) {
			return nil
		}
		return fmt.Errorf("-server-ip %s не совпал с адресом из ключа %s — это не тот сервер", want, ip)
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return fmt.Errorf("адрес из ключа %q не разрешён (%v) — сверить с -server-ip нельзя", host, err)
	}
	for _, ip := range ips {
		if ip.Equal(want) {
			return nil
		}
	}
	return fmt.Errorf("-server-ip %s не совпал ни с одним адресом %q из ключа — это не тот сервер", want, host)
}

// existingSnap — снимок клиентов, бывших на сервере до канарейки: по ключу
// клиента — запись clientsTable (JSON), блок [Peer] файла конфигурации и
// присутствие в работающем сервере.
type existingSnap struct {
	table   map[string]string // ClientID → запись clientsTable
	peers   map[string]string // PublicKey → блок [Peer]
	runtime map[string]bool   // PublicKey в wg show
}

func (s *existingSnap) count() int {
	keys := map[string]bool{}
	for k := range s.table {
		keys[k] = true
	}
	for k := range s.peers {
		keys[k] = true
	}
	for k := range s.runtime {
		keys[k] = true
	}
	return len(keys)
}

// peerBlocks — блоки [Peer] текста конфигурации по PublicKey; блок — от
// строки [Peer] до следующей секции, без хвостовых пустых строк.
func peerBlocks(conf string) map[string]string {
	out := map[string]string{}
	var cur []string
	flush := func() {
		if len(cur) == 0 {
			return
		}
		key := ""
		for _, l := range cur {
			if kv := strings.SplitN(l, "=", 2); len(kv) == 2 && strings.TrimSpace(kv[0]) == "PublicKey" {
				key = strings.TrimSpace(kv[1])
			}
		}
		out[key] = strings.TrimRight(strings.Join(cur, "\n"), "\n\r\t ")
		cur = nil
	}
	for _, l := range strings.Split(conf, "\n") {
		t := strings.TrimSpace(l)
		if strings.HasPrefix(t, "[") {
			flush()
			if t == "[Peer]" {
				cur = []string{l}
			}
			continue
		}
		if cur != nil {
			cur = append(cur, l)
		}
	}
	flush()
	return out
}

// takeSnap — снимок трёх источников. Ошибка — не прочитано (П0: СТОП).
func (e *Env) takeSnap() (*existingSnap, string) {
	s := &existingSnap{table: map[string]string{}, peers: map[string]string{}, runtime: map[string]bool{}}
	clients, err := e.Sess.LoadClients(e.Ctr)
	if err != nil {
		return nil, "clientsTable не прочитана: " + err.Error()
	}
	for _, c := range clients {
		b, err := json.Marshal(c)
		if err != nil {
			return nil, "запись clientsTable не разобрана: " + err.Error()
		}
		s.table[c.ClientID] = string(b)
	}
	wg, err := e.Remote(e.docker + " exec " + e.Ctr.Name + " cat " + e.conf())
	if err != nil {
		return nil, e.fam.File + " не прочитан: " + err.Error()
	}
	s.peers = peerBlocks(wg)
	rt, err := e.Sess.GetPeerStats(e.Ctr)
	if err != nil {
		return nil, "работающий сервер не опрошен (wg show): " + err.Error()
	}
	for k := range rt {
		s.runtime[k] = true
	}
	return s, ""
}

// existingAllowed — П0 с -server-ip: существующих клиентов не больше
// MaxExisting и среди них нет canary-* (следы прошлого прогона). Снимок —
// в e.existing.
func (e *Env) existingAllowed() Result {
	r := Result{ID: "П0", Name: "существующие клиенты сняты, их не больше " + fmt.Sprint(MaxExisting)}
	s, why := e.takeSnap()
	if s == nil {
		r.Detail = why + " — СТОП"
		return r
	}
	clients, _ := e.Sess.LoadClients(e.Ctr)
	for _, c := range clients {
		if strings.HasPrefix(c.Name(), "canary-") {
			r.Status, r.Detail = Fail, "на сервере уже есть "+c.Name()+" — следы прошлого прогона, СТОП"
			return r
		}
	}
	if n := s.count(); n > MaxExisting {
		r.Status, r.Detail = Fail, fmt.Sprintf("клиентов %d — больше %d: похоже на сервер, которым пользуются люди, СТОП", n, MaxExisting)
		return r
	}
	e.existing = s
	r.Status = Pass
	r.Detail = fmt.Sprintf("клиентов до проверки %d (таблица %d, [Peer] в %s %d, в работающем сервере %d) — снимок снят, в конце сверяется (П0-итог)",
		s.count(), len(s.table), e.fam.File, len(s.peers), len(s.runtime))
	return r
}

// existingIntact — П0-итог: каждый клиент из снимка на месте и не изменён.
func (e *Env) existingIntact() Result {
	r := Result{ID: "П0-итог", Name: "существующие клиенты не изменились"}
	if e.existing == nil {
		r.Status, r.Detail = NotApplicable, "снимка нет: сервер был пуст"
		return r
	}
	if e.existing.count() == 0 {
		r.Status, r.Detail = Pass, "существующих клиентов не было"
		return r
	}
	now, why := e.takeSnap()
	if now == nil {
		r.Detail = why
		return r
	}
	var bad []string
	for id, was := range e.existing.table {
		if got, ok := now.table[id]; !ok {
			bad = append(bad, "запись clientsTable "+short(id)+" пропала")
		} else if got != was {
			bad = append(bad, "запись clientsTable "+short(id)+" изменилась")
		}
	}
	for k, was := range e.existing.peers {
		if got, ok := now.peers[k]; !ok {
			bad = append(bad, "[Peer] "+short(k)+" пропал из "+e.fam.File)
		} else if got != was {
			bad = append(bad, "[Peer] "+short(k)+" изменился")
		}
	}
	for k := range e.existing.runtime {
		if !now.runtime[k] {
			bad = append(bad, "peer "+short(k)+" пропал из работающего сервера")
		}
	}
	if len(bad) > 0 {
		sort.Strings(bad)
		r.Status, r.Detail = Fail, strings.Join(bad, "; ")
		return r
	}
	r.Status, r.Detail = Pass, fmt.Sprintf("клиентов %d — таблица, %s и работающий сервер байт в байт прежние", e.existing.count(), e.fam.File)
	return r
}

// short — начало ключа для текста (ключ публичный, но строка короче).
func short(k string) string {
	if len(k) > 8 {
		return k[:8] + "…"
	}
	return k
}

// canaryCount — сколько в списке своих клиентов (canary-*).
func canaryCount(m map[string]bool) int { return len(m) }

// canaryNames — имена canary-* из списка клиентов.
func canaryNames[T any](m map[string]T) map[string]bool {
	out := map[string]bool{}
	for n := range m {
		if strings.HasPrefix(n, "canary-") {
			out[n] = true
		}
	}
	return out
}
