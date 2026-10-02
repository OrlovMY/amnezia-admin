package canary

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"amnezia-admin/core"
)

// Правка П0 (живой стенд 89.22.229.78, решение ядра): приложение Amnezia
// при установке протокола само создаёт клиента администратора — «сервер
// пуст» на обычной установке невыполним. С флагом -server-ip (второй фактор
// против боевого сервера вместе с -not-production) П0 допускает уже
// существующих клиентов, снимает их снимок и в конце (П0-итог) сверяет, что
// они не изменились.

// MaxExisting — сколько уже существующих клиентов допускает П0 с
// -server-ip, НА СЕРВЕР в сумме по всем контейнерам семейства WG (SEC П-2:
// счёт на контейнер пропускал боевой сервер с клиентами в разных
// протоколах). Обоснование: на свежей установке приложение Amnezia создаёт
// одного клиента администратора на КАЖДЫЙ протокол (на стенде — по одному
// у amnezia-wireguard и amnezia-awg2, итого 2); запас — один. Сам по себе
// порог боевой сервер не отличает (на семью хватает 1–3 клиентов), поэтому
// главный признак — свежесть контейнеров (MaxFreshAge).
const MaxExisting = 3

// CheckServerIP — -server-ip против адреса из ключа (hostName) ДО
// подключения; имя разрешается системным резолвером. См. checkServerIPWith.
func CheckServerIP(flagIP, host string) error {
	_, err := checkServerIPWith(flagIP, host, net.LookupIP)
	return err
}

// checkServerIPWith — сверка (SEC П-1): в ключе IP — обязан совпасть с
// флагом; в ключе имя — флаг обязан быть среди разрешённых адресов.
// Возвращает адрес, по которому ТОЛЬКО и можно подключаться: сам флаг.
func checkServerIPWith(flagIP, host string, lookup func(string) ([]net.IP, error)) (net.IP, error) {
	want := net.ParseIP(strings.TrimSpace(flagIP))
	if want == nil {
		return nil, fmt.Errorf("-server-ip %q — не IP-адрес", flagIP)
	}
	if ip := net.ParseIP(strings.TrimSpace(host)); ip != nil {
		if ip.Equal(want) {
			return want, nil
		}
		return nil, fmt.Errorf("-server-ip %s не совпал с адресом из ключа %s — это не тот сервер", want, ip)
	}
	ips, err := lookup(host)
	if err != nil {
		return nil, fmt.Errorf("адрес из ключа %q не разрешён (%v) — сверить с -server-ip нельзя", host, err)
	}
	for _, ip := range ips {
		if ip.Equal(want) {
			return want, nil
		}
	}
	return nil, fmt.Errorf("-server-ip %s нет среди адресов %q из ключа — это не тот сервер", want, host)
}

// PinServer — SEC П-1: после сверки подключаться ПРЯМО по IP из флага,
// без второго разрешения имени (иначе SSH или дочерняя программа -new могли
// бы уйти на другой адрес того же имени). Возвращает копию ключа с
// hostName = IP из флага; остальные поля — как были. Ключ хоста
// проверяется как обычно (known_hosts/-hostkey).
func PinServer(cfg map[string]any, flagIP string, lookup func(string) ([]net.IP, error)) (map[string]any, error) {
	host, _ := cfg["hostName"].(string)
	ip, err := checkServerIPWith(flagIP, host, lookup)
	if err != nil {
		return nil, err
	}
	out := make(map[string]any, len(cfg))
	for k, v := range cfg {
		out[k] = v
	}
	out["hostName"] = ip.String()
	return out, nil
}

// ChildKey — ключ vpn:// для дочерних программ (-new, -old) из
// закреплённого PinServer: JSON без сжатия (core.DecodeVpnKey, вариант 3).
// Секрет: не печатается, уходит только в окружение дочерней программы.
func ChildKey(cfg map[string]any) (string, error) {
	b, err := json.Marshal(cfg)
	if err != nil {
		return "", err
	}
	return "vpn://" + base64.RawURLEncoding.EncodeToString(b), nil
}

// SudoKey — SEC П-3: второй ключ (AMNEZIA_KEY_SUDO, по нему пишет PR4.2)
// обязан вести на тот же тестовый сервер, что и основной. С -server-ip —
// через PinServer с тем же флагом (подключение по IP, ключ дочерним
// программам — ChildKey). Без флага — hostName и порт обязаны совпасть с
// основным ключом (mainCfg), иначе отказ до подключения. Текст ошибки
// ключа не содержит.
func SudoKey(mainCfg map[string]any, sudoKey, flagIP string, lookup func(string) ([]net.IP, error)) (string, error) {
	cfg, err := core.DecodeVpnKey(sudoKey)
	if err != nil {
		return "", fmt.Errorf("AMNEZIA_KEY_SUDO не разобран: %v", err)
	}
	port := func(m map[string]any) string {
		if p := core.Str(m, "port"); p != "" && p != "0" {
			return p
		}
		return "22"
	}
	if flagIP != "" {
		// SEC-01 (02.10): с -server-ip адрес второго ключа подменяется
		// сверенным, но порт берётся из самого ключа — сверяем его с портом
		// основного, иначе второй ключ мог вести на другой sshd того же IP.
		if port(cfg) != port(mainCfg) {
			return "", fmt.Errorf("AMNEZIA_KEY_SUDO ведёт на порт %s, основной ключ — на порт %s: второй ключ обязан быть от того же тестового сервера", port(cfg), port(mainCfg))
		}
		p, err := PinServer(cfg, flagIP, lookup)
		if err != nil {
			return "", fmt.Errorf("AMNEZIA_KEY_SUDO: %v", err)
		}
		return ChildKey(p)
	}
	mh, sh := core.Str(mainCfg, "hostName"), core.Str(cfg, "hostName")
	if sh == "" || sh != mh || port(cfg) != port(mainCfg) {
		return "", fmt.Errorf("AMNEZIA_KEY_SUDO ведёт на %s:%s, основной ключ — на %s:%s: второй ключ обязан быть от того же тестового сервера", sh, port(cfg), mh, port(mainCfg))
	}
	return sudoKey, nil
}

// MaxFreshAge — SEC П-2: объективный признак «сервер только что поставлен».
// Тестовый сервер арендуется на сутки и ставится под проверку; боевой
// работает неделями. Контейнер Amnezia старше 72 ч — СТОП, флагом не
// обходится. ГРАНИЦА (SEC, раунд 2): .Created — возраст КОНТЕЙНЕРА, а не
// сервера; если на боевом сервере протокол переустановлен за последние
// 72 ч, свежесть пройдёт — тогда защищают порог MaxExisting и -server-ip.
const MaxFreshAge = 72 * time.Hour

// AgeCheck — П0-свежесть: возраст КАЖДОГО контейнера Amnezia на сервере
// (docker inspect .Created). Старше MaxFreshAge — НЕ ПРОЙДЕН (СТОП); сбой
// inspect, неразобранный ответ, не все контейнеры в ответе — НЕ ПРОВЕРЕНО
// (СТОП).
func AgeCheck(remote func(string) (string, error), names []string, now time.Time) Result {
	r := Result{ID: "П0-свежесть", Name: fmt.Sprintf("контейнеры Amnezia поставлены не раньше %d ч назад", int(MaxFreshAge.Hours()))}
	if len(names) == 0 {
		r.Detail = "контейнеров нет — СТОП"
		return r
	}
	args := " inspect --format '{{.Name}} {{.Created}}' " + strings.Join(names, " ")
	out, err := remote("docker" + args)
	if err != nil && strings.Contains(strings.ToLower(out+err.Error()), "permission denied") {
		out, err = remote("sudo -n docker" + args)
	}
	if err != nil {
		r.Detail = "docker inspect не выполнился: " + oneLine(out) + " " + err.Error() + " — СТОП"
		return r
	}
	seen := map[string]bool{}
	var old []string
	oldest := time.Duration(0)
	for _, l := range strings.Split(strings.TrimSpace(out), "\n") {
		l = strings.TrimSpace(strings.TrimRight(l, "\r"))
		f := strings.Fields(l)
		if len(f) != 2 {
			r.Detail = "ответ docker inspect не разобран: " + oneLine(l) + " — СТОП"
			return r
		}
		created, perr := time.Parse(time.RFC3339Nano, f[1])
		if perr != nil {
			r.Detail = "время создания не разобрано: " + oneLine(l) + " — СТОП"
			return r
		}
		name := strings.TrimPrefix(f[0], "/")
		seen[name] = true
		age := now.Sub(created)
		if age > oldest {
			oldest = age
		}
		if age > MaxFreshAge {
			old = append(old, fmt.Sprintf("%s — %.0f ч", name, age.Hours()))
		}
	}
	for _, n := range names {
		if !seen[n] {
			r.Detail = "в ответе docker inspect нет " + n + " — СТОП"
			return r
		}
	}
	if len(old) > 0 {
		r.Status = Fail
		r.Detail = "контейнер старше " + fmt.Sprint(int(MaxFreshAge.Hours())) + " ч: " + strings.Join(old, ", ") + " — похоже на сервер, которым пользуются, СТОП (флагом не обходится)"
		return r
	}
	r.Status, r.Detail = Pass, fmt.Sprintf("контейнеров %d, старшему %.1f ч", len(names), oldest.Hours())
	return r
}

// Preflight — SEC П-2: ОДИН раз по серверу до первой записи. Свежесть
// всех контейнеров Amnezia (names) и сумма существующих клиентов по ВСЕМ
// контейнерам семейства WG (envs) — не больше MaxExisting на сервер.
// Снимок каждого контейнера остаётся в его Env (П0-итог); П0 в Run
// пропускает только при пройденной предпроверке.
func Preflight(remote func(string) (string, error), envs []*Env, names []string, now time.Time) []Result {
	// Прежняя отметка не переживает новую предпроверку (признак 4): не
	// прошла — снимков и отметки нет, даже если раньше проходила.
	for _, e := range envs {
		e.existing, e.preflightOK = nil, false
	}
	age := AgeCheck(remote, names, now)
	cnt := Result{ID: "П0-сервер", Name: fmt.Sprintf("клиентов на сервере до проверки не больше %d", MaxExisting)}
	total := 0
	var parts []string
	snaps := make([]*existingSnap, len(envs))
	for i, e := range envs {
		if err := e.init(); err != nil {
			cnt.Detail = e.Ctr.Name + ": " + err.Error() + " — СТОП"
			return []Result{age, cnt}
		}
		s, why := e.takeSnap()
		if s == nil {
			cnt.Detail = e.Ctr.Name + ": " + why + " — СТОП"
			return []Result{age, cnt}
		}
		snaps[i] = s
		total += s.count()
		parts = append(parts, fmt.Sprintf("%s %d", e.Ctr.Name, s.count()))
	}
	switch {
	case len(envs) == 0:
		cnt.Detail = "контейнеров семейства WG нет — СТОП"
	case total > MaxExisting:
		cnt.Status, cnt.Detail = Fail, fmt.Sprintf("клиентов на сервере %d (%s) — больше %d: похоже на сервер, которым пользуются люди, СТОП", total, strings.Join(parts, ", "), MaxExisting)
	default:
		cnt.Status, cnt.Detail = Pass, fmt.Sprintf("клиентов на сервере %d (%s) — снимки сняты, в конце сверяются (П0-итог)", total, strings.Join(parts, ", "))
	}
	if age.Status == Pass && cnt.Status == Pass {
		for i, e := range envs {
			e.existing = snaps[i]
			e.preflightOK = true
		}
	}
	return []Result{age, cnt}
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

// existingAllowed — П0 с -server-ip: предпроверка сервера (Preflight:
// свежесть и сумма клиентов по серверу) пройдена, среди существующих нет
// canary-* (следы прошлого прогона). Снимок — из Preflight, снят до первой
// записи на сервер.
func (e *Env) existingAllowed() Result {
	r := Result{ID: "П0", Name: "существующие клиенты сняты до первой записи"}
	if !e.preflightOK || e.existing == nil {
		r.Detail = "предпроверка сервера (П0-свежесть, П0-сервер) не пройдена или не выполнялась — СТОП"
		return r
	}
	clients, err := e.Sess.LoadClients(e.Ctr)
	if err != nil {
		r.Detail = "clientsTable не прочитана: " + err.Error() + " — СТОП"
		return r
	}
	for _, c := range clients {
		if strings.HasPrefix(c.Name(), "canary-") {
			r.Status, r.Detail = Fail, "на сервере уже есть "+c.Name()+" — следы прошлого прогона, СТОП"
			return r
		}
	}
	s := e.existing
	r.Status = Pass
	r.Detail = fmt.Sprintf("клиентов в контейнере до проверки %d (таблица %d, [Peer] в %s %d, в работающем сервере %d) — снимок снят до первой записи, в конце сверяется (П0-итог)",
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
