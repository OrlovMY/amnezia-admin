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
	r := step("П0-свежесть")
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
// ageCheck — шов теста программы: fakesrv не отвечает на docker inspect
// .Created (TestProgramStepsMatchRegistry, режим -server-ip).
var ageCheck = AgeCheck

func Preflight(remote func(string) (string, error), envs []*Env, names []string, now time.Time) []Result {
	// Прежняя отметка не переживает новую предпроверку (признак 4): не
	// прошла — снимков и отметки нет, даже если раньше проходила.
	for _, e := range envs {
		e.existing, e.preflightOK, e.k6 = nil, false, k6Window{}
	}
	age := ageCheck(remote, names, now)
	cnt := step("П0-сервер")
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
	r := step("П0")
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

// k6Window — снимки существующих клиентов непосредственно до вопроса К6 и
// сразу после ответа «да». opened — человек ответил «да» (приложение
// Amnezia могло писать на сервер); снимок nil — не снят (why — почему).
type k6Window struct {
	opened              bool
	before, after       *existingSnap
	beforeWhy, afterWhy string
	lockWhy             string // замок не свободен перед К6 — окно не открыто
}

// plainFields — поля userData, значения которых печатаются (не секреты).
// Значения прочих полей не печатаются: состав clientsTable задаёт не только
// наша программа.
var plainFields = map[string]bool{"clientName": true, "creationDate": true, "allowed_ips": true, "disabled": true}

// fieldDiff — перечень изменённых полей userData двух записей clientsTable
// (JSON ClientEntry): «поле: было X, стало Y»; отсутствие поля — «нет».
// Запись не разобрана — так и сказано (не «полей нет»).
func fieldDiff(was, got string) string {
	var a, b core.ClientEntry
	if json.Unmarshal([]byte(was), &a) != nil || json.Unmarshal([]byte(got), &b) != nil {
		return "поля не разобраны"
	}
	keys := map[string]bool{}
	for k := range a.UserData {
		keys[k] = true
	}
	for k := range b.UserData {
		keys[k] = true
	}
	val := func(m map[string]any, k string) (string, bool) {
		v, ok := m[k]
		if !ok {
			return "нет", false
		}
		j, _ := json.Marshal(v)
		return string(j), true
	}
	var out []string
	for k := range keys {
		x, _ := val(a.UserData, k)
		y, _ := val(b.UserData, k)
		if x == y {
			continue
		}
		if plainFields[k] {
			out = append(out, fmt.Sprintf("%s: было %s, стало %s", k, x, y))
		} else {
			out = append(out, k+" (значение не печатается)")
		}
	}
	if len(out) == 0 {
		return "userData та же, отличается запись вне userData"
	}
	sort.Strings(out)
	return strings.Join(out, ", ")
}

// tableDiff — записи clientsTable из ids: пропала или изменилась от a к b.
func tableDiff(ids map[string]string, a, b *existingSnap) (gone, changed []string) {
	for id := range ids {
		was, ok := a.table[id]
		if !ok {
			continue // пропала раньше — сказано на своём отрезке
		}
		if got, ok := b.table[id]; !ok {
			gone = append(gone, "запись clientsTable "+short(id)+" пропала")
		} else if got != was {
			changed = append(changed, "запись clientsTable "+short(id)+" изменилась (поля: "+fieldDiff(was, got)+")")
		}
	}
	return gone, changed
}

// windowDiff — изменения таблицы в окне К6 (снимки a «до», b «после»).
// Закрытый список (AU-LOGIC р8 High-5): допустимо только (1) новая запись
// и (2) у существующей записи ПОЯВИЛОСЬ allowed_ips, равное AllowedIPs её
// [Peer] в снимке «после», при прочих полях байт в байт прежних — это
// сведения (info). Пропажа записи — порча, НЕ ПРОЙДЕН (gone). Любое другое
// изменение — чья правка, не различить (unknown → П0-итог НЕ ПРОВЕРЕНО).
func windowDiff(ids map[string]string, a, b *existingSnap) (info, unknown, gone []string) {
	for id := range b.table {
		if _, ok := a.table[id]; !ok {
			info = append(info, "в окне К6 появилась запись "+short(id))
		}
	}
	for id := range ids {
		was, ok := a.table[id]
		if !ok {
			continue
		}
		got, ok := b.table[id]
		switch {
		case !ok:
			// пропажа клиента — порча, а не «не различить» (QA-01 р9 Н11)
			gone = append(gone, "запись clientsTable "+short(id)+" пропала (в окне К6)")
			continue
		case got == was:
			continue
		}
		if what, ok := windowAllowed(was, got, b.peers[id]); ok {
			info = append(info, "у записи "+short(id)+" "+what)
			continue
		}
		unknown = append(unknown, "изменение в окне К6 — чья правка, не различить: запись "+short(id)+", поля: "+fieldDiff(was, got))
	}
	sort.Strings(info)
	return info, unknown, gone
}

// statsFields — поля статистики, которые приложение Amnezia пишет в userData
// существующих записей, когда показывает список пользователей (живой прогон
// ФИНАЛ-2 03.10: dataReceived, dataSent, latestHandshake в окне К6). Наш код
// их не пишет (поиск по core и cmd). Закрытый список: расширять только по
// новому наблюдению приложения с записью в отчёте.
var statsFields = map[string]bool{"dataReceived": true, "dataSent": true, "latestHandshake": true}

// windowAllowed — got отличается от was только допустимыми в окне К6
// изменениями (закрытый список, AU-LOGIC р8 High-5):
//   - появилось allowed_ips (строка), равное AllowedIPs блока [Peer] peer;
//   - появились или сменились строковые поля статистики statsFields
//     (пропажа поля статистики — не из списка).
//
// Остальные поля userData обязаны совпасть по значению. Возвращает
// сведение без значений статистики (они не наши и в итоге не нужны).
func windowAllowed(was, got, peer string) (string, bool) {
	var a, b core.ClientEntry
	if json.Unmarshal([]byte(was), &a) != nil || json.Unmarshal([]byte(got), &b) != nil || a.ClientID != b.ClientID {
		return "", false
	}
	var parts, stats []string
	for k := range a.UserData {
		if _, ok := b.UserData[k]; !ok {
			return "", false // поле пропало — ни одно допустимое изменение этого не делает
		}
	}
	keys := make([]string, 0, len(b.UserData))
	for k := range b.UserData {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		y := b.UserData[k]
		x, had := a.UserData[k]
		jx, _ := json.Marshal(x)
		jy, _ := json.Marshal(y)
		if had && string(jx) == string(jy) {
			continue
		}
		switch {
		case statsFields[k]:
			if _, ok := y.(string); !ok {
				return "", false
			}
			stats = append(stats, k)
		case k == "allowed_ips" && !had:
			v, ok := y.(string)
			if !ok || !peerAllowedIPs(peer, v) {
				return "", false
			}
			parts = append(parts, "появилось allowed_ips = "+v)
		default:
			return "", false
		}
	}
	if len(stats) > 0 {
		parts = append(parts, "обновлена статистика ("+strings.Join(stats, ", ")+")")
	}
	if len(parts) == 0 {
		return "", false // запись переписана без изменения полей — не из списка
	}
	return strings.Join(parts, "; "), true
}

// peerAllowedIPs — v равно AllowedIPs блока [Peer] peer (пробелы не в счёт).
func peerAllowedIPs(peer, v string) bool {
	want := ""
	for _, l := range strings.Split(peer, "\n") {
		if kv := strings.SplitN(l, "=", 2); len(kv) == 2 && strings.TrimSpace(kv[0]) == "AllowedIPs" {
			want = strings.TrimSpace(kv[1])
		}
	}
	norm := func(s string) string { return strings.ReplaceAll(s, " ", "") }
	return want != "" && norm(v) == norm(want)
}

// existingIntact — П0-итог: каждый клиент из снимка на месте и не изменён.
// Окно К6 (человек добавлял пользователя в приложении Amnezia, оно
// переписывает clientsTable): изменение записи внутри окна — сведение;
// пропажа записи, [Peer] и peer работающего сервера — НЕ ПРОЙДЕН всегда.
// Вне окна — любое изменение НЕ ПРОЙДЕН. Окно открыто, а снимок до или
// после него не снят — НЕ ПРОВЕРЕНО: чья правка, не различить.
func (e *Env) existingIntact() Result {
	r := step("П0-итог")
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
	var bad, info, unknown []string
	ids := e.existing.table
	if e.k6.lockWhy != "" {
		// QA-01 р10 Н12: окно не открылось, приложение не писало — сверка
		// «начало → конец» как без К6 (ниже, opened=false); причина — сведением.
		info = append(info, "замок не свободен перед К6 ("+e.k6.lockWhy+") — окно К6 не открыто, сверка «начало → конец»")
	}
	if e.k6.opened {
		switch {
		case e.k6.before == nil:
			r.Detail = "снимок до К6 не снят (" + e.k6.beforeWhy + ") — правки приложения Amnezia от наших не отличить"
			return r
		case e.k6.after == nil:
			r.Detail = "снимок после К6 не снят (" + e.k6.afterWhy + ") — правки приложения Amnezia от наших не отличить"
			return r
		}
		g, c := tableDiff(ids, e.existing, e.k6.before)
		bad = append(bad, g...)
		bad = append(bad, c...)
		wi, wu, wg := windowDiff(ids, e.k6.before, e.k6.after)
		bad = append(bad, wg...)
		info = append(info, wi...)
		unknown = append(unknown, wu...)
		g, c = tableDiff(ids, e.k6.after, now)
		bad = append(bad, g...)
		bad = append(bad, c...)
	} else {
		g, c := tableDiff(ids, e.existing, now)
		bad = append(bad, g...)
		bad = append(bad, c...)
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
	sort.Strings(info)
	note := ""
	if len(info) > 0 {
		note = "; сведение: " + strings.Join(info, "; ")
	}
	if len(bad) > 0 {
		sort.Strings(bad)
		r.Status, r.Detail = Fail, strings.Join(bad, "; ")+note
		return r
	}
	if len(unknown) > 0 {
		sort.Strings(unknown)
		r.Detail = strings.Join(unknown, "; ") + note
		return r
	}
	if len(info) > 0 {
		r.Status, r.Detail = Pass, fmt.Sprintf("клиентов %d — %s и работающий сервер байт в байт прежние; таблица прежняя или изменена только допустимо в окне К6%s", e.existing.count(), e.fam.File, note)
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
