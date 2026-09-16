package core

// Единый аллокатор IP (PR-3, находка аудита High «IP отключённого
// переиспользуется»): раньше AddUser и RegenerateUser независимо считали
// занятыми только адрес интерфейса и AllowedIPs peer'ов из wg0.conf — резерв
// отключённого пользователя (сохранённый в userData.allowedIP при disable,
// core/txn.go:planDisableLocked) не был виден ни одному из них, и следующий
// AddUser получал IP, который де-факто "забронирован" за молчащим
// пользователем. Решение владельца 14.09.2026: резервировать IP отключённого
// пользователя — тот, у кого уже есть настройки, не должен потерять свой
// адрес, даже если долго не пользуется.
//
// Три источника занятости адреса:
//  1. адрес интерфейса (Address в [Interface] wg0.conf);
//  2. AllowedIPs каждого [Peer] в wg0.conf (активные пользователи и сироты);
//  3. userData.allowedIP каждой записи clientsTable с Disabled() == true —
//     резерв отключённого; peer такого пользователя в wg0.conf уже нет
//     (disable его убирает), поэтому без этого источника резерв невидим.

import (
	"fmt"
	"strconv"
)

// hostIP достаёт хост-адрес без маски из строки вида "10.8.1.5/32" или
// "10.8.1.5" (userData.allowedIP хранится как есть, тем же значением, что
// было в AllowedIPs на момент disable — core.go:planDisableLocked). Если в
// строке несколько адресов через запятую (например,
// "10.8.1.5/32, fd00::5/128"), берёт первый IPv4 — тем же ipRe, что и
// остальной код (core.go:590); менять этот разбор — не предмет PR-3.
// Пустая строка или отсутствие IPv4 — "" (адрес не учитывается).
func hostIP(s string) string {
	m := ipRe.FindStringSubmatch(s)
	if m == nil {
		return ""
	}
	return m[1] + "." + m[2]
}

// usedIPs — карта хост-адрес → владелец, общая для allocateIP (Г1) и
// проверки конфликта при включении (Г2, planEnableLocked). Владелец —
// PublicKey peer'а из wg0.conf либо ClientID отключённой записи
// clientsTable. Адрес интерфейса сюда намеренно не входит (у него нет
// "владельца" в смысле ClientEntry/peer) — allocateIP учитывает его отдельно.
func usedIPs(conf *wgConf, clients []ClientEntry) map[string]string {
	used := map[string]string{}
	for _, p := range conf.peers {
		if ip := hostIP(p["AllowedIPs"]); ip != "" {
			used[ip] = p["PublicKey"]
		}
	}
	// Резерв отключённого НЕ перезаписывает адрес, уже занятый активным
	// peer'ом из wg0.conf: пока клиент отключён, у него самого peer'а в
	// конфиге нет (disable его убирает), так что совпадение возможно только
	// если этот же адрес занял КТО-ТО ДРУГОЙ, пока клиент был отключён —
	// именно этот случай и обязан распознать Г2 (конфликт при включении:
	// владелец, показанный отказом, должен быть занявшим адрес peer'ом, а не
	// самим отключённым, чей резерв не должен маскировать конфликт).
	for _, cl := range clients {
		if !cl.Disabled() {
			continue
		}
		ip := hostIP(Str(cl.UserData, "allowedIP"))
		if ip == "" {
			continue
		}
		if _, taken := used[ip]; !taken {
			used[ip] = cl.ClientID
		}
	}
	return used
}

// ownerLabel — человекочитаемое имя владельца адреса для отказа при
// включении (Г2): clientName из clientsTable по ownerID, либо, если owner —
// PublicKey peer'а-сироты (не найден ни в одной записи clientsTable),
// "ключ <PublicKey>" — администратор должен понять, кого он видит, не
// открывая wg0.conf (решение владельца 2, 14.09.2026).
func ownerLabel(clients []ClientEntry, ownerID string) string {
	for _, cl := range clients {
		if cl.ClientID == ownerID {
			return fmt.Sprintf("%q", cl.Name())
		}
	}
	return fmt.Sprintf("ключ %s", ownerID)
}

// allocateIP выдаёт следующий свободный адрес подсети, считая занятыми:
//   - адрес интерфейса (Address в [Interface]),
//   - AllowedIPs каждого [Peer] в wg0.conf,
//   - userData.allowedIP каждой записи clientsTable с Disabled() == true
//     (резерв отключённого).
//
// Единственное место, где строится следующий свободный адрес — AddUser
// (planAddUserLocked). RegenerateUser (planRekeyLocked) IP не выделяет:
// перевыпуск всегда сохраняет адрес уже существующего peer'а (Г3).
func allocateIP(conf *wgConf, clients []ClientEntry) (string, error) {
	subnet := ""
	used := map[int]bool{}
	if m := ipRe.FindStringSubmatch(conf.iface["Address"]); m != nil {
		subnet = m[1]
		n, _ := strconv.Atoi(m[2])
		used[n] = true
	}
	// Подсеть при отсутствующем Address — обходом СРЕЗА conf.peers (порядок
	// в тексте wg0.conf, детерминированный), а не обходом map usedIPs
	// (порядок итерации карты в Go не определён — review круг 2, Low,
	// AR-01: недетерминизм, внесённый этим PR; nextFreeIP до PR-3 читала
	// подсеть тем же способом, через conf.peers).
	if subnet == "" {
		for _, p := range conf.peers {
			if m := ipRe.FindStringSubmatch(p["AllowedIPs"]); m != nil {
				subnet = m[1]
				break
			}
		}
	}
	for ip := range usedIPs(conf, clients) {
		m := ipRe.FindStringSubmatch(ip)
		if m == nil {
			continue
		}
		n, _ := strconv.Atoi(m[2])
		used[n] = true
	}
	if subnet == "" {
		subnet = "10.8.1"
		used[1] = true
	}
	next := 2
	for used[next] {
		next++
	}
	if next > 254 {
		return "", fmt.Errorf("свободных адресов в подсети %s.0/24 не осталось", subnet)
	}
	return fmt.Sprintf("%s.%d", subnet, next), nil
}
