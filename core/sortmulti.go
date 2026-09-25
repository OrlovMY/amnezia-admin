// Файл sortmulti.go — многоключевая (primary+secondary) сортировка списка
// клиентов для GUI-таблицы (клик по заголовку колонки). Держится отдельно от
// SortByActivity (core.go), которая остаётся дефолтной сортировкой CLI.
package core

import "sort"

// SortColumn — сортируемая колонка таблицы пользователей
type SortColumn int

const (
	SortNone          SortColumn = iota
	SortByName                   // "Имя" — алфавит
	SortByCreated                // "Создан" — дата создания (RFC3339, сравнивается как строка)
	SortByActivityCol            // "Активность" — LastHandshake
	SortByTraffic                // "Трафик" — RxBytes (см. комментарий к compareByColumn)
)

// SortDir — направление сортировки
type SortDir int

const (
	Asc SortDir = iota
	Desc
)

// compareByColumn возвращает -1/0/1 при сравнении a и b по указанной колонке.
// SortNone (или любая нераспознанная колонка) всегда считается равной —
// используется как "нет secondary".
func compareByColumn(a, b ClientEntry, stats map[string]PeerStat, col SortColumn) int {
	switch col {
	case SortByName:
		an, bn := a.Name(), b.Name()
		switch {
		case an < bn:
			return -1
		case an > bn:
			return 1
		default:
			return 0
		}
	case SortByCreated:
		ac, bc := a.Created(), b.Created()
		switch {
		case ac < bc: // RFC3339 сравнивается лексикографически = хронологически
			return -1
		case ac > bc:
			return 1
		default:
			return 0
		}
	case SortByActivityCol:
		sa, _ := ReadPeer(stats, false, a.ClientID).Measured()
		sb, _ := ReadPeer(stats, false, b.ClientID).Measured()
		ta, tb := sa.LastHandshake, sb.LastHandshake
		switch {
		case ta.Before(tb):
			return -1
		case ta.After(tb):
			return 1
		default:
			return 0
		}
	case SortByTraffic:
		// Трафик сортируется по RxBytes (не Rx+Tx и не Tx отдельно) —
		// решение UX/BE-02: RX обычно доминирует по объёму (скачивание через
		// VPN) и достаточен как индикатор активности использования канала.
		sa, _ := ReadPeer(stats, false, a.ClientID).Measured()
		sb, _ := ReadPeer(stats, false, b.ClientID).Measured()
		ra, rb := sa.RxBytes, sb.RxBytes
		switch {
		case ra < rb:
			return -1
		case ra > rb:
			return 1
		default:
			return 0
		}
	default:
		return 0
	}
}

// SortClientsMultiKey сортирует clients на месте по primary-колонке
// (primaryDir — направление); при равенстве по primary — по secondary-колонке
// (secondaryDir); при равенстве и по secondary (или если secondary==SortNone)
// сохраняется исходный относительный порядок (сортировка стабильна).
func SortClientsMultiKey(clients []ClientEntry, stats map[string]PeerStat, primary SortColumn, primaryDir SortDir, secondary SortColumn, secondaryDir SortDir) {
	sort.SliceStable(clients, func(i, j int) bool {
		// Неизвестные — в конец ПРИ ЛЮБОМ направлении (задание
		// НЕЗНАНИЕ-ТРАФИК, ревью QA-01): сортировка трафика по возрастанию —
		// способ искать неиспользуемых на удаление, и клиент с неизвестным
		// трафиком не имеет права встать первым как «наименьший».
		// unknownOrder применяется ДО учёта направления.
		if u := unknownOrder(clients[i], clients[j], stats, primary); u != 0 {
			return u < 0
		}
		c := compareByColumn(clients[i], clients[j], stats, primary)
		if primaryDir == Desc {
			c = -c
		}
		if c != 0 {
			return c < 0
		}
		if secondary == SortNone {
			return false
		}
		if u := unknownOrder(clients[i], clients[j], stats, secondary); u != 0 {
			return u < 0
		}
		c2 := compareByColumn(clients[i], clients[j], stats, secondary)
		if secondaryDir == Desc {
			c2 = -c2
		}
		return c2 < 0
	})
}

// unknownOrder — порядок по ЗНАНИЮ для колонок статистики: -1, если про a
// значение известно, а про b нет (a выше); 1 — наоборот; 0 — одинаково
// (или колонка не из статистики). Не зависит от направления сортировки.
func unknownOrder(a, b ClientEntry, stats map[string]PeerStat, col SortColumn) int {
	if col != SortByActivityCol && col != SortByTraffic {
		return 0
	}
	_, ka := ReadPeer(stats, false, a.ClientID).Measured()
	_, kb := ReadPeer(stats, false, b.ClientID).Measured()
	switch {
	case ka && !kb:
		return -1
	case !ka && kb:
		return 1
	}
	return 0
}
