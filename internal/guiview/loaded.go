package guiview

import (
	"fmt"
	"strings"

	"amnezia-admin/core"
)

// LoadedStatus — строка состояния после успешного чтения списка
// управляемого протокола (долг У7, паритет с CLI list): к базовому тексту
// view.Status добавляется ПРИЧИНА «?» в таблице — запрос статистики не
// удался (с причиной) или клиентов нет в ответе сервера, — и имена
// клиентов, у которых неизвестно, включены ли они (У1). Ячейки таблицы
// остаются прежними; без этой строки обе причины «?» выглядели одинаково.
// Отключённые в счёт «нет в статистике» не входят: их отсутствие штатно.
func LoadedStatus(base string, clients []core.ClientEntry, stats map[string]core.PeerStat, statsErr error) string {
	parts := []string{base}
	statsFailed := statsErr != nil
	absent := 0
	var unknown []string
	for _, cl := range clients {
		switch cl.EnabledState() {
		case core.EnabledActive:
			if core.ReadPeer(stats, statsFailed, cl.ClientID).State == core.PeerAbsent {
				absent++
			}
		case core.EnabledUnknown:
			unknown = append(unknown, cl.Name())
		}
	}
	switch {
	case statsFailed:
		// Раунд 4 (AU-UX Low): первым — что делать; сырая ошибка SSH бывает
		// в сотни знаков, поэтому в строке состояния — сжатая (начало и
		// конец, где обычно сама причина).
		parts = append(parts, "Статистику с сервера получить не удалось — нажмите «Обновить» позже "+
			"или проверьте связь с сервером; активность и трафик неизвестны («?»). "+
			"Причина: "+ShortReason(statsErr.Error())+".")
	case absent > 0:
		parts = append(parts, fmt.Sprintf("Клиентов нет в статистике сервера: %d. Подключиться они сейчас не могут; "+
			"их активность и трафик неизвестны («?»). Возможно, конфигурация сервера не применилась — "+
			"проверьте сервер, прежде чем удалять.", absent))
	}
	if note := core.EnabledUnknownNote(unknown); note != "" {
		parts = append(parts, note)
	}
	return strings.Join(parts, " · ")
}

// shortReasonMax — сколько знаков причины помещается в строку состояния.
const shortReasonMax = 120

// ShortReason — причина ошибки для строки состояния: пробелы и переводы
// строк схлопнуты; длиннее shortReasonMax — начало и конец через «…»
// (конец сохраняется: в ошибках SSH и docker там сама причина).
func ShortReason(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	r := []rune(s)
	if len(r) <= shortReasonMax {
		return s
	}
	head, tail := 50, shortReasonMax-50-3
	return string(r[:head]) + " … " + string(r[len(r)-tail:])
}
