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
		parts = append(parts, fmt.Sprintf("Статистику с сервера получить не удалось (%s): "+
			"активность и трафик неизвестны («?»).", statsErr.Error()))
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
