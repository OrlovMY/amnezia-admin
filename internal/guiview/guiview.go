// Package guiview — решения GUI "что грузить / что показывать / доступно ли
// управление" для одного контейнера Amnezia, вынесенные из cmd/gui/main.go в
// отдельный пакет БЕЗ Fyne и без CGO (FIX-VIEW, задание Д2): юнит-тест этого
// пакета идёт без холодной сборки GUI. Граф импорта: cmd/gui → internal/guiview
// → core; cmd/cli этот пакет не импортирует (список пользователей для
// неуправляемых протоколов — фича только GUI, у CLI регресса не было).
//
// ViewState — единственное место, откуда refresh() в cmd/gui/main.go берёт
// решения "грузить список / запрашивать статистику / доступно управление /
// текст статуса" (Э3а, решение ядра 15.09): сама refresh() не содержит
// собственных условий по Container.Managed.
package guiview

import (
	"fmt"

	"amnezia-admin/core"
)

// View — решение GUI для одного контейнера на основе результата
// LoadClientsView.
type View struct {
	// LoadList — читать ли список пользователей (LoadClientsView). Всегда
	// true для любого amnezia-* контейнера (Д2): разница между управляемыми
	// и неуправляемыми — не "показывать ли список", а "можно ли им
	// управлять" (CanManage) и нужна ли серверная статистика (LoadStats).
	LoadList bool
	// LoadStats — запрашивать ли GetHandshakes/GetPeerStats (команда `wg
	// show`). Только для управляемых (WG-семейство) — у XRay/DNS и прочих
	// нет `wg`, лишняя команда на сервер (Г2 п.2).
	LoadStats bool
	// CanManage — доступны ли кнопки управления (создать/переименовать/
	// вкл-выкл/перевыпуск/удалить).
	CanManage bool
	// Status — дословный текст строки статуса (UI-01).
	Status string
}

// ProtoLabel — подпись протокола для списка протоколов и для строки статуса:
// имя протокола как есть для управляемых, "<Proto> (только просмотр)" для
// неуправляемых. ЕДИНСТВЕННОЕ место этой подписи (Д2) — второго суффикса
// быть не должно (ни в core.Container.Proto, ни второй раз в GUI).
func ProtoLabel(c core.Container) string {
	if c.Managed {
		return c.Proto
	}
	return fmt.Sprintf("%s (только просмотр)", c.Proto)
}

// ViewState решает состояние GUI для контейнера c по результату
// c.LoadClientsView (clients, existed, err), см. таблицу дословных строк в
// задании FIX-VIEW, Д2. LoadStats и CanManage равны c.Managed — единственная
// переменная, влияющая на них; err/existed влияют только на текст Status.
func ViewState(c core.Container, clients []core.ClientEntry, existed bool, err error) View {
	v := View{
		LoadList:  true, // Д2: список пробуем читать для ЛЮБОГО amnezia-*
		LoadStats: c.Managed,
		CanManage: c.Managed,
	}
	switch {
	case c.Managed && err != nil:
		v.Status = "Ошибка: " + err.Error()
	case c.Managed:
		v.Status = fmt.Sprintf("Пользователей: %d · трафик и активность — с момента перезапуска сервера", len(clients))
	case err != nil:
		v.Status = fmt.Sprintf("Не удалось прочитать список пользователей %s: %s.", c.Proto, err.Error())
	case !existed:
		v.Status = fmt.Sprintf("Протокол %s не ведёт список пользователей в этой утилите — только просмотр.", c.Proto)
	default:
		v.Status = fmt.Sprintf("Пользователей: %d — только просмотр: управление для протокола %s не поддерживается.", len(clients), c.Proto)
	}
	return v
}
