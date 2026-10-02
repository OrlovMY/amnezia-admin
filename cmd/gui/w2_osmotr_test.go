package main

// Прибор PR-W2: главное окно с протоколами трёх состояний. Выбранный
// протокол — «незнакомый контейнер» и «известен, не поддерживается»: самые
// длинные подписи в списке протоколов. Контейнеры — как их вернул бы
// core.FindContainers (amnezia-awg, amnezia-xray, amnezia-foo).

import (
	"testing"

	"amnezia-admin/core"
	"amnezia-admin/internal/guiview"
)

func openMainW2(pick int) func(t *testing.T, u *ui, sized func()) osmotrScene {
	return func(t *testing.T, u *ui, sized func()) osmotrScene {
		u.sess = core.NewSessionWithRunner(osmotrNoServer{}, &core.ServerCreds{Host: "203.0.113.10", User: "root"})
		u.containers = []core.Container{
			{Name: "amnezia-awg", Dir: "/opt/amnezia/awg", Proto: "AmneziaWG", Support: core.SupportYes},
			{Name: "amnezia-xray", Dir: "/opt/amnezia/xray", Proto: "XRay", Support: core.SupportKnownNo},
			{Name: "amnezia-foo", Support: core.SupportUnknown},
		}
		u.cur = &u.containers[pick]
		u.canManage = false
		u.showMainScreen()
		u.protoSelect.Selected = u.protoSelect.Options[pick]
		u.protoSelect.Refresh()
		var lerr error
		if u.cur.Dir == "" {
			lerr = core.ErrContainerDirUnknown // как вернул бы LoadClientsView
		}
		v := guiview.ViewState(*u.cur, nil, false, lerr)
		u.status.SetText(v.Status)
		sized()
		c := u.win.Canvas()
		return osmotrScene{root: c.Content(), canvas: c, mins: osmotrFrame(c.Content(), nil)}
	}
}

func init() {
	// Список протоколов прибор описывает по заглушке «(Select one)», как в
	// invMain; выбранная подпись меряется шириной самого списка. Строка
	// состояния — первая строка статуса ViewState.
	inv := func(status string) []string {
		return []string{
			"подпись:Сервер: root@203.0.113.10", "подпись:Протокол:", "список:(Select one)",
			"кнопка:Обновить", "кнопка:Создать", "кнопка:Переименовать", "кнопка:Вкл/Выкл",
			"кнопка:Перевыпустить", "кнопка:Удалить", "таблица:", "подпись:" + firstLine(status),
		}
	}
	osmotrForms = append(osmotrForms,
		osmotrForm{name: "(п) протоколы: незнакомый контейнер", open: openMainW2(2), inventory: inv("Незнакомый контейнер amnezia-foo: программа не знает, что это за протокол, и не заходит в него.")},
		osmotrForm{name: "(п) протоколы: XRay не поддерживается", open: openMainW2(1), inventory: inv("Протокол XRay не ведёт список пользователей в этой утилите — только просмотр.")},
	)
}
