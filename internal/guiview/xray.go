package guiview

// XRay в GUI (AL-01): тексты и решения без Fyne, чтобы их сверял тест.

import (
	"fmt"
	"strings"

	"amnezia-admin/core"
)

// XRayStatus — строка состояния после загрузки списка XRay: число
// пользователей, почему нет трафика, служебный UUID и сироты.
func XRayStatus(v core.XRayView) string {
	parts := []string{fmt.Sprintf("Пользователей: %d · %s", len(v.Clients), core.XRayStatsNote)}
	parts = append(parts, core.XRayNotes(v)...)
	return strings.Join(parts, " ")
}

// XRayDeleteActivity — что карточка удаления говорит о подключениях XRay:
// ничего не утверждает (статистики нет), а не «подключений не было».
const XRayDeleteActivity = "Подключался ли клиент — неизвестно: XRay не отдаёт статистику."

// XRayServiceInfo — ответ на попытку действия над служебной строкой.
const XRayServiceInfo = "Служебный UUID XRay создан при установке протокола. Программа его не удаляет, не отключает и не перевыпускает."

// XRayRestartTitle, XRayRestartBody, XRayRestartConfirm, XRayRestartCancel —
// диалог перед действием, перезапускающим XRay (решение владельца 1).
func XRayRestartTitle() string   { return core.XRayRestartTitle }
func XRayRestartBody() string    { return core.XRayRestartWarning }
func XRayRestartConfirm() string { return core.XRayRestartConfirm }
func XRayRestartCancel() string  { return "Отмена" }

// XRayServiceRow — строка таблицы для служебного UUID.
func XRayServiceRow(num int, v core.XRayView) Row {
	return Row{Num: num, Name: core.XRayServiceName, XRay: true, XRayService: true, KeyShown: v.ServicePrint, CanManage: true}
}

// xrayActivity — колонка «Активность» у XRay: состояние доступа там, где
// у WG «(откл.)», и «—» у включённого — статистики нет.
func xrayActivity(r Row) string {
	if r.XRayService {
		return "без действий"
	}
	if r.XRayAccess == core.XRayActive {
		return "—"
	}
	return core.XRayAccessText(r.XRayAccess)
}

// XRayAccessHeader — подпись колонки «Активность» у XRay (AU-UX Low).
const XRayAccessHeader = "Доступ"

// ErrorStatus — строка состояния об ошибке: ЕДИНСТВЕННОЕ место, где текст
// ошибки идёт в строку состояния, — через границу маскировки core.MaskText
// (SEC Н-2).
func ErrorStatus(err error, suffix string) string {
	return "Ошибка: " + core.MaskText(err.Error()) + suffix
}

// XRayStaleSuffix — хвост статуса при сбое чтения XRay: прежний список
// этого XRay показан (stale) или списка нет.
func XRayStaleSuffix(stale bool) string {
	if stale {
		return " · показаны данные прошлого чтения; изменения недоступны до успешного чтения."
	}
	return " · список XRay не показан."
}
