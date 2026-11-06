package guiview

import (
	"strings"

	"amnezia-admin/core"
)

// DetailText — одно поле «Подробнее» для человека. Три состояния печатаются
// тремя разными видами; пустое значение не печатается никогда — состояние
// берётся из поля State, а не из пустоты Value.
func DetailText(f core.DetailField) string {
	switch f.State {
	case core.DetailKnown:
		if f.Value != "" {
			return f.Value
		}
		return "не удалось узнать (значение пустое)"
	case core.DetailNotApplies:
		if f.Reason != "" {
			return "не применяется (" + f.Reason + ")"
		}
		return "не применяется"
	default:
		if f.Reason != "" {
			return "не удалось узнать: " + f.Reason
		}
		return "не удалось узнать"
	}
}

// ProtoDetailsTitle — заголовок окна «Подробнее».
func ProtoDetailsTitle(c core.Container) string { return "Подробнее: " + c.Title() }

// ProtoDetailsText — текст окна «Подробнее» протокола.
func ProtoDetailsText(d core.ProtoDetails) string {
	rows := []struct {
		k string
		f core.DetailField
	}{
		{"Контейнер", d.Container},
		{"Файл конфигурации", d.ConfFile},
		{"Порт", d.Port},
		{"Транспорт", d.Transport},
		{"Подсеть", d.Subnet},
		{"Версия параметров", d.Version},
	}
	var b strings.Builder
	for i, r := range rows {
		if i > 0 {
			b.WriteByte('\n')
		}
		b.WriteString(r.k + ": " + DetailText(r.f))
	}
	return b.String()
}
