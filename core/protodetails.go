package core

import "strings"

// Подробности протокола для кнопки «Подробнее» (пожелание владельца 05.11).
//
// ТРИ СОСТОЯНИЯ У КАЖДОГО ПОЛЯ (CLAUDE.md): значение; «не применяется» (у
// XRay нет подсети); «не удалось узнать» с причиной. Пустая строка значения
// сама по себе не означает ничего — состояние несёт DetailField.State, и
// печать не вправе угадывать его по пустоте.

// Состояния поля подробностей.
const (
	DetailKnown      = "known"
	DetailNotApplies = "n/a"
	DetailUnknown    = "unknown"
)

// DetailField — одно поле подробностей.
type DetailField struct {
	State  string // DetailKnown / DetailNotApplies / DetailUnknown
	Value  string // только при DetailKnown
	Reason string // при DetailUnknown — почему; при DetailNotApplies — почему не применяется
}

func known(v string) DetailField          { return DetailField{State: DetailKnown, Value: v} }
func unknownField(why string) DetailField { return DetailField{State: DetailUnknown, Reason: why} }

// ProtoDetails — подробности протокола (контейнера) сервера.
type ProtoDetails struct {
	Container DetailField
	ConfFile  DetailField
	Port      DetailField
	Subnet    DetailField
	Transport DetailField
	Version   DetailField
}

// ReadProtoDetails читает файл конфигурации сервера контейнера c (только
// чтение) и раскладывает его на поля. Ошибка чтения не возвращается
// отдельно: она — причина «не удалось узнать» у каждого зависящего поля.
func (s *Session) ReadProtoDetails(c *Container) ProtoDetails {
	return protoDetailsFrom(c, func(name string) ([]byte, string, string) {
		return s.readFileState(c, name)
	})
}

// protoDetailsFrom — разбор без сети (read подставляется в тестах).
func protoDetailsFrom(c *Container, read func(name string) (data []byte, status, reason string)) ProtoDetails {
	var d ProtoDetails
	if c.Name != "" {
		d.Container = known(c.Name)
	} else {
		d.Container = unknownField("имя контейнера не получено")
	}
	cf, ok := confNameOf(c)
	if !ok || c.Dir == "" {
		why := "контейнер не из закрытого списка — файл конфигурации неизвестен"
		d.ConfFile, d.Port, d.Subnet, d.Transport, d.Version = unknownField(why), unknownField(why), unknownField(why), unknownField(why), unknownField(why)
		return d
	}
	d.ConfFile = known(c.Dir + "/" + cf)
	data, st, why := read(cf)
	if st != FileSaved {
		if st == FileAbsent {
			why = "файла " + cf + " нет"
		}
		if why == "" {
			why = "файл " + cf + " не прочитан"
		}
		why = MaskText(why)
		d.Port, d.Version = unknownField(why), unknownField(why)
		if IsXRay(c) {
			d.Subnet = DetailField{State: DetailNotApplies, Reason: "у XRay нет подсети"}
			d.Transport = unknownField(why)
		} else {
			d.Subnet = unknownField(why)
			d.Transport = known("udp")
		}
		return d
	}
	v, vst, vwhy := protoVersion(c, data)
	if vst == VersionKnown {
		d.Version = known(v)
	} else {
		d.Version = unknownField(vwhy)
	}
	port, subnet := portSubnet(c, data)
	if strings.TrimSpace(port) != "" {
		d.Port = known(strings.TrimSpace(port))
	} else {
		d.Port = unknownField("порт в " + cf + " не найден")
	}
	if IsXRay(c) {
		d.Subnet = DetailField{State: DetailNotApplies, Reason: "у XRay нет подсети"}
		if _, err := parseXRayServer(data); err == nil {
			d.Transport = known("tcp/reality")
		} else {
			d.Transport = unknownField("формат server.json не распознан")
		}
	} else {
		if strings.TrimSpace(subnet) != "" {
			d.Subnet = known(strings.TrimSpace(subnet))
		} else {
			d.Subnet = unknownField("подсеть (Address) в " + cf + " не найдена")
		}
		d.Transport = known("udp")
	}
	return d
}
