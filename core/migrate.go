package core

// Проверка совместимости цели перед переездом (решения владельца 4–5,
// решение ядра Р-2 от 04.10). Только чтение. До записи на новый сервер
// сверяются по каждому сохранённому в копии контейнеру: есть ли он на цели,
// протокол и версия, порт и подсеть. У каждого признака три состояния —
// совпало / не совпало / узнать не удалось; не совпало и не удалось — СТОП
// до переезда с объяснением, что сделать на новом сервере. Обновление версии
// при переезде не делается (бэклог владельца).
//
// Адрес выдачи — четыре итога (проект БК ред. 3, Р3-3): тот же / по имени /
// другой / проверить не удалось. «Другой» и «не удалось» не останавливают
// сами, но требуют отдельного подтверждения (NeedAddressConfirm).

import (
	"fmt"
	"net"
	"strings"
)

// CompatState — исход одной сверки.
type CompatState int

const (
	CompatUnknown  CompatState = iota // узнать не удалось — нулевое значение: пока не измерено — не знаем
	CompatMatch                       // совпало
	CompatMismatch                    // не совпало
)

func (c CompatState) String() string {
	switch c {
	case CompatMatch:
		return "совпадает"
	case CompatMismatch:
		return "НЕ совпадает"
	}
	return "узнать не удалось"
}

// CompatRow — строка проверки цели.
type CompatRow struct {
	Container string
	What      string // «контейнер», «протокол и версия», «порт», «подсеть»
	State     CompatState
	Text      string // что сказать человеку; для не «совпадает» — что сделать
}

// AddressVerdict — итог проверки адреса выдачи.
type AddressVerdict int

const (
	AddrUnknown AddressVerdict = iota // проверить не удалось
	AddrSame                          // адрес тот же
	AddrByName                        // в копии имя
	AddrDiffers                       // в копии IP, у цели другой
)

// ForeignConfigsNote — всегда: про конфиги, выданные не этой программой.
const ForeignConfigsNote = "Конфиги, выданные не этой программой (например, приложением Amnezia), могли быть выданы с другим адресом — проверить их программа не может."

// CompatReport — итог проверки цели.
type CompatReport struct {
	Rows []CompatRow
	// Stop — переезд невозможен до исправления на новом сервере (есть строка
	// «не совпадает» или «узнать не удалось»).
	Stop bool
	// Untouched — контейнеры цели, которых нет в копии: переезд их не трогает.
	Untouched []string

	Address            AddressVerdict
	AddressText        string
	NeedAddressConfirm bool // «другой» или «не удалось» — нужно отдельное подтверждение
}

func (r *CompatReport) add(ctr, what string, st CompatState, text string) {
	r.Rows = append(r.Rows, CompatRow{ctr, what, st, text})
	if st != CompatMatch {
		r.Stop = true
	}
}

// installHint — Р-2: что сделать на новом сервере.
func installHint(bc BackupContainer) string {
	h := "установите на новом сервере " + bc.Proto
	if bc.Version != "" && bc.Version != bc.Proto {
		h += " версии " + bc.Version
	}
	if bc.Port != "" {
		h += " с портом " + bc.Port
	}
	if bc.Subnet != "" {
		h += " и подсетью " + bc.Subnet
	}
	return h + " (приложение Amnezia → протокол → настройки) и повторите"
}

// CheckTarget — проверка цели (этот Session) по копии b. Ошибка — только
// если не получен список контейнеров цели: тогда проверки нет вовсе, и
// переезд невозможен (вызывающий говорит об этом прямо).
func (s *Session) CheckTarget(b *Backup, resolve Resolver) (*CompatReport, error) {
	cs, err := s.FindContainers()
	if err != nil {
		return nil, fmt.Errorf("список контейнеров нового сервера не получен — совместимость не проверена: %w", err)
	}
	byName := map[string]*Container{}
	for i := range cs {
		byName[cs[i].Name] = &cs[i]
	}
	r := &CompatReport{}
	inBackup := map[string]bool{}
	for _, bc := range b.Containers {
		inBackup[bc.Name] = true
		switch bc.Status {
		case CtrNotIncluded:
			continue // протокол копией не поддерживается — перечислен в копии
		case CtrSaved:
		default:
			r.add(bc.Name, "контейнер", CompatUnknown, "в копии этот протокол не сохранён ("+bc.Reason+") — перенести его нельзя; снимите копию со старого сервера заново")
			continue
		}
		c := byName[bc.Name]
		if c == nil {
			r.add(bc.Name, "контейнер", CompatMismatch, "на новом сервере нет "+bc.Proto+" — "+installHint(bc))
			continue
		}
		cf, ok := confNameOf(c)
		if !ok {
			r.add(bc.Name, "контейнер", CompatUnknown, "контейнер на новом сервере не распознан — "+installHint(bc))
			continue
		}
		data, st, why := s.readFileState(c, cf)
		if st != FileSaved {
			if st == FileAbsent {
				why = "файла " + cf + " нет"
			}
			r.add(bc.Name, "протокол и версия", CompatUnknown, "на новом сервере "+why+" — версию определить не удалось; "+installHint(bc))
			continue
		}
		r.versionRow(bc, c, data)
		port, subnet := portSubnet(c, data)
		r.cmpRow(bc, "порт", bc.Port, port)
		if !IsXRay(c) {
			r.cmpRow(bc, "подсеть", bc.Subnet, subnet)
		}
	}
	for _, c := range cs {
		if !inBackup[c.Name] {
			r.Untouched = append(r.Untouched, c.Name)
		}
	}
	host := ""
	if s.Creds != nil {
		host = s.Creds.Host
	}
	r.Address, r.AddressText = addressVerdict(b.IssuedAddress, host, resolve)
	r.NeedAddressConfirm = r.Address == AddrDiffers || r.Address == AddrUnknown
	return r, nil
}

func confNameOf(c *Container) (string, bool) {
	if IsXRay(c) {
		return xrayConfFile, true
	}
	f, err := WGFamilyOf(c)
	if err != nil {
		return "", false
	}
	return f.File, true
}

func (r *CompatReport) versionRow(bc BackupContainer, c *Container, conf []byte) {
	v, st, why := protoVersion(c, conf)
	switch {
	case bc.VersionState != VersionKnown:
		why := bc.VersionReason
		if why == "" {
			why = "причина в копии не записана"
		}
		r.add(bc.Name, "протокол и версия", CompatUnknown, "версию протокола в копии определить не удалось ("+why+") — переезд невозможен: версии не сверить")
	case st != VersionKnown:
		r.add(bc.Name, "протокол и версия", CompatUnknown, "версию определить не удалось на новом сервере ("+why+") — "+installHint(bc))
	case v != bc.Version:
		r.add(bc.Name, "протокол и версия", CompatMismatch, fmt.Sprintf("в копии %s, на новом сервере %s — переустановите на новом сервере ту же версию: %s", bc.Version, v, installHint(bc)))
	default:
		r.add(bc.Name, "протокол и версия", CompatMatch, bc.Proto+" "+v)
	}
}

func (r *CompatReport) cmpRow(bc BackupContainer, what, want, got string) {
	switch {
	case want == "" || got == "":
		where := "в копии"
		if want != "" {
			where = "на новом сервере"
		}
		r.add(bc.Name, what, CompatUnknown, what+" "+where+" не найден(а) — сверить нельзя; "+installHint(bc))
	case want != got:
		r.add(bc.Name, what, CompatMismatch, fmt.Sprintf("%s: в копии %s, на новом сервере %s — %s", what, want, got, installHint(bc)))
	default:
		r.add(bc.Name, what, CompatMatch, want)
	}
}

func hostIPs(host string, resolve Resolver) ([]string, bool) {
	if ip := net.ParseIP(host); ip != nil {
		return []string{ip.String()}, true
	}
	if resolve == nil {
		return nil, false
	}
	ips, err := resolve(host)
	if err != nil || len(ips) == 0 {
		return nil, false
	}
	var out []string
	for _, ip := range ips {
		out = append(out, ip.String())
	}
	return out, true
}

func intersects(a, b []string) bool {
	for _, x := range a {
		for _, y := range b {
			if x == y {
				return true
			}
		}
	}
	return false
}

// addressVerdict — четыре итога; «не удалось» никогда не становится «тот же».
func addressVerdict(a IssuedAddress, targetHost string, resolve Resolver) (AddressVerdict, string) {
	switch a.Kind {
	case AddressKindIP:
		tips, ok := hostIPs(targetHost, resolve)
		switch {
		case !ok:
			return AddrUnknown, "Проверить адрес не удалось: адрес нового сервера " + targetHost + " не разрешился. Неизвестно, будут ли работать выданные конфиги."
		case intersects([]string{a.Value}, tips):
			return AddrSame, "Адрес тот же (" + a.Value + "): выданные этой программой конфиги будут работать."
		}
		return AddrDiffers, "Конфиги выданы с адресом " + a.Value + ", а у нового сервера " + strings.Join(tips, ", ") + ". Старые конфиги к новому серверу НЕ ПРИДУТ, пока адрес " + a.Value + " не перенесён на него у хостера. Восстановление этого не исправит."
	case AddressKindName:
		tips, tok := hostIPs(targetHost, resolve)
		nips, nok := hostIPs(a.Value, resolve)
		switch {
		case strings.EqualFold(targetHost, a.Value):
			return AddrByName, "Конфиги выданы по имени " + a.Value + ", и новый сервер доступен по этому же имени: выданные этой программой конфиги будут работать."
		case !tok || !nok:
			// AU-LOGIC Medium-1 (решение ядра): не разрешилось — «проверить
			// не удалось» с подтверждением, а не «по имени».
			return AddrUnknown, "Проверить адрес не удалось: имя " + a.Value + " или адрес нового сервера " + targetHost + " сейчас не разрешились. Неизвестно, будут ли работать выданные конфиги; после переезда имя должно указывать на новый сервер."
		case intersects(nips, tips):
			return AddrByName, "Конфиги выданы по имени " + a.Value + "; имя уже указывает на новый сервер (" + strings.Join(tips, ", ") + ")."
		case a.ResolvedIP != "" && intersects(nips, strings.Split(a.ResolvedIP, ",")):
			// QA-01 (б), решение ядра: имя всё ещё ведёт на СТАРЫЙ сервер —
			// адрес отличается, нужно подтверждение.
			return AddrDiffers, "Конфиги выданы по имени " + a.Value + ", и оно всё ещё указывает на старый сервер (" + strings.Join(nips, ", ") + "), а не на новый (" + strings.Join(tips, ", ") + "). Перенаправьте имя на новый сервер — иначе пользователи будут стучаться на старый."
		}
		return AddrByName, "Конфиги выданы по имени " + a.Value + "; сейчас оно указывает на " + strings.Join(nips, ", ") + ", а не на новый сервер (" + strings.Join(tips, ", ") + "). После восстановления перенаправьте имя на новый сервер, иначе пользователи будут стучаться на старый."
	}
	return AddrUnknown, "Проверить адрес не удалось: в копии нет адреса, по которому выдавались конфиги. Неизвестно, будут ли работать выданные конфиги."
}
