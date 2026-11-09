package core

import (
	"strconv"
	"strings"
)

// SkippedContainer — что известно о контейнере, исключённом из переноса
// по согласию человека (-skip-xray). Present=false — в копии его не было,
// исключать нечего. Клиенты — три состояния (TargetClients): Known с
// пустым Names — измеренное «клиентов нет», !Known — «не удалось прочитать».
type SkippedContainer struct {
	Present bool
	Clients TargetClients
}

// BackupWithout — копия b без контейнера name (для -to-host -skip-xray:
// исключённый не попадает ни в предпроверку портов, ни в план установки,
// ни в перенос, ни в ключ vpn://). Исходная b не меняется; Files общие
// (только чтение).
func BackupWithout(b *Backup, name string) (*Backup, SkippedContainer) {
	if b == nil {
		return nil, SkippedContainer{}
	}
	var sk SkippedContainer
	out := *b
	out.Containers = nil
	for _, c := range b.Containers {
		if c.Name == name {
			sk.Present = true
			continue
		}
		out.Containers = append(out.Containers, c)
	}
	if sk.Present {
		sk.Clients = targetClientsOf(b, name, "")
	}
	return &out, sk
}

// SkippedXRayLines — громкое предупреждение о переносе без XRay (CLI и GUI —
// один текст). nil — XRay в копии не было, исключать было нечего.
func SkippedXRayLines(sk SkippedContainer) []string {
	if !sk.Present {
		return nil
	}
	var who string
	switch c := sk.Clients; {
	case !c.Known:
		who = "  Клиенты XRay: " + c.Why + " — сколько их и кто, неизвестно (это не «клиентов нет»)."
	case len(c.Names) == 0:
		why := c.Why
		if why == "" {
			why = "clientsTable прочитана, записей нет"
		}
		who = "  Клиенты XRay: нет (" + why + ")."
	default:
		who = "  Клиенты XRay (" + strconv.Itoa(len(c.Names)) + "): " + strings.Join(c.Names, ", ") + "."
	}
	return []string{
		"XRay НЕ перенесён по -skip-xray: его клиенты на новом сервере работать не будут.",
		who,
		"  Это не полная копия источника: XRay на новом сервере не ставится и в ключ vpn:// не попадает.",
	}
}
