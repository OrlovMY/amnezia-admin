package core

// Повторная выдача админского ключа vpn:// для сервера, к которому уже есть
// доступ (команда admin-key CLI и пункт «Выдать ключ vpn://…» GUI).
//
// В ключ идёт ФАКТИЧЕСКОЕ состояние сервера: список запущенных контейнеров
// и параметры протокола, прочитанные из их конфигураций, — не то, что
// записано в старом ключе.
//
// Три состояния по каждому контейнеру сервера (CLAUDE.md, «незнание не
// выдаётся за знание»): параметры прочитаны (Containers); не прочитаны или
// тип в ключ не кладётся (Gaps — с причиной); и третье для сервера в
// целом — список контейнеров не прочитан вовсе (ошибка). Неполный ключ
// молча не выдаётся: решение о нём принимает вызывающий, показав Gaps.

import (
	"errors"
	"fmt"
)

// AdminKeyGap — контейнер сервера, которого в ключе НЕ будет, и почему.
type AdminKeyGap struct {
	Container string
	Reason    string
}

// AdminKeyReissue — что можно положить в ключ по прочитанному с сервера.
type AdminKeyReissue struct {
	Containers []AdminKeyContainer
	Gaps       []AdminKeyGap
	Notes      []string
	// Default — контейнер по умолчанию: предпочтённый вызывающим, если он
	// в ключе, иначе первый из Containers ("" — контейнеров нет).
	Default string
}

// Complete — в ключ попадут ВСЕ контейнеры Amnezia сервера.
func (r AdminKeyReissue) Complete() bool { return len(r.Gaps) == 0 && len(r.Containers) > 0 }

// ErrAdminKeyNoContainers — ни у одного контейнера сервера параметры не
// прочитаны: ключ без протоколов не выдаётся даже с согласием на неполный.
var ErrAdminKeyNoContainers = errors.New("ни у одного контейнера параметры не прочитаны — ключ не выдаётся")

// adminKeyContainerFrom — параметры протокола одного найденного контейнера.
func (s *Session) adminKeyContainerFrom(c *Container) (AdminKeyContainer, string, error) {
	n := c.Name
	if c.Dir == "" {
		return AdminKeyContainer{}, "", fmt.Errorf("ключ: контейнера %q на сервере не видно — параметры не прочитаны", n)
	}
	var conf []byte
	note := ""
	if n == "amnezia-xray" {
		raw, rerr := s.catIn(c, c.Dir+"/"+xrayConfFile)
		if rerr != nil {
			return AdminKeyContainer{}, "", fmt.Errorf("ключ: контейнер %q, server.json не прочитан: %w", n, rerr)
		}
		conf = []byte(raw)
		if srv, perr := parseXRayServerEmptyOK(conf); perr == nil && len(srv.ids) == 0 {
			note = XRayNoClientsNote
		}
	} else {
		out, rerr := s.catConf(c)
		if rerr != nil {
			return AdminKeyContainer{}, "", fmt.Errorf("ключ: контейнер %q, конфигурация не прочитана: %w", n, rerr)
		}
		conf = []byte(out)
	}
	p, perr := ProtocolParamsFromServer(n, conf)
	if perr != nil {
		return AdminKeyContainer{}, "", perr
	}
	return AdminKeyContainer{Name: n, Protocol: p}, note, nil
}

// AdminKeyReissuePlan — параметры для ключа по ВСЕМ контейнерам Amnezia,
// запущенным на сервере. Ошибка — только если список контейнеров не
// прочитан (тогда неизвестно ничего); контейнер, параметры которого не
// прочитаны или тип которого в ключ не кладётся, — в Gaps, не ошибка и не
// молчаливый пропуск. preferDefault — контейнер по умолчанию из прежнего
// ключа ("" — нет).
func (s *Session) AdminKeyReissuePlan(preferDefault string) (AdminKeyReissue, error) {
	found, err := s.FindContainers()
	if err != nil {
		return AdminKeyReissue{}, fmt.Errorf("ключ: список контейнеров на сервере не прочитан: %w", err)
	}
	var r AdminKeyReissue
	for i := range found {
		c := &found[i]
		if _, ok := adminKeyProto(c.Name); !ok {
			r.Gaps = append(r.Gaps, AdminKeyGap{Container: c.Name, Reason: "тип контейнера в ключ не кладётся (программа знает формат ключа только для AWG, AWG2, WireGuard и XRay)"})
			continue
		}
		kc, note, err := s.adminKeyContainerFrom(c)
		if err != nil {
			r.Gaps = append(r.Gaps, AdminKeyGap{Container: c.Name, Reason: MaskText(err.Error())})
			continue
		}
		r.Containers = append(r.Containers, kc)
		if note != "" {
			r.Notes = append(r.Notes, note)
		}
	}
	for _, c := range r.Containers {
		if c.Name == preferDefault {
			r.Default = c.Name
		}
	}
	if r.Default == "" && len(r.Containers) > 0 {
		r.Default = r.Containers[0].Name
	}
	return r, nil
}
