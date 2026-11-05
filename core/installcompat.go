package core

import (
	"fmt"

	"amnezia-admin/core/provision"
)

// Совместимость установки на чистый сервер (план БК «перенос на чистый
// сервер», раздел 2, PR 4). Только данные и чистые функции: на серверах
// ничего не выполняется.
//
// Решение владельца: ставить свежую ревизию, если она ставит СЕМЕЙСТВО
// параметров исходного контейнера (protoVersion), иначе другую
// закреплённую, иначе стоп.

// Вердикт по контейнеру — CompatState (migrate.go): нулевое значение —
// «не знаем», забытое присваивание не превращается ни в «да», ни в «нет».
// Mismatch — известно, что ни одна закреплённая ревизия семейство не ставит
// (в т.ч. ставит «без параметров семейства» — SupportPartial).

// DefaultRevisionPreference — порядок выбора: самая свежая первой.
var DefaultRevisionPreference = []string{provision.Rev5106, provision.RevDev94b51df}

// InstallItem — план установки одного контейнера копии.
type InstallItem struct {
	Container string // имя контейнера копии (его же поднимет установка)
	Family    string // семейство параметров (BackupContainer.Version)
	Revision  string // выбранная ревизия скриптов; "" — не выбрана
	Compat    CompatState
	Reason    string // почему не Match; у Match — оговорка
	Source    string // клетка таблицы — доказательство выбранной ревизии
	// NeedsMeasurement — ревизия пишет параметры, но версия бинаря не
	// закреплена (SupportScriptOnly): совместимость подтвердится только
	// измерением (CheckTarget) после установки.
	NeedsMeasurement bool
	// Параметры установки из копии.
	Port      string
	Subnet    string // у XRay пусто
	Transport string // только XRay: «tcp/reality»
	SNI       string // только XRay: serverNames
}

// InstallSkip — контейнер копии, который не ставится (не входит в копию).
type InstallSkip struct {
	Container, Reason string
}

// InstallPlan — план по всей копии.
type InstallPlan struct {
	Items   []InstallItem
	Skipped []InstallSkip
}

// Ready — все контейнеры совместимы; иначе установка — стоп. Пустой план
// не готов.
func (p InstallPlan) Ready() bool {
	if len(p.Items) == 0 {
		return false
	}
	for _, it := range p.Items {
		if it.Compat != CompatMatch {
			return false
		}
	}
	return true
}

// PlanInstall — по каждому контейнеру копии: ревизия и вердикт. prefs —
// порядок ревизий (nil — DefaultRevisionPreference).
func PlanInstall(b *Backup, prefs []string) InstallPlan {
	if prefs == nil {
		prefs = DefaultRevisionPreference
	}
	var p InstallPlan
	if b == nil {
		return p
	}
	for i := range b.Containers {
		bc := &b.Containers[i]
		if bc.Status == CtrNotIncluded {
			p.Skipped = append(p.Skipped, InstallSkip{bc.Name, bc.Reason})
			continue
		}
		p.Items = append(p.Items, planContainer(bc, prefs))
	}
	return p
}

func planContainer(bc *BackupContainer, prefs []string) InstallItem {
	it := InstallItem{Container: bc.Name, Family: bc.Version, Port: bc.Port, Subnet: bc.Subnet}
	unknown := func(format string, a ...any) InstallItem {
		it.Compat, it.Reason = CompatUnknown, fmt.Sprintf(format, a...)
		return it
	}
	if bc.Status != CtrSaved {
		return unknown("контейнер в копии не сохранён (%s): %s", bc.Status, bc.Reason)
	}
	if bc.VersionState != VersionKnown {
		return unknown("семейство параметров не определено: %s", bc.VersionReason)
	}
	if bc.Port == "" {
		return unknown("в копии нет порта")
	}
	if bc.Version == "XRay" {
		if len(bc.Files) == 0 {
			return unknown("в копии нет server.json")
		}
		srv, err := parseXRayServer(bc.Files[0].Data.Bytes())
		if err != nil {
			return unknown("server.json копии не разобран — транспорт и SNI неизвестны")
		}
		it.Transport, it.SNI = "tcp/reality", srv.serverName
	} else if bc.Subnet == "" {
		return unknown("в копии нет подсети")
	}
	sawUnknown, why := false, ""
	for _, rev := range prefs {
		s := provision.InstallSupport(rev, bc.Version)
		switch {
		case s.State == provision.SupportUnknown:
			sawUnknown = true
			why += fmt.Sprintf("; %s: нет данных", rev)
			continue
		case s.State != provision.SupportYes && s.State != provision.SupportScriptOnly:
			why += fmt.Sprintf("; %s: %s", rev, s.State)
			continue
		case s.Container != bc.Name:
			why += fmt.Sprintf("; %s: ставит %s, а не %s", rev, s.Container, bc.Name)
			continue
		}
		it.Revision, it.Compat, it.Source = rev, CompatMatch, s.Source
		if s.State == provision.SupportScriptOnly {
			it.NeedsMeasurement = true
			it.Reason = "совместимость подтвердится измерением после установки: " + s.Note
		}
		return it
	}
	if sawUnknown {
		return unknown("ни одна ревизия не подтверждает семейство %q%s", bc.Version, why)
	}
	it.Compat, it.Reason = CompatMismatch, fmt.Sprintf("ни одна закреплённая ревизия не ставит семейство %q%s", bc.Version, why)
	return it
}
