package core

import (
	"fmt"
	"strings"

	"amnezia-admin/core/provision"
)

// Совместимость установки на чистый сервер (план БК «перенос на чистый
// сервер», раздел 2, PR 4). Только данные и чистые функции: на серверах
// ничего не выполняется.
//
// Решение владельца (дословно): ставить «свежую версию, если совместима,
// иначе такую же, как на исходном».
//
// Решение ядра о толковании (ревью-1 M2): ревизию скриптов, которыми был
// поставлен исходный сервер, измерить нельзя — в копии её нет и на сервере
// она не записывается. Поэтому «такая же, как на исходном» здесь означает
// «ревизия, которая ставит ТО ЖЕ СЕМЕЙСТВО параметров (protoVersion), что у
// исходного контейнера». Порядок: самая свежая закреплённая, затем другие
// закреплённые по DefaultRevisionPreference, иначе стоп. Об откате на не
// первую ревизию говорится в Reason.

// Вердикт — CompatState (migrate.go), но в ДРУГОМ смысле, чем в проверке
// цели: здесь он отвечает на вопрос «есть ли закреплённая ревизия, которая
// ставит семейство копии», а не «цель совпала с копией». Поэтому String()
// сам по себе ничего не объясняет: потребитель печатает Verdict() и Reason.
// Нулевое значение — «не знаем». Mismatch — известно, что ни одна
// закреплённая ревизия семейство не ставит (в т.ч. SupportPartial).

// sourceRevisionNote — одна фраза о толковании решения владельца для Reason
// отката.
const sourceRevisionNote = "ревизию скриптов исходного сервера измерить нельзя; взята ревизия, которая ставит то же семейство параметров"

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

// Verdict — подпись вердикта для человека. Match с NeedsMeasurement не
// печатается голым «совпало»: совпадение только по скриптам.
func (it InstallItem) Verdict() string {
	switch {
	case it.Compat == CompatMatch && it.NeedsMeasurement && it.Family == "XRay":
		// Скрипты server.json не пишут (аудит AU-1 N1): он и ключи — из копии.
		return "совпало: контейнер ставят скрипты, server.json и ключи — из копии, версия бинаря подтвердится после установки"
	case it.Compat == CompatMatch && it.NeedsMeasurement:
		return "совпало по скриптам, версия бинаря подтвердится после установки"
	case it.Compat == CompatMatch:
		return "совпало"
	case it.Compat == CompatMismatch:
		return "ни одна закреплённая ревизия не ставит семейство"
	}
	return "нет данных"
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

// Ready — все контейнеры совместимы ПО СКРИПТАМ; иначе установка — стоп.
// Где у контейнера NeedsMeasurement, совместимость подтверждается только
// измерением после установки — это сводит NeedsMeasurement() плана, и
// потребитель обязан печатать его вместе с Ready. Пустой план не готов. Skipped НЕ учитываются: потребитель обязан назвать их целиком
// (контейнер и причину) — они не будут поставлены.
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

// NeedsMeasurement — хоть один контейнер плана совместим только по
// скриптам: «готов» без оговорки печатать нельзя (аудит AU-1 M2).
func (p InstallPlan) NeedsMeasurement() bool {
	for _, it := range p.Items {
		if it.NeedsMeasurement {
			return true
		}
	}
	return false
}

// PlanInstall — по каждому контейнеру копии: ревизия и вердикт. prefs —
// порядок ревизий (nil — DefaultRevisionPreference). Пустой не-nil prefs —
// не проверена ни одна ревизия: Unknown, а не Mismatch (аудит AU-1 M1).
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
		// По имени и статусу, не по позиции (аудит AU-1 L2).
		var conf *BackupFile
		for i := range bc.Files {
			if bc.Files[i].Name == xrayConfFile {
				conf = &bc.Files[i]
				break
			}
		}
		if conf == nil || conf.Status != FileSaved {
			return unknown("в копии нет сохранённого server.json")
		}
		srv, err := parseXRayServer(conf.Data.Bytes())
		if err != nil {
			return unknown("server.json копии не разобран — транспорт и SNI неизвестны")
		}
		it.Transport, it.SNI = "tcp/reality", srv.serverName
	} else if bc.Subnet == "" {
		return unknown("в копии нет подсети")
	}
	if len(prefs) == 0 {
		return unknown("не проверена ни одна ревизия скриптов (список ревизий пуст)")
	}
	sawUnknown, why := false, ""
	for _, rev := range prefs {
		s := provision.InstallSupport(rev, bc.Version)
		switch {
		case s.State == provision.SupportUnknown:
			sawUnknown = true
			why += fmt.Sprintf("; %s: нет данных о семействе %q", rev, bc.Version)
			continue
		case s.State != provision.SupportYes && s.State != provision.SupportScriptOnly:
			why += fmt.Sprintf("; %s: %s", rev, s.State)
			continue
		case s.Container != bc.Name:
			// Расхождение таблицы контейнеров core и provision — «данных
			// нет», а не «не ставит» (аудит AU-1 L3).
			sawUnknown = true
			why += fmt.Sprintf("; %s: ставит %s, а не %s", rev, s.Container, bc.Name)
			continue
		}
		it.Revision, it.Compat, it.Source = rev, CompatMatch, s.Source
		var notes []string
		if why != "" {
			notes = append(notes, fmt.Sprintf("выбрана не самая свежая ревизия %s, отвергнуты%s; %s", rev, why, sourceRevisionNote))
		}
		if s.State == provision.SupportScriptOnly {
			it.NeedsMeasurement = true
			notes = append(notes, "совместимость подтвердится измерением после установки: "+s.Note)
		}
		it.Reason = strings.Join(notes, ". ")
		return it
	}
	if sawUnknown {
		return unknown("ни одна ревизия не подтверждает семейство %q%s", bc.Version, why)
	}
	it.Compat, it.Reason = CompatMismatch, fmt.Sprintf("ни одна закреплённая ревизия не ставит семейство %q%s", bc.Version, why)
	return it
}
