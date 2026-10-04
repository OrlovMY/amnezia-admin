package canary

// Реестр шагов канарейки (AU-LOGIC Р-4 раунд 2, High-1; решение ядра):
// ЗАКРЫТЫЙ список — единственный источник ID и названий всех шагов. Класс
// дефекта «шаг написан, но не вызывается» (К9 @ 1f5c909: 70 ПРОЙДЕН без
// единой строки К9) закрывается так:
//   - название шага берётся только отсюда (step, stepName) — литералов
//     названий в коде нет (сторож TestNoStepNameLiterals);
//   - Audit сверяет строки прогона с реестром: шаг, ожидаемый на этом
//     контейнере, без строки — «шаг не исполнялся», НЕ ПРОЙДЕН (пропуск
//     исполнения — дефект программы, а не «не проверено»); строка с ID вне
//     реестра — тоже НЕ ПРОЙДЕН.

import (
	"fmt"
	"sort"
	"strings"
)

// Scope — где шаг ожидается.
type Scope int

const (
	// ScopeWG — на каждом проверяемом контейнере семейства WG, обязательно.
	ScopeWG Scope = iota
	// ScopeWGOptional — на контейнере WG по условию (П3 — сбой init, У2 —
	// создан временный пользователь, П0-итог — режим -server-ip). Не
	// ожидается, но допустим.
	ScopeWGOptional
	// ScopeK8 — К8: на amnezia-awg2 — К8.1–К8.8, на прочих — одна строка К8.
	ScopeK8
	// ScopeK9 — К9 на amnezia-xray и на каждом проверяемом контейнере WG:
	// К9.0–К9.2, или одна строка К9 (контейнера нет / прогон WG не завершён).
	ScopeK9
	// ScopeRun — один раз на прогон (П4) — обязателен.
	ScopeRun
	// ScopeRunOptional — один раз на прогон по условию (С, П0-свежесть,
	// П0-сервер).
	ScopeRunOptional
)

// StepDef — строка реестра.
type StepDef struct {
	ID, Name string
	Scope    Scope
}

// Steps — реестр. Порядок — порядок вывода.
var Steps = []StepDef{
	{"П4", "каталог данных awg и awg2 не общий (docker inspect mounts)", ScopeRun},
	{"П0-свежесть", fmt.Sprintf("контейнеры Amnezia поставлены не раньше %d ч назад", int(MaxFreshAge.Hours())), ScopeRunOptional},
	{"П0-сервер", fmt.Sprintf("клиентов на сервере до проверки не больше %d", MaxExisting), ScopeRunOptional},
	{"С", "обязательное семейство WG", ScopeRunOptional},
	{"П3", "контейнер семейства WG", ScopeWGOptional},
	{"П2", "сборка -new: ревизия и текст команды записи", ScopeWG},
	{"П0", "на сервере нет клиентов (или существующие сняты до первой записи)", ScopeWG},
	{"П1", "следов прошлого прогона нет", ScopeWG},
	{"К2.1", "/run/lock — каталог root 1777", ScopeWG},
	{"К2.2", "busybox в контейнере ≥ 1.30", ScopeWG},
	{"К2.3", "синтаксис timeout в контейнере", ScopeWG},
	{"К2.4", "никто не держит замок /run/lock до прогона", ScopeWG},
	{"К2.5", "flock и timeout на хосте", ScopeWG},
	{"К2.6", "утилиты в контейнере", ScopeWG},
	{"К2.9", "запуск docker exec < 10 с (запас casOuterMargin)", ScopeWG},
	{"К2.10", "запуск sudo + docker exec < 10 с (sudo-пользователь)", ScopeWG},
	{"К2.7", "sysctl fs.protected_regular (сведение)", ScopeWG},
	{"К2.8", "docker без sudo (сведение)", ScopeWG},
	{"К3", "обычная работа новой версии", ScopeWG},
	{"PR4.4", "права 0600 после записи", ScopeWG},
	{"PR4.1", "откат через подмену wg-quick", ScopeWG},
	{"PR4.2", "sudo в обоих порядках", ScopeWG},
	{"К4", "гонка: новая версия без потерь, прежняя запись без замка — с потерей", ScopeWG},
	{"К5", "обрыв: замок не зависает, файлы целиком", ScopeWG},
	{"К6", "приложение Amnezia: «изменён другим»", ScopeWG},
	{"К7", "v0.2.0 после всего работает", ScopeWG},
	{"К8", "AWG2/AWG3", ScopeK8},
	{"К8.1", "формат awg0.conf", ScopeK8},
	{"К8.2", "добавление: ключ в awg show, параметры [Interface] не тронуты", ScopeK8},
	{"К8.3", "конфиг импортируется на телефон, связь есть", ScopeK8},
	{"К8.4", "выключить — связи нет, включить — есть", ScopeK8},
	{"К8.5", "перевыпуск: старый не подключается, новый подключается", ScopeK8},
	{"К8.6", "удаление: ключа нет в awg show", ScopeK8},
	{"К8.7", "второе устройство на AWG2 не теряет связь", ScopeK8},
	{"К8.8", "формат awg show dump сходится с разбором parsePeerStats", ScopeK8},
	{"У", "уборка canary-*", ScopeWG},
	{"У2", "временный пользователь " + TempUser + " удалён", ScopeWGOptional},
	{"П0-итог", "существующие клиенты не изменились", ScopeWGOptional},
	{"К9", "запись с ключами под замком", ScopeK9},
	{"К9.0", "файлы прочитаны", ScopeK9},
	{"К9.1", "запись с ключами (те же байты): файлы заменены (новый inode), права 0600, без временных файлов", ScopeK9},
	{"К9.2", "устаревшая сумма ключа — «изменился», ничего не записано", ScopeK9},
}

var stepIndex = func() map[string]StepDef {
	m := map[string]StepDef{}
	for _, s := range Steps {
		if _, dup := m[s.ID]; dup {
			panic("реестр шагов канарейки: повтор " + s.ID)
		}
		m[s.ID] = s
	}
	return m
}()

// stepName — название шага из реестра; ID вне реестра — паника: это
// ошибка программы, а не сервера (сторож TestRegistryCoversCode).
func stepName(id string) string {
	s, ok := stepIndex[id]
	if !ok {
		panic("шаг " + id + " вне реестра канарейки")
	}
	return s.Name
}

// step — строка шага с названием из реестра (статус — НЕ ПРОВЕРЕНО).
func step(id string) Result { return Result{ID: id, Name: stepName(id)} }

// stepR — строка шага с исходом.
func stepR(id string, st Status, detail string) Result {
	r := step(id)
	r.Status, r.Detail = st, detail
	return r
}

// StepName — название шага из реестра (для программы канарейки).
func StepName(id string) string { return stepName(id) }

// InRegistry — ID есть в реестре.
func InRegistry(id string) bool { _, ok := stepIndex[id]; return ok }

// group — ожидание: хотя бы один из вариантов присутствует целиком.
type group struct{ alts [][]string }

func idsOf(scope Scope) []string {
	var out []string
	for _, s := range Steps {
		if s.Scope == scope {
			out = append(out, s.ID)
		}
	}
	return out
}

// ExpectedWG — ожидаемые шаги контейнера WG, прогон которого завершился без
// остановки: все ScopeWG и К8 (одна строка или К8.1–К8.8).
func expectedWG() []group {
	var gs []group
	for _, id := range idsOf(ScopeWG) {
		gs = append(gs, group{[][]string{{id}}})
	}
	k8 := idsOf(ScopeK8)
	gs = append(gs, group{[][]string{{"К8"}, k8[1:]}})
	return gs
}

func expectedK9() []group {
	k9 := idsOf(ScopeK9)
	return []group{{[][]string{{"К9"}, k9[1:]}}}
}

// Audit — строки-дефекты прогона против реестра. rows — строки одного
// контейнера (или прогона); complete — прогон этого контейнера дошёл до
// конца (иначе отсутствие шагов — следствие остановки, и о нём уже сказано);
// kind — "wg", "k9" или "run". ID вне реестра — НЕ ПРОЙДЕН всегда.
func Audit(where string, rows []Result, complete bool, kind string) []Result {
	var out []Result
	have := map[string]bool{}
	for _, r := range rows {
		have[r.ID] = true
		if !InRegistry(r.ID) {
			out = append(out, Result{ID: r.ID, Name: "шаг вне реестра", Status: Fail,
				Detail: where + ": строка с ID «" + r.ID + "» вне реестра шагов канарейки — дефект программы"})
		}
	}
	var gs []group
	switch kind {
	case "wg":
		gs = expectedWG()
	case "k9":
		gs = expectedK9()
	case "run":
		for _, id := range idsOf(ScopeRun) {
			gs = append(gs, group{[][]string{{id}}})
		}
	}
	if !complete {
		return out
	}
	for _, g := range gs {
		ok := false
		for _, alt := range g.alts {
			all := true
			for _, id := range alt {
				all = all && have[id]
			}
			ok = ok || all
		}
		if !ok {
			var miss []string
			for _, id := range g.alts[len(g.alts)-1] {
				if !have[id] {
					miss = append(miss, id)
				}
			}
			sort.Strings(miss)
			id := g.alts[len(g.alts)-1][0]
			out = append(out, Result{ID: id, Name: stepName(id), Status: Fail,
				Detail: where + ": шаг не исполнялся (" + strings.Join(miss, ", ") + ") — дефект программы канарейки, а не сервера"})
		}
	}
	return out
}
