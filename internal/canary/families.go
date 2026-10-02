package canary

// PR-W1, раунд 2 (ревью QA, находка 4; SEC W-R2): обязательные семейства и
// общий каталог данных awg/awg2.

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"amnezia-admin/core"
)

// RequiredFamilies — семейства, без живой проверки которых выпуск нельзя
// (решение ядра, W1 раунд 2):
//   - amnezia-awg — основной протокол владельца, команды записи изменены W1;
//   - amnezia-awg2 — предмет W1 и W3, свои файл, утилита и интерфейс.
//
// amnezia-wireguard НЕ обязателен: его строка таблицы отличается от
// amnezia-awg только каталогом (/opt/amnezia/wireguard) — тот же wg0.conf,
// та же утилита wg и интерфейс wg0, те же построители команд; каталог
// проверяет закрытое выражение reCASDir и сверка с таблицей (W-R1). Живая
// проверка amnezia-awg исполняет ровно те же строки кода. Если он найден —
// проверяется; если нет — итог называет это строкой «не обязателен, не
// проверен», а не молчит.
var RequiredFamilies = []string{"amnezia-awg", "amnezia-awg2"}

// FamilyPlan — что делать с семействами: rows — шаги «семейство X: НЕ
// ПРОВЕРЕНО» для ненайденных обязательных; skipped — пропущенные флагом
// -skip-family; notes — строки про необязательные; err — флаг задан неверно.
func FamilyPlan(selected []string, skip []string) (rows []Result, skipped, notes []string, err error) {
	sel := map[string]bool{}
	for _, s := range selected {
		sel[s] = true
	}
	known := map[string]bool{}
	for _, f := range core.WGFamilies() {
		known[f.Container] = true
	}
	sk := map[string]bool{}
	for _, s := range skip {
		switch {
		case !known[s]:
			return nil, nil, nil, fmt.Errorf("-skip-family %s: такого семейства WG нет (есть: amnezia-awg, amnezia-awg2, amnezia-wireguard)", s)
		case sel[s]:
			return nil, nil, nil, fmt.Errorf("-skip-family %s: семейство проверяется в этом прогоне — пропуск не нужен", s)
		}
		sk[s] = true
	}
	for _, r := range RequiredFamilies {
		switch {
		case sel[r]:
		case sk[r]:
			skipped = append(skipped, r)
		default:
			rows = append(rows, Result{ID: "С", Name: "семейство " + r, Status: NotChecked,
				Detail: "нет на сервере (или не выбрано -container) — живой проверки нет; пропустить осознанно: -skip-family " + r})
		}
	}
	for _, f := range core.WGFamilies() {
		n := f.Container
		if sel[n] || sk[n] {
			continue
		}
		req := false
		for _, r := range RequiredFamilies {
			req = req || r == n
		}
		if !req {
			notes = append(notes, "семейство "+n+": не обязательно для выпуска, не проверено (нет на сервере или не выбрано)")
		}
	}
	return rows, skipped, notes, nil
}

// FinalSummary — итог с учётом пропущенных семейств. Пропуск обязательного
// семейства флагом — не ПРОЙДЕН, а ПРОЙДЕН ЧАСТИЧНО (AU-LOGIC M-1): первая
// строка итога — «ИТОГ: ПРОЙДЕН ЧАСТИЧНО — без живой проверки: …», статус
// PassPartial, код выхода канарейки — 3. Выпуск по такому итогу — только
// явным решением владельца (RELEASING 6а).
func FinalSummary(rs []Result, runErr error, skipped []string) (Status, string) {
	st, line := Summary(rs, runErr)
	if st == Pass && len(skipped) > 0 {
		counts := strings.TrimPrefix(line, "ИТОГ: ПРОЙДЕН ")
		return PassPartial, "ИТОГ: ПРОЙДЕН ЧАСТИЧНО — без живой проверки: " + strings.Join(skipped, ", ") +
			" (флаг -skip-family: эти семейства на живом сервере НЕ исполнялись) " + counts +
			"\nВыпуск по частичному итогу — только явным решением владельца (RELEASING 6а)."
	}
	return st, line
}

// mount — элемент .Mounts из docker inspect.
type mount struct {
	Source, Destination string
}

// MountsCheck — SEC W-R2: если /opt/amnezia/awg у amnezia-awg и
// amnezia-awg2 смонтирован на один каталог хоста, clientsTable у них общая
// и каждая запись переписывает чужую — СТОП до решения ядра. Отказ inspect
// или неразобранный ответ — НЕ ПРОВЕРЕНО (шлюз: запись не выполняется).
// Один из двух контейнеров — НЕ ПРИМЕНИМО.
func MountsCheck(remote func(string) (string, error), names []string) Result {
	r := Result{ID: "П4", Name: "каталог данных awg и awg2 не общий (docker inspect mounts)"}
	has := map[string]bool{}
	for _, n := range names {
		has[n] = true
	}
	if !has["amnezia-awg"] || !has["amnezia-awg2"] {
		r.Status, r.Detail = NotApplicable, "на сервере нет обоих контейнеров amnezia-awg и amnezia-awg2"
		return r
	}
	args := " inspect -f '{{.Name}} {{json .Mounts}}' amnezia-awg amnezia-awg2"
	out, err := remote("docker" + args)
	if err != nil && strings.Contains(strings.ToLower(out+err.Error()), "permission denied") {
		out, err = remote("sudo -n docker" + args)
	}
	if err != nil {
		r.Detail = "docker inspect не выполнился: " + oneLine(out) + " " + err.Error()
		return r
	}
	src := map[string]string{} // контейнер → каталог хоста для /opt/amnezia/awg
	got := 0
	for _, l := range strings.Split(strings.TrimSpace(out), "\n") {
		l = strings.TrimSpace(strings.TrimRight(l, "\r"))
		sp := strings.IndexByte(l, ' ')
		if sp < 0 {
			r.Detail = "ответ docker inspect не разобран: " + oneLine(l)
			return r
		}
		name := strings.TrimPrefix(l[:sp], "/")
		var ms []mount
		if err := json.Unmarshal([]byte(l[sp+1:]), &ms); err != nil {
			r.Detail = "ответ docker inspect не разобран: " + err.Error()
			return r
		}
		got++
		for _, m := range ms {
			d := strings.TrimRight(m.Destination, "/")
			if d == "/opt/amnezia/awg" || d == "/opt/amnezia" || d == "/opt" || d == "" {
				src[name] = m.Source
			}
		}
	}
	if got != 2 {
		r.Detail = fmt.Sprintf("docker inspect вернул %d контейнеров вместо 2", got)
		return r
	}
	a, b := src["amnezia-awg"], src["amnezia-awg2"]
	if a != "" && a == b {
		r.Status = Fail
		r.Detail = "СТОП: /opt/amnezia/awg обоих контейнеров смонтирован на один каталог хоста " + a + " — clientsTable общая; запись не выполняется до решения ядра"
		return r
	}
	var desc []string
	for _, n := range []string{"amnezia-awg", "amnezia-awg2"} {
		if s := src[n]; s != "" {
			desc = append(desc, n+" → "+s)
		}
	}
	sort.Strings(desc)
	r.Status = Pass
	if len(desc) == 0 {
		r.Detail = "монтирований /opt/amnezia/awg нет — данные внутри контейнеров"
	} else {
		r.Detail = "каталоги хоста разные: " + strings.Join(desc, "; ")
	}
	return r
}

// ExitCode — код выхода канарейки по итогу: 0 — ПРОЙДЕН; 3 — ПРОЙДЕН
// ЧАСТИЧНО (-skip-family, AU-LOGIC M-1); 1 — всё прочее.
func ExitCode(st Status) int {
	switch st {
	case Pass:
		return 0
	case PassPartial:
		return 3
	}
	return 1
}
