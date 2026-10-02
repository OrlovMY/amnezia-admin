package canary

import (
	"strings"

	"amnezia-admin/core"
)

// SelectWG — контейнеры семейства WG, на которых идёт канарейка (PR-W1):
// все найденные из таблицы core.WGFamilies или один — по флагу -container.
// Пустой выбор — why с причиной: «НЕ ПРОВЕРЕНО», не «пройдено».
func SelectWG(cs []core.Container, only string) (sel []core.Container, why string) {
	for _, c := range cs {
		c := c
		if _, err := core.WGFamilyOf(&c); err != nil {
			continue
		}
		if only != "" && c.Name != only {
			continue
		}
		sel = append(sel, c)
	}
	if len(sel) > 0 {
		return sel, ""
	}
	if only != "" {
		return nil, "НЕ ПРОВЕРЕНО: контейнера " + only + " семейства WG на сервере нет. " + ContainersFound(cs)
	}
	return nil, "НЕ ПРОВЕРЕНО: на сервере нет протокола семейства WG (amnezia-awg, amnezia-awg2, amnezia-wireguard). " + ContainersFound(cs)
}

// Table — итог «шаг × контейнер»: строки — шаги в порядке первого
// появления, столбцы — контейнеры; «—» — шаг на этом контейнере не шёл.
func Table(order []string, per map[string][]Result) string {
	type key struct{ id, name string }
	var steps []key
	seen := map[key]bool{}
	cell := map[string]map[key]string{}
	for _, c := range order {
		cell[c] = map[key]string{}
		for _, r := range per[c] {
			k := key{r.ID, r.Name}
			if !seen[k] {
				seen[k] = true
				steps = append(steps, k)
			}
			cell[c][k] = r.Status.String()
		}
	}
	var b strings.Builder
	b.WriteString("шаг")
	for _, c := range order {
		b.WriteString(" | " + c)
	}
	b.WriteString("\n")
	for _, k := range steps {
		b.WriteString(k.id + " " + k.name)
		for _, c := range order {
			v := cell[c][k]
			if v == "" {
				v = "—"
			}
			b.WriteString(" | " + v)
		}
		b.WriteString("\n")
	}
	return b.String()
}
