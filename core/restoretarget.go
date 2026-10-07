package core

// Проверка цели восстановления (задача владельца 07.10.2026): перед
// записью — сколько пользователей уже есть на новом сервере (служебный
// отдельно), сколько будет удалено, пересекаются ли они с клиентами копии.
// Есть пользователи кроме служебного или конфликты — запись только после
// отдельного явного подтверждения (RestoreOptions.TargetConfirmed).
//
// Служебный клиент:
//   - XRay — клиент установки, UUID из xray_uuid.key (устройство
//     администратора; см. readXRayInstallID). Ключ не прочитан или не UUID —
//     служебный НЕ опознан (ServiceUnknown) и все клиенты считаются
//     пользователями: незнание не превращается в «это админ».
//   - WG-семейство — признака служебного клиента у Amnezia нет (установка
//     сервера клиента не создаёт) — ServiceNone, считаются все.
//
// Третье состояние «не удалось узнать» (clientsTable не разобрана) — СТОП в
// planRestoreContainer до этой проверки, не «0 пользователей».

import (
	"fmt"
	"slices"
	"sort"
	"strings"
)

// ServiceState — опознан ли служебный клиент цели.
type ServiceState int

const (
	// ServiceNone — у протокола нет признака служебного клиента.
	ServiceNone ServiceState = iota
	// ServiceFound — признак прочитан (XRay: xray_uuid.key).
	ServiceFound
	// ServiceUnknown — признак должен быть, но не прочитан: все клиенты
	// считаются пользователями.
	ServiceUnknown
)

// ConflictKind — вид пересечения клиента цели с клиентом копии.
type ConflictKind int

const (
	// ConflictName — то же имя, разный ключ.
	ConflictName ConflictKind = iota + 1
	// ConflictKey — тот же ключ (clientId), другое имя.
	ConflictKey
	// ConflictAddress — тот же адрес (AllowedIPs) у разных клиентов.
	ConflictAddress
)

// RestoreConflict — пересечение ОДНОЙ пары клиентов (сервер, копия) со
// всеми её признаками (круг 3, живая проверка: счёт конфликтов — по парам
// клиентов, не по признакам). Без ключей: только имена и адреса.
type RestoreConflict struct {
	Kinds  []ConflictKind // по возрастанию, без повторов
	Target string         // имя клиента нового сервера
	Source string         // имя клиента копии
	Addrs  []string       // общие адреса (ConflictAddress)
}

// Has — есть ли у пары признак k.
func (c RestoreConflict) Has(k ConflictKind) bool {
	for _, x := range c.Kinds {
		if x == k {
			return true
		}
	}
	return false
}

func (c RestoreConflict) String() string {
	addr := ""
	if c.Has(ConflictAddress) {
		addr = strings.Join(c.Addrs, ", ")
	}
	switch {
	case c.Has(ConflictName) && addr != "":
		return fmt.Sprintf("«%s»: на сервере и в копии — разные клиенты (разные ключи), адрес тот же — %s", c.Target, addr)
	case c.Has(ConflictName):
		return fmt.Sprintf("«%s»: на сервере и в копии — разные клиенты (разные ключи)", c.Target)
	case c.Has(ConflictKey):
		return fmt.Sprintf("один и тот же ключ: на сервере — «%s», в копии — «%s»", c.Target, c.Source)
	case addr != "":
		return fmt.Sprintf("адрес %s: на сервере у «%s», в копии у «%s» (разные клиенты)", addr, c.Target, c.Source)
	}
	return "пересечение неизвестного вида"
}

// TargetUsers — клиенты нового сервера до записи.
type TargetUsers struct {
	// Users — пользователи (кроме служебного), по именам.
	Users   []string
	Service ServiceState
	// ServiceName — имя служебного клиента на сервере ("" — его нет в
	// списке или Service != ServiceFound).
	ServiceName string
	// Matches — тот же клиент (тот же ключ и имя) и в копии.
	Matches []string
}

type restoreClient struct {
	id, name string
	addrs    []string
}

func displayName(n string) string {
	if n == "" {
		return "(без имени)"
	}
	return n
}

// clientsOf — клиенты: объединение clientsTable и конфигурации — [Peer]
// у WG, clients из server.json у XRay (AU-LOGIC З1): клиент конфигурации
// без записи в таблице — тоже клиент («без имени»). Адреса — AllowedIPs
// (WG). server.json не разобран — ошибка: кто там, неизвестно.
func clientsOf(tbl []ClientEntry, conf []byte, wg bool) ([]restoreClient, error) {
	addrs := map[string][]string{}
	var order []string
	if !wg {
		srv, err := parseXRayServer(conf)
		if err != nil {
			return nil, err
		}
		for _, id := range srv.ids {
			if _, ok := addrs[id]; !ok {
				order = append(order, id)
				addrs[id] = nil
			}
		}
	}
	if wg {
		for _, p := range parseWgConf(string(conf)).peers {
			pk := p["PublicKey"]
			if pk == "" {
				continue
			}
			if _, ok := addrs[pk]; !ok {
				order = append(order, pk)
				addrs[pk] = []string{}
			}
			for _, a := range strings.Split(p["AllowedIPs"], ",") {
				if a = strings.TrimSpace(a); a != "" {
					addrs[pk] = append(addrs[pk], a)
				}
			}
		}
	}
	var out []restoreClient
	seen := map[string]bool{}
	for _, e := range tbl {
		seen[e.ClientID] = true
		out = append(out, restoreClient{id: e.ClientID, name: e.Name(), addrs: addrs[e.ClientID]})
	}
	for _, pk := range order {
		if !seen[pk] {
			out = append(out, restoreClient{id: pk, addrs: addrs[pk]})
		}
	}
	return out, nil
}

// compareTarget — пользователи цели и пересечения с копией. tgtSvc/srcSvc —
// id служебного клиента цели и копии ("" — нет или не опознан); служебные в
// пересечения не входят (у цели и копии они свои по определению).
func compareTarget(tgt, src []restoreClient, svc ServiceState, tgtSvc, srcSvc string) (TargetUsers, []RestoreConflict) {
	tu := TargetUsers{Service: svc}
	srcByID := map[string]restoreClient{}
	srcByName := map[string][]restoreClient{}
	srcByAddr := map[string][]restoreClient{}
	for _, c := range src {
		if srcSvc != "" && c.id == srcSvc {
			continue
		}
		srcByID[c.id] = c
		if c.name != "" {
			srcByName[c.name] = append(srcByName[c.name], c)
		}
		for _, a := range c.addrs {
			srcByAddr[a] = append(srcByAddr[a], c)
		}
	}
	var cs []RestoreConflict
	for _, t := range tgt {
		if tgtSvc != "" && t.id == tgtSvc {
			tu.ServiceName = XRayServiceName // одно имя везде, как в list
			continue
		}
		tu.Users = append(tu.Users, displayName(t.name))
		// пара (t, клиент копии) → одна запись со всеми признаками
		pairs := map[string]int{}
		add := func(s restoreClient, k ConflictKind, addr string) {
			i, ok := pairs[s.id]
			if !ok {
				i = len(cs)
				pairs[s.id] = i
				cs = append(cs, RestoreConflict{Target: displayName(t.name), Source: displayName(s.name)})
			}
			if !cs[i].Has(k) {
				cs[i].Kinds = append(cs[i].Kinds, k)
				sort.Slice(cs[i].Kinds, func(a, b int) bool { return cs[i].Kinds[a] < cs[i].Kinds[b] })
			}
			// адрес — один раз (QA Minor: повтор в AllowedIPs печатался
			// дважды); порядок — первого появления
			if addr != "" && !slices.Contains(cs[i].Addrs, addr) {
				cs[i].Addrs = append(cs[i].Addrs, addr)
			}
		}
		if s, ok := srcByID[t.id]; ok {
			if s.name == t.name {
				tu.Matches = append(tu.Matches, displayName(t.name))
			} else {
				add(s, ConflictKey, "")
			}
		}
		if t.name != "" {
			for _, s := range srcByName[t.name] {
				if s.id != t.id {
					add(s, ConflictName, "")
				}
			}
		}
		for _, a := range t.addrs {
			for _, s := range srcByAddr[a] {
				if s.id != t.id {
					add(s, ConflictAddress, a)
				}
			}
		}
	}
	sort.SliceStable(cs, func(i, j int) bool { return cs[i].Kinds[0] < cs[j].Kinds[0] })
	return tu, cs
}

// ReplacedNote — пометка удаляемого клиента, которого заменит одноимённый
// клиент копии (круг 3, живая проверка).
const ReplacedNote = " (будет заменён клиентом из копии с тем же именем)"

// removedOf — клиенты цели, которых нет в копии (по ключу); одноимённый
// клиент копии — пометка ReplacedNote; служебный XRay — XRayServiceName.
func removedOf(tgt, src []restoreClient, tgtSvc, srcSvc string) []string {
	keep := map[string]bool{}
	names := map[string]bool{}
	for _, e := range src {
		keep[e.id] = true
		if e.name != "" && (srcSvc == "" || e.id != srcSvc) {
			names[e.name] = true
		}
	}
	var out []string
	for _, e := range tgt {
		if keep[e.id] {
			continue
		}
		switch {
		case tgtSvc != "" && e.id == tgtSvc:
			out = append(out, XRayServiceName)
		case e.name != "" && names[e.name]:
			out = append(out, e.name+ReplacedNote)
		default:
			out = append(out, displayName(e.name))
		}
	}
	return out
}

// NeedsTargetConfirm — нужно ли отдельное подтверждение записи: на новом
// сервере есть пользователи кроме служебного или есть конфликты.
func (rp *RestorePlan) NeedsTargetConfirm() bool {
	if rp == nil {
		return false
	}
	for _, it := range rp.Items {
		if len(it.Target.Users) > 0 || len(it.Conflicts) > 0 {
			return true
		}
	}
	return false
}

// TargetUserCount — всего пользователей (кроме служебных) на новом сервере
// по всем контейнерам плана.
func (rp *RestorePlan) TargetUserCount() int {
	n := 0
	for _, it := range rp.Items {
		n += len(it.Target.Users)
	}
	return n
}

// TargetConflictCount — всего конфликтов с копией.
func (rp *RestorePlan) TargetConflictCount() int {
	n := 0
	for _, it := range rp.Items {
		n += len(it.Conflicts)
	}
	return n
}

// TargetWarnHead — заголовок предупреждения: число всегда видно.
func TargetWarnHead(rp *RestorePlan) string {
	s := fmt.Sprintf("ВНИМАНИЕ: на этом сервере уже есть пользователи — %d (не считая служебного). После замены останутся только клиенты копии.", rp.TargetUserCount())
	if nc := rp.TargetConflictCount(); nc > 0 {
		s += fmt.Sprintf(" Конфликтов с копией: %d.", nc)
	}
	return s
}

// TargetWarnLines — по контейнерам: число, служебный, имена (не больше max;
// max<=0 — все, число всегда видно), совпадения и конфликты.
func TargetWarnLines(rp *RestorePlan, max int) []string {
	var out []string
	for _, it := range rp.Items {
		tu := it.Target
		line := fmt.Sprintf("  %s: пользователей на сервере %d, будет удалено %d", it.Container, len(tu.Users), len(it.Removed))
		switch {
		case tu.Service == ServiceFound && tu.ServiceName != "":
			line += fmt.Sprintf("; служебный «%s» (ключ установки xray_uuid.key) не считается", tu.ServiceName)
		case tu.Service == ServiceUnknown:
			line += "; " + XRayServiceName + " не опознан (ключ установки xray_uuid.key не прочитан) — посчитаны все"
		}
		out = append(out, line)
		if len(tu.Users) > 0 {
			names := tu.Users
			more := 0
			if max > 0 && len(names) > max {
				names, more = names[:max], len(names)-max
			}
			l := "      " + strings.Join(names, ", ")
			if more > 0 {
				l += fmt.Sprintf(" … и ещё %d", more)
			}
			out = append(out, l)
		}
		if len(tu.Matches) > 0 {
			out = append(out, fmt.Sprintf("      совпадают с копией (тот же клиент): %d — %s", len(tu.Matches), strings.Join(tu.Matches, ", ")))
		}
		for _, c := range it.Conflicts {
			out = append(out, "      КОНФЛИКТ: "+c.String())
		}
	}
	return out
}
