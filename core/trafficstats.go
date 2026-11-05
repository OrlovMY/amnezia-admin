package core

// Чтение и агрегация статистики трафика, накопленной сборщиком на сервере
// (формат и ротация — trafficstats_script.go).
//
// ТРИ СОСТОЯНИЯ У КАЖДОЙ ЦИФРЫ (CLAUDE.md, «Незнание не выдаётся за
// знание»; история ложного нуля трафика 25.09). Цифра за период — это
// TrafficCell, и прочитать из неё байты можно только через Measured(),
// то есть только вместе с ответом «а измерено ли»:
//
//	TrafficMeasured     — за период есть хотя бы один учтённый интервал
//	                      этого клиента; ноль здесь — настоящий ноль;
//	TrafficNoData       — сборщик есть (или данные есть), но за период по
//	                      этому клиенту не учтено ни одного интервала:
//	                      снимков не было (сервер выключен, сборщик ещё не
//	                      работал) или клиента не было в снимках;
//	TrafficNotInstalled — сборщик не установлен и данных нет вовсе.
//
// Нулевое значение — TrafficUnknown: незаполненная ячейка — незнание, а не
// ноль и не «нет данных».

import (
	"errors"
	"fmt"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// TrafficState — исход одной цифры статистики.
type TrafficState int

const (
	// TrafficUnknown — ничего не известно (нулевое значение: забытое поле
	// не превращается ни в ноль, ни в «нет данных»).
	TrafficUnknown TrafficState = iota
	// TrafficNotInstalled — сборщик на сервере не установлен, данных нет.
	TrafficNotInstalled
	// TrafficNoData — за этот период по этому клиенту данных нет.
	TrafficNoData
	// TrafficMeasured — измерено.
	TrafficMeasured
	// TrafficPartial — измерено НЕ полностью (аудит AU-1, С3): в периоде
	// есть интервал, в котором между снимками была дыра больше
	// statsGapSec и при этом перезапуск — трафик от прошлого снимка до
	// перезапуска потерян. Цифра — нижняя граница, а не измерение.
	TrafficPartial
)

// statsGapSec — дыра между снимками, после которой потеря при
// перезапуске уже не мелочь: два интервала таймера и запас точности.
// То же число — в awkAgg (TestStatsGapSameInAwk).
const statsGapSec = 660

// TrafficCell — цифры одного клиента за период.
type TrafficCell struct {
	State  TrafficState
	rx, tx int64
	// LastHandshake — последнее рукопожатие в учтённых интервалах периода;
	// нулевое при Measured — «не подключался за период».
	LastHandshake time.Time
}

// Measured — принято и отправлено (со стороны сервера: rx — от клиента,
// tx — клиенту) и true, только если цифры измерены.
func (c TrafficCell) Measured() (rx, tx int64, ok bool) {
	if c.State != TrafficMeasured {
		return 0, 0, false
	}
	return c.rx, c.tx, true
}

// LowerBound — цифры частично потерянного периода («не меньше»).
func (c TrafficCell) LowerBound() (rx, tx int64, ok bool) {
	if c.State != TrafficPartial {
		return 0, 0, false
	}
	return c.rx, c.tx, true
}

// TrafficKey — клиент в данных сборщика: контейнер и публичный ключ.
type TrafficKey struct {
	Container, PubKey string
}

// DayRange — период в сутках UTC от 1970-01-01, обе границы включительно.
type DayRange struct {
	From, To int64
}

// AllTime — период «за всё время».
var AllTime = DayRange{math.MinInt64, math.MaxInt64}

func (r DayRange) has(d int64) bool { return d >= r.From && d <= r.To }

// DayOf — сутки UTC момента t.
func DayOf(t time.Time) int64 { return floorDiv(t.Unix(), 86400) }

// DayStart — начало суток d (UTC).
func DayStart(d int64) time.Time { return time.Unix(d*86400, 0).UTC() }

func floorDiv(a, b int64) int64 {
	q := a / b
	if (a%b != 0) && ((a < 0) != (b < 0)) {
		q--
	}
	return q
}

type trafficAgg struct {
	rx, tx, hs int64
	n, partial int
}

// TrafficLog — разобранные данные сборщика.
type TrafficLog struct {
	days map[int64]map[TrafficKey]*trafficAgg
	cov  map[int64]map[string]int

	// HaveDaily, HaveRaw — файлы daily.log и snapshots.log существуют.
	HaveDaily, HaveRaw bool
	// Corrupt — сколько записей/блоков пропущено как повреждённые. Не ноль
	// — цифры могут быть неполными (пропуск снимка обычно ничего не теряет:
	// следующий целый снимок даёт ту же разницу; теряется при перезапуске
	// внутри пропуска).
	Corrupt int
	// Torn — последний блок журнала не дописан (запись идёт сейчас или
	// оборвалась); он не учтён.
	Torn bool
	// RawStale — журнал снимков старше суточных итогов (окно между двумя
	// mv ротации): он уже учтён в daily.log и пропущен.
	RawStale bool
	// Failed — снимков, в которых снять счётчики не удалось (строки F).
	Failed int
	// LastSnapshot — время последнего целого снимка в журнале.
	LastSnapshot time.Time
	// Heuristic — интервалов, учтённых без признака запуска (снимки
	// старого формата или сервер не отдал boot_id/StartedAt): перезапуск,
	// после которого счётчик перерос прежний, в них мог остаться незамеченным.
	Heuristic int
}

var (
	reStatsNum  = regexp.MustCompile(`^[0-9]{1,15}$`)
	reStatsCtr  = regexp.MustCompile(`^[a-z0-9-]+$`)
	reStatsPub  = regexp.MustCompile(`^[A-Za-z0-9+/=]+$`)
	reStatsSig  = regexp.MustCompile(`^[0-9A-Za-z:.+-]+$`)
	errStatsBad = errors.New("bad")
)

func statsNum(s string) (int64, error) {
	if !reStatsNum.MatchString(s) {
		return 0, errStatsBad
	}
	return strconv.ParseInt(s, 10, 64)
}

func (l *TrafficLog) add(day int64, k TrafficKey, rx, tx, hs int64, n, partial int) {
	if l.days[day] == nil {
		l.days[day] = map[TrafficKey]*trafficAgg{}
	}
	a := l.days[day][k]
	if a == nil {
		a = &trafficAgg{}
		l.days[day][k] = a
	}
	a.rx += rx
	a.tx += tx
	a.n += n
	a.partial += partial
	if hs > a.hs {
		a.hs = hs
	}
}

func (l *TrafficLog) addCov(day int64, c string, n int) {
	if l.cov[day] == nil {
		l.cov[day] = map[string]int{}
	}
	l.cov[day][c] += n
}

// ParseTrafficLog разбирает содержимое daily.log и snapshots.log.
// haveDaily/haveRaw — существуют ли файлы (пустой файл ≠ отсутствующий).
func ParseTrafficLog(daily string, haveDaily bool, raw string, haveRaw bool) *TrafficLog {
	l := &TrafficLog{
		days:      map[int64]map[TrafficKey]*trafficAgg{},
		cov:       map[int64]map[string]int{},
		HaveDaily: haveDaily,
		HaveRaw:   haveRaw,
	}
	maxGen := int64(0)
	for _, line := range strings.Split(daily, "\n") {
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		g, ok := l.parseDaily(f)
		if !ok {
			l.Corrupt++
			continue
		}
		if g > maxGen {
			maxGen = g
		}
	}
	l.parseRaw(raw, maxGen)
	return l
}

func (l *TrafficLog) parseDaily(f []string) (int64, bool) {
	var nums []int64
	switch {
	case f[0] == "D" && (len(f) == 9 || len(f) == 10) && reStatsCtr.MatchString(f[3]) && reStatsPub.MatchString(f[4]):
		// Десятое поле (раунд 3, С3) — частично потерянных интервалов.
		for _, s := range append([]string{f[1], f[2]}, f[5:]...) {
			v, err := statsNum(s)
			if err != nil {
				return 0, false
			}
			nums = append(nums, v)
		}
		partial := 0
		if len(nums) == 7 {
			partial = int(nums[6])
		}
		l.add(nums[1], TrafficKey{f[3], f[4]}, nums[2], nums[3], nums[4], int(nums[5]), partial)
		return nums[0], true
	case f[0] == "N" && (len(f) == 5 || len(f) == 6) && reStatsCtr.MatchString(f[3]):
		// Шестое поле (раунд 2, С2) — сколько интервалов учтено без
		// признаков перезапуска; в старых записях его нет.
		for _, s := range append([]string{f[1], f[2]}, f[4:]...) {
			v, err := statsNum(s)
			if err != nil {
				return 0, false
			}
			nums = append(nums, v)
		}
		l.addCov(nums[1], f[3], int(nums[2]))
		if len(nums) == 4 {
			l.Heuristic += int(nums[3])
		}
		return nums[0], true
	}
	return 0, false
}

type statsPeer struct {
	pub        string
	rx, tx, hs int64
}

// trafficState — правило разницы между снимками. То же правило — в awkAgg
// (ротация на сервере); равенство проверяет TestAwkMatchesGo.
type trafficState struct {
	prev map[TrafficKey][2]int64
	seen map[string]bool
	// sig — признак запуска (boot_id и StartedAt контейнера) последнего
	// целого снимка контейнера; "" — признака не было (старый формат).
	sig map[string]string
	// last — время последнего целого снимка контейнера (для дыр, С3).
	last map[string]int64
}

// apply — правило разницы. Раунд 2 (С2): если у обоих снимков есть
// признак запуска и он сменился — это перезапуск, и счётчик считается с
// нуля НЕЗАВИСИМО от величин (прежняя эвристика «уменьшился» не видит
// перезапуска, после которого счётчик перерос прежний). Без признака —
// прежняя эвристика, а интервал считается в Heuristic (пометка в выводе).
//
// Аудит AU-1, С3: перезапуск в интервале длиннее statsGapSec — трафик от
// прошлого снимка до перезапуска потерян, интервал помечается partial.
//
// Ревью 2, Н6 — известное ограничение: peer удалён и возвращён (toggle)
// внутри одной жизни контейнера, StartedAt тот же, и за интервал счётчик
// перерос прежнее накопленное значение — сброс не виден (интервал
// «известный», в Heuristic не попадает). Практически невозможно: прежнее
// значение накоплено за всю жизнь контейнера.
func (st *trafficState) apply(l *TrafficLog, ts int64, c, bsig string, peers []statsPeer) {
	day := floorDiv(ts, 86400)
	psig, had := st.sig[c]
	known := bsig != "" && had && psig != ""
	restarted := known && psig != bsig
	lastTS, hadLast := st.last[c]
	gap := hadLast && ts-lastTS > statsGapSec
	heur := 0
	cur := map[TrafficKey]bool{}
	for _, p := range peers {
		k := TrafficKey{c, p.pub}
		var dx, dt int64
		has := false
		part := 0
		if pv, ok := st.prev[k]; ok {
			if restarted || p.rx < pv[0] || p.tx < pv[1] {
				dx, dt = p.rx, p.tx // сброс счётчика: перезапуск
				if gap {
					part = 1
				}
			} else {
				dx, dt = p.rx-pv[0], p.tx-pv[1]
			}
			has = true
			if !known {
				heur++
			}
		} else if st.seen[c] {
			dx, dt, has = p.rx, p.tx, true // peer добавлен после прошлого снимка
		}
		if has {
			l.add(day, k, dx, dt, p.hs, 1, part)
		}
		st.prev[k] = [2]int64{p.rx, p.tx}
		cur[k] = true
	}
	for k := range st.prev {
		if k.Container == c && !cur[k] {
			delete(st.prev, k)
		}
	}
	if st.seen[c] {
		l.addCov(day, c, 1)
	}
	l.Heuristic += heur
	st.seen[c] = true
	st.sig[c] = bsig
	st.last[c] = ts
}

func (l *TrafficLog) parseRaw(raw string, maxGen int64) {
	lines := strings.Split(raw, "\n")
	first := true
	st := &trafficState{prev: map[TrafficKey][2]int64{}, seen: map[string]bool{}, sig: map[string]string{}, last: map[string]int64{}}
	var (
		inb   bool
		bts   int64
		bc    string
		bn    int64
		bsig  string
		peers []statsPeer
	)
	// open — блок начат и не закрыт: если за ним идёт что-то ещё, это
	// повреждение, если конец файла — недописанный хвост.
	open := false
	broken := func() {
		if open {
			l.Corrupt++
		}
		open, inb = false, false
	}
	for _, line := range lines {
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		if first {
			first = false
			if f[0] == "H" {
				g, err := int64(0), error(nil)
				if len(f) == 3 && f[1] == "v1" {
					g, err = statsNum(f[2])
				} else {
					err = errStatsBad
				}
				if err != nil {
					l.Corrupt++
				} else if g < maxGen {
					l.RawStale = true
					return
				}
				continue
			}
			l.Corrupt++ // заголовка нет
		}
		switch f[0] {
		case "S":
			broken()
			if (len(f) == 4 || len(f) == 6 && reStatsSig.MatchString(f[4]) && reStatsSig.MatchString(f[5])) && reStatsCtr.MatchString(f[2]) {
				t, e1 := statsNum(f[1])
				n, e2 := statsNum(f[3])
				if e1 == nil && e2 == nil {
					inb, open, bts, bc, bn, peers, bsig = true, true, t, f[2], n, nil, ""
					if len(f) == 6 && f[4] != "-" && f[5] != "-" {
						bsig = f[4] + " " + f[5]
					}
					continue
				}
			}
			l.Corrupt++
		case "P":
			if inb && len(f) == 5 && reStatsPub.MatchString(f[1]) {
				rx, e1 := statsNum(f[2])
				tx, e2 := statsNum(f[3])
				hs, e3 := statsNum(f[4])
				if e1 == nil && e2 == nil && e3 == nil {
					peers = append(peers, statsPeer{f[1], rx, tx, hs})
					continue
				}
			}
			// Повреждённый блок считается один раз — когда он кончится
			// (E или следующая запись); не кончился до конца файла —
			// недописанный хвост, а не повреждение.
			if !open {
				l.Corrupt++
			}
			inb = false
		case "E":
			if inb && len(f) == 4 && f[2] == bc && reStatsNum.MatchString(f[1]) && reStatsNum.MatchString(f[3]) {
				t, _ := statsNum(f[1])
				if n, _ := statsNum(f[3]); t == bts && n == bn && int64(len(peers)) == bn {
					st.apply(l, bts, bc, bsig, peers)
					if t := time.Unix(bts, 0); t.After(l.LastSnapshot) {
						l.LastSnapshot = t
					}
					open, inb = false, false
					continue
				}
			}
			if !open {
				l.Corrupt++
			}
			broken()
		case "F":
			broken()
			if len(f) == 4 {
				l.Failed++
			} else {
				l.Corrupt++
			}
		default:
			if !open {
				l.Corrupt++
			}
			broken()
		}
	}
	if open {
		l.Torn = true
	}
}

// Keys — все клиенты, встреченные в учтённых интервалах, по порядку.
func (l *TrafficLog) Keys() []TrafficKey {
	set := map[TrafficKey]bool{}
	for _, m := range l.days {
		for k := range m {
			set[k] = true
		}
	}
	var out []TrafficKey
	for k := range set {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Container != out[j].Container {
			return out[i].Container < out[j].Container
		}
		return out[i].PubKey < out[j].PubKey
	})
	return out
}

// CoveredDays — сутки, в которых учтён хотя бы один снимок контейнера c
// ("" — любого), по возрастанию.
func (l *TrafficLog) CoveredDays(c string) []int64 {
	var out []int64
	for d, m := range l.cov {
		for ctr, n := range m {
			if n > 0 && (c == "" || ctr == c) {
				out = append(out, d)
				break
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// Containers — контейнеры, у которых есть учтённые снимки, по имени.
func (l *TrafficLog) Containers() []string {
	set := map[string]bool{}
	for _, m := range l.cov {
		for c, n := range m {
			if n > 0 {
				set[c] = true
			}
		}
	}
	var out []string
	for c := range set {
		out = append(out, c)
	}
	sort.Strings(out)
	return out
}

// Partial — сколько учтённых интервалов частично потеряно (С3).
func (l *TrafficLog) Partial() int {
	n := 0
	for _, m := range l.days {
		for _, a := range m {
			n += a.partial
		}
	}
	return n
}

// Empty — данных нет вовсе: ни одного файла.
func (l *TrafficLog) Empty() bool { return l == nil || (!l.HaveDaily && !l.HaveRaw) }

// Cell — цифры клиента k за период r. collector — установлен ли сборщик:
// нужен, только чтобы различить «не установлен» и «нет данных», когда
// файлов нет вовсе.
func (l *TrafficLog) Cell(k TrafficKey, r DayRange, collector CollectorState) TrafficCell {
	if l.Empty() {
		switch collector {
		case CollectorNotInstalled:
			return TrafficCell{State: TrafficNotInstalled}
		case CollectorUnknown:
			return TrafficCell{State: TrafficUnknown}
		}
		return TrafficCell{State: TrafficNoData}
	}
	var c TrafficCell
	n, partial := 0, 0
	for d, m := range l.days {
		if !r.has(d) {
			continue
		}
		if a := m[k]; a != nil && a.n > 0 {
			c.rx += a.rx
			c.tx += a.tx
			n += a.n
			partial += a.partial
			if a.hs > 0 {
				if t := time.Unix(a.hs, 0); t.After(c.LastHandshake) {
					c.LastHandshake = t
				}
			}
		}
	}
	if n == 0 {
		return TrafficCell{State: TrafficNoData}
	}
	c.State = TrafficMeasured
	if partial > 0 {
		c.State = TrafficPartial
	}
	return c
}

// ---------- состояние сборщика на сервере ----------

// CollectorState — установлен ли сборщик.
type CollectorState int

const (
	// CollectorUnknown — узнать не удалось (нулевое значение).
	CollectorUnknown CollectorState = iota
	// CollectorNotInstalled — ни одного из трёх файлов нет.
	CollectorNotInstalled
	// CollectorInstalled — все три файла наши (суммы совпали), таймер активен.
	CollectorInstalled
	// CollectorPartial — что-то есть, но не всё или не той версии, или
	// таймер не активен; Detail — что именно.
	CollectorPartial
)

// CollectorStatus — ответ `stats status`.
type CollectorStatus struct {
	State  CollectorState
	Detail []string
	// Full — сборщик остановился по пределу объёма (метка FULL).
	Full string
	Err  error

	// Collect — идёт ли сбор НА САМОМ ДЕЛЕ (аудит AU-1, С2): не по
	// «таймер активен», а по исходу службы и свежести последнего снимка.
	Collect CollectState
	// CollectWhy — почему «не работает» или «неизвестно».
	CollectWhy string
	// LastSnapshot — время последнего целого снимка (по серверу); нулевое —
	// снимков нет. SnapshotAge — его возраст по часам сервера.
	LastSnapshot time.Time
	SnapshotAge  time.Duration
}

// CollectState — идёт ли сбор.
type CollectState int

const (
	// CollectUnknown — состояние службы или журнала прочитать не удалось.
	CollectUnknown CollectState = iota
	// CollectStopped — не работает; причина в CollectWhy.
	CollectStopped
	// CollectWorking — служба завершилась успешно И последний снимок не
	// старше statsFreshSec.
	CollectWorking
)

// statsFreshSec — снимок свежий, если не старше двух интервалов таймера.
const statsFreshSec = 600

// posixCksum — сумма в формате утилиты cksum (POSIX): CRC-32 с многочленом
// 0x04C11DB7 без отражения по данным и длине, с инверсией.
func posixCksum(data []byte) uint32 {
	var crc uint32
	upd := func(b byte) {
		crc ^= uint32(b) << 24
		for i := 0; i < 8; i++ {
			if crc&0x80000000 != 0 {
				crc = crc<<1 ^ 0x04C11DB7
			} else {
				crc <<= 1
			}
		}
	}
	for _, b := range data {
		upd(b)
	}
	for n := len(data); n > 0; n >>= 8 {
		upd(byte(n))
	}
	return ^crc
}

// parseCollectorStatus — разбор вывода statsStatusScript.
func parseCollectorStatus(out string) CollectorStatus {
	want := map[string]StatsInstallFile{}
	for _, f := range StatsInstallFiles() {
		want[f.Path] = f
	}
	st := CollectorStatus{}
	seen, present, ours := 0, 0, 0
	active := ""
	ended := false
	unit := map[string]string{} // systemctl show: Result=, ActiveState=, SubState=
	var now, lastE int64
	haveNow, haveTail, haveE, inTail := false, false, false, false
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		switch f[0] {
		case "AA_F":
			if len(f) < 3 {
				continue
			}
			w, ok := want[f[1]]
			if !ok {
				continue
			}
			seen++
			if f[2] == "-" {
				st.Detail = append(st.Detail, "нет файла "+f[1])
				continue
			}
			present++
			exp := fmt.Sprintf("%d", posixCksum([]byte(w.Content)))
			if len(f) >= 4 && f[2] == exp && f[3] == strconv.Itoa(len(w.Content)) {
				ours++
			} else {
				st.Detail = append(st.Detail, "файл "+f[1]+" отличается от версии этой программы")
			}
		case "AA_ACTIVE":
			if len(f) >= 2 {
				active = f[1]
			}
		case "AA_FULL":
			st.Full = strings.Join(f[1:], " ")
			if st.Full == "" {
				st.Full = "?"
			}
		case "AA_STATUS_END":
			ended = true
		case "AA_NOW":
			if len(f) == 2 {
				if v, err := statsNum(f[1]); err == nil {
					now, haveNow = v, true
				}
			}
		case "AA_TAIL_BEGIN":
			inTail, haveTail = true, true
			continue
		case "AA_TAIL_END":
			inTail = false
			continue
		}
		if inTail {
			// Последний целый снимок — последняя строка E хвоста журнала.
			if f[0] == "E" && len(f) == 4 {
				if v, err := statsNum(f[1]); err == nil {
					lastE, haveE = v, true
				}
			}
			continue
		}
		if k, v, ok := strings.Cut(line, "="); ok && len(f) == 1 {
			unit[k] = v
		}
	}
	switch {
	case !ended || seen != len(want):
		st.State = CollectorUnknown
		st.Detail = []string{"ответ сервера не разобран"}
	case present == 0:
		st.State = CollectorNotInstalled
		st.Detail = nil
	case ours == len(want) && active == "active":
		st.State = CollectorInstalled
	default:
		if active != "active" {
			a := active
			if a == "" {
				a = "нет ответа"
			}
			st.Detail = append(st.Detail, "таймер не активен ("+a+")")
		}
		st.State = CollectorPartial
	}
	st.Collect, st.CollectWhy = CollectUnknown, ""
	if haveE {
		st.LastSnapshot = time.Unix(lastE, 0)
		if haveNow {
			st.SnapshotAge = time.Duration(now-lastE) * time.Second
		}
	}
	res, haveRes := unit["Result"]
	switch {
	case st.State == CollectorUnknown:
		st.CollectWhy = "ответ сервера не разобран"
	case st.State == CollectorNotInstalled:
		st.Collect, st.CollectWhy = CollectStopped, "сборщик не установлен"
	case st.Full != "":
		st.Collect, st.CollectWhy = CollectStopped, "достигнут предел объёма"
	case !haveRes || !haveNow:
		st.CollectWhy = "состояние службы прочитать не удалось"
	case res != "success":
		st.Collect, st.CollectWhy = CollectStopped, "последний запуск сборщика завершился с ошибкой (Result="+res+")"
	case !haveTail:
		st.Collect, st.CollectWhy = CollectStopped, "снимков ещё нет"
	case !haveE:
		st.Collect, st.CollectWhy = CollectStopped, "в последних записях журнала нет ни одного целого снимка"
	case now-lastE > statsFreshSec:
		why := fmt.Sprintf("последний снимок %d мин назад", (now-lastE)/60)
		if unit["ActiveState"] == "activating" {
			why += "; служба выполняется сейчас — возможно, зависла"
		}
		st.Collect, st.CollectWhy = CollectStopped, why
	default:
		st.Collect = CollectWorking
	}
	return st
}

// statsRun — команда от root: напрямую или через sudo -n.
func (s *Session) statsRun(script string) (string, error) {
	cmd := "sh -s"
	if s.Creds != nil && s.Creds.User != "root" {
		cmd = "sudo -n sh -s"
	}
	return s.run(cmd, []byte(script))
}

// StatsStatus — установлен ли сборщик (только чтение).
func (s *Session) StatsStatus() CollectorStatus {
	out, err := s.statsRun(statsStatusScript())
	if err != nil {
		return CollectorStatus{State: CollectorUnknown, Err: err}
	}
	return parseCollectorStatus(out)
}

// StatsInstall ставит сборщик (идемпотентно). Вызывать только после
// подтверждения человека: это запись на сервер.
func (s *Session) StatsInstall() error {
	out, err := s.statsRun(statsInstallScript())
	// Аудит AU-1, Н1: отказ по каталогу — с причиной.
	if i := strings.Index(out, "AA_STATS_BADDIR "); i >= 0 {
		why := strings.TrimSpace(strings.SplitN(out[i+len("AA_STATS_BADDIR "):], "\n", 2)[0])
		if why == "symlink" {
			why = "это символическая ссылка"
		} else {
			why = "владелец:права " + why + ", ожидалось 0:700 (root, 0700)"
		}
		return fmt.Errorf("установка отменена: каталог %s небезопасен — %s", StatsDir, why)
	}
	if err != nil {
		return fmt.Errorf("установка сборщика: %w", err)
	}
	if !strings.Contains(out, "AA_STATS_INSTALLED") {
		return fmt.Errorf("установка сборщика: сервер не подтвердил завершение — проверьте `stats status`")
	}
	return nil
}

// StatsUninstall снимает таймер, службу и скрипт; данные остаются.
func (s *Session) StatsUninstall() error {
	out, err := s.statsRun(statsUninstallScript())
	if err != nil {
		return fmt.Errorf("снятие сборщика: %w", err)
	}
	if !strings.Contains(out, "AA_STATS_REMOVED") {
		return fmt.Errorf("снятие сборщика: сервер не подтвердил завершение — проверьте `stats status`")
	}
	return nil
}

// ReadTraffic читает накопленные данные. Ошибка — данных не знаем (не
// «нет данных»): вызывающий не строит таблицу.
func (s *Session) ReadTraffic() (*TrafficLog, error) {
	out, err := s.statsRun(statsReadScript())
	if err != nil {
		return nil, fmt.Errorf("чтение статистики: %w", err)
	}
	return parseTrafficRead(out)
}

func parseTrafficRead(out string) (*TrafficLog, error) {
	if !strings.Contains(out, "\nAA_READ_END") && !strings.HasPrefix(out, "AA_READ_END") {
		return nil, fmt.Errorf("чтение статистики: ответ сервера оборван")
	}
	body := map[string]string{}
	have := map[string]bool{}
	var cur string
	var buf []string
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimRight(line, "\r")
		f := strings.Fields(line)
		if cur != "" {
			if len(f) == 2 && f[1] == cur && (f[0] == "AA_EOF" || f[0] == "AA_ERR") {
				if f[0] == "AA_ERR" {
					return nil, fmt.Errorf("чтение статистики: файл %s не прочитан", cur)
				}
				body[cur] = strings.Join(buf, "\n")
				have[cur] = true
				cur, buf = "", nil
				continue
			}
			buf = append(buf, line)
			continue
		}
		if len(f) == 2 && f[0] == "AA_FILE" && (f[1] == "daily.log" || f[1] == "snapshots.log") {
			cur = f[1]
		}
	}
	if cur != "" {
		return nil, fmt.Errorf("чтение статистики: файл %s передан не полностью", cur)
	}
	return ParseTrafficLog(body["daily.log"], have["daily.log"], body["snapshots.log"], have["snapshots.log"]), nil
}
