package canary

// К8 — amnezia-awg2 (AWG2/AWG3), проект БК-ПРОТОКОЛЫ-AWG2-XRAY, PR-W3.
// Шаги, которые проверяет сервер, — по серверу; связь на устройствах —
// вопросом человеку (да / нет / не проверено), ответ «не проверено» —
// НЕ ПРОВЕРЕНО, а не ПРОЙДЕН.

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"amnezia-admin/core"
)

// k8IDs — шаги К8 по порядку.
var k8IDs = []string{"К8.1", "К8.2", "К8.3", "К8.4", "К8.5", "К8.6", "К8.7", "К8.8"}

var reANSI = regexp.MustCompile(`\x1b\[[0-9;]*m`)

// savedPath — путь к .conf из строки вывода CLI «Конфиг сохранён: <путь>»
// (без цветовых кодов и подписи); "" — строки не было.
func savedPath(line string) string {
	l := strings.TrimSpace(reANSI.ReplaceAllString(line, ""))
	if i := strings.LastIndex(l, ": "); i >= 0 {
		l = l[i+2:]
	}
	return strings.TrimSpace(l)
}

// isAWG2Ctr — контейнер amnezia-awg2 (файл awg0.conf).
func (e *Env) isAWG2Ctr() bool { return e.fam.File == "awg0.conf" }

// k8Rows — строки К8 для Run: не amnezia-awg2 — одна «НЕ ПРИМЕНИМО»;
// предусловия не подтверждены — все НЕ ПРОВЕРЕНО.
func (e *Env) k8Rows(gateOK bool) []Result {
	if !e.isAWG2Ctr() {
		return []Result{stepR("К8", NotApplicable, "контейнер "+e.Ctr.Name+" — не amnezia-awg2; К8 проверяется запуском с -container amnezia-awg2")}
	}
	if !gateOK {
		var rs []Result
		for _, s := range k8IDs {
			rs = append(rs, stepR(s, NotChecked, "запись не выполнялась: предусловие К2 не подтверждено"))
		}
		return rs
	}
	return e.k8()
}

// AWGVariantLine — какой вариант проверен вживую (проект: «В итоге
// канарейки это называется вслух»). "" — К8 не дошёл до определения.
func AWGVariantLine(version string, known bool) string {
	if !known {
		return ""
	}
	switch version {
	case "3.1":
		return "проверено на AWG3; AWG2 — только на тестовом стенде"
	case "2":
		return "проверено на AWG2; AWG3 — только на тестовом стенде"
	}
	return "проверено на файле без признаков AWG2/AWG3 (версия не определена); AWG2 и AWG3 — только на тестовом стенде"
}

// expectStatus — ответ человека на вопрос «Открывается ли сайт?» против
// ожидания (UX W3 В2: вопросы без отрицаний, ожидаемое — в скобках, сверяет
// программа): совпал — ПРОЙДЕН, не совпал — НЕ ПРОЙДЕН, пропуск — НЕ ПРОВЕРЕНО.
func expectStatus(a Answer, opens bool) Status {
	switch {
	case a == AnswerSkip:
		return NotChecked
	case (a == AnswerYes) == opens:
		return Pass
	}
	return Fail
}

// worse — худший из двух исходов шага с двумя вопросами.
func worse(a, b Status) Status {
	switch {
	case a == Fail || b == Fail:
		return Fail
	case a == NotChecked || b == NotChecked:
		return NotChecked
	}
	return Pass
}

// ifaceBlock — секция [Interface] текста (до первой [Peer]).
func ifaceBlock(text string) string {
	if i := strings.Index(text, "[Peer]"); i >= 0 {
		return text[:i]
	}
	return text
}

// ifaceKeys — ИМЕНА ключей [Interface] (значения — нет: среди них
// PrivateKey сервера).
func ifaceKeys(text string) []string {
	var ks []string
	for _, l := range strings.Split(ifaceBlock(text), "\n") {
		l = strings.TrimSpace(strings.TrimRight(l, "\r"))
		if l == "" || strings.HasPrefix(l, "[") {
			continue
		}
		if strings.HasPrefix(l, "#") {
			if m := strings.SplitN(strings.TrimSpace(strings.TrimPrefix(l, "#")), "=", 2); len(m) == 2 {
				ks = append(ks, "# "+strings.TrimSpace(m[0]))
			}
			continue
		}
		ks = append(ks, strings.TrimSpace(strings.SplitN(l, "=", 2)[0]))
	}
	return ks
}

// dumpPeers — ключи peer'ов из `awg show awg0 dump` и число полей в каждой
// строке peer'а.
func dumpPeers(out string) (keys map[string]int) {
	keys = map[string]int{}
	for i, l := range strings.Split(out, "\n") {
		l = strings.TrimRight(l, "\r")
		if i == 0 || strings.TrimSpace(l) == "" {
			continue
		}
		f := strings.Split(l, "\t")
		keys[f[0]] = len(f)
	}
	return keys
}

func (e *Env) dump() (map[string]int, string, error) {
	out, err := e.Remote(e.docker + " exec " + e.Ctr.Name + " " + e.fam.Tool + " show " + e.fam.Iface + " dump")
	if err != nil {
		return nil, out, err
	}
	return dumpPeers(out), out, nil
}

// k8 — шаги К8.1–К8.8 на amnezia-awg2.
func (e *Env) k8() []Result {
	rs := make([]Result, len(k8IDs))
	for i, s := range k8IDs {
		rs[i] = stepR(s, NotChecked, "не выполнялся: остановлено на предыдущем шаге")
	}
	set := func(i int, st Status, d string) { rs[i].Status, rs[i].Detail = st, d }

	// К8.1 — формат. Незнакомый ключ или файл не прочитан — СТОП К8.
	f := e.Sess.AWGFormatOf(e.Ctr)
	text, terr := e.catFile(e.conf())
	keys := "ключи не прочитаны"
	if terr == nil {
		keys = strings.Join(ifaceKeys(text), ", ")
	}
	switch f.State {
	case core.FormatKnown:
		e.awgVariant = AWGVariantLine(f.Version, true)
		set(0, Pass, core.AWGVersionLabel(f)+"; [Interface]: "+keys+"; "+e.awgVariant)
	case core.FormatUnknownKey:
		set(0, Fail, core.AWGVersionLabel(f)+"; [Interface]: "+keys+" — СТОП: незнакомый параметр, программа такой файл только показывает")
		return rs
	default:
		set(0, NotChecked, core.AWGVersionLabel(f)+" — СТОП")
		return rs
	}

	// К8.2 — добавление.
	before := ifaceBlock(text)
	a := e.cli(e.NewBin, e.KeyEnv, "add", "-name", "canary-k8")
	if a.code != 0 {
		set(1, Fail, fmt.Sprintf("add: код %d: %s", a.code, a.title))
		return rs
	}
	m, err := e.names()
	if err != nil {
		set(1, NotChecked, "список после add не прочитан: "+err.Error())
		return rs
	}
	id := m["canary-k8"].ClientID
	peers, _, derr := e.dump()
	after, aerr := e.catFile(e.conf())
	switch {
	case id == "":
		set(1, Fail, "canary-k8 нет в списке после add")
		return rs
	case derr != nil || aerr != nil:
		set(1, NotChecked, "awg show или awg0.conf после add не прочитаны")
		return rs
	case peers[id] == 0:
		set(1, Fail, "ключа canary-k8 нет в awg show "+e.fam.Iface+" dump")
		return rs
	case strings.TrimRight(ifaceBlock(after), " \r\n") != strings.TrimRight(before, " \r\n"):
		set(1, Fail, "[Interface] awg0.conf после add изменился — параметры маскировки не должны меняться")
		return rs
	}
	aConf := savedPath(a.conf)
	set(1, Pass, "ключ в awg show dump; [Interface] awg0.conf байт в байт прежний (без учёта пустых строк перед [Peer])")

	// К8.3 — телефон.
	st3, d3 := e.askIP("К8.3: импортируйте на телефон в приложение AmneziaWG или Amnezia файл "+aConf+" и подключитесь им.", true)
	set(2, st3, d3)

	// К8.4 — выключить/включить.
	if r := e.cli(e.NewBin, e.KeyEnv, "toggle", "-name", "canary-k8", "-yes"); r.code != 0 {
		set(3, Fail, fmt.Sprintf("выключить: код %d: %s", r.code, r.title))
		return rs
	}
	offS, offD := e.askIP("К8.4: программа ВЫКЛЮЧИЛА пользователя canary-k8. На телефоне, не переподключаясь,", false)
	if r := e.cli(e.NewBin, e.KeyEnv, "toggle", "-name", "canary-k8", "-yes"); r.code != 0 {
		set(3, Fail, fmt.Sprintf("включить: код %d: %s", r.code, r.title))
		return rs
	}
	onS, onD := e.askIP("К8.4: программа ВКЛЮЧИЛА canary-k8 обратно. На телефоне", true)
	set(3, worse(offS, onS), fmt.Sprintf("выключен — %s (%s); включён — %s (%s)", offS, offD, onS, onD))

	// К8.5 — перевыпуск. Прежний файл программа перезапишет — копия.
	oldCopy := ""
	if b, err := os.ReadFile(aConf); err == nil {
		if dir, err := os.MkdirTemp("", "canary-k8-old"); err == nil {
			oldCopy = filepath.Join(dir, "canary-k8-old.conf")
			if os.WriteFile(oldCopy, b, 0o600) != nil {
				oldCopy = ""
			}
		}
	}
	r := e.cli(e.NewBin, e.KeyEnv, "rekey", "-name", "canary-k8", "-yes")
	if r.code != 0 {
		set(4, Fail, fmt.Sprintf("rekey: код %d: %s", r.code, r.title))
		return rs
	}
	newConf := savedPath(r.conf)
	if newConf == "" {
		newConf = aConf
	}
	// Копии прежнего конфига нет — вопрос не задаётся, половина шага
	// НЕ ПРОВЕРЕНО (а не «пропустите вопрос»).
	oldS, oldD := NotChecked, "копия прежнего конфига не сделана, вопрос не задан"
	if oldCopy != "" {
		oldS, oldD = e.askIP("К8.5: в приложении на телефоне отключите текущее подключение, импортируйте ПРЕЖНИЙ конфиг "+oldCopy+" и подключитесь им.", false)
	}
	newS, newD := e.askIP("К8.5: отключите прежний, импортируйте НОВЫЙ конфиг "+newConf+" и подключитесь им.", true)
	set(4, worse(oldS, newS), fmt.Sprintf("прежний — %s (%s); новый — %s (%s)", oldS, oldD, newS, newD))

	// К8.6 — удаление.
	m, err = e.names()
	if err != nil {
		set(5, NotChecked, "список перед удалением не прочитан: "+err.Error())
		return rs
	}
	id = m["canary-k8"].ClientID
	if d := e.cli(e.NewBin, e.KeyEnv, "del", "-name", "canary-k8", "-yes"); d.code != 0 {
		set(5, Fail, fmt.Sprintf("del: код %d: %s", d.code, d.title))
		return rs
	}
	peers, _, derr = e.dump()
	switch {
	case derr != nil:
		set(5, NotChecked, "awg show после удаления не прочитан")
	case id == "":
		set(5, Fail, "canary-k8 не найден перед удалением")
	case peers[id] != 0:
		set(5, Fail, "ключ canary-k8 остался в awg show после удаления")
	default:
		set(5, Pass, "ключа нет в awg show dump")
	}

	// К8.7 — второе устройство.
	st7, d7 := e.askIP("К8.7: второе устройство — то, что вы подключили через приложение Amnezia, когда программа просила добавить пользователя. Не переподключая его,", true)
	set(6, st7, d7)

	// К8.8 — формат dump против parsePeerStats.
	st8, d8 := e.k8Stats()
	set(7, st8, d8)
	return rs
}

// k8Stats — К8.8: каждая строка peer'а в dump — 8 полей, и набор ключей
// совпадает с разбором GetPeerStats (parsePeerStats).
func (e *Env) k8Stats() (Status, string) {
	peers, _, err := e.dump()
	if err != nil {
		return NotChecked, "awg show dump не прочитан: " + err.Error()
	}
	stats, err := e.Sess.GetPeerStats(e.Ctr)
	if err != nil {
		if strings.Contains(err.Error(), "не разобран") {
			return Fail, "parsePeerStats не разобрал ответ сервера: " + err.Error()
		}
		return NotChecked, "статистика не получена: " + err.Error()
	}
	var bad []string
	for k, n := range peers {
		if n != 8 {
			bad = append(bad, fmt.Sprintf("строка peer'а — %d полей вместо 8", n))
		}
		if _, ok := stats[k]; !ok {
			bad = append(bad, "peer из dump нет в разборе")
		}
	}
	if len(stats) != len(peers) {
		bad = append(bad, fmt.Sprintf("peer'ов в dump %d, в разборе %d", len(peers), len(stats)))
	}
	if len(bad) > 0 {
		sort.Strings(bad)
		return Fail, strings.Join(bad, "; ")
	}
	return Pass, fmt.Sprintf("peer'ов %d, по 8 полей, разбор совпал", len(peers))
}
