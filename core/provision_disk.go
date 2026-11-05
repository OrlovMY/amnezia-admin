package core

// Свободное место для предпроверки (А1; аудит AU р1 M1, аудит-2 L2).
// Меряется каталог, куда лягут данные Docker:
//   - демон работает — DockerRootDir;
//   - демон остановлен — data-root из /etc/docker/daemon.json (файла нет —
//     цепочка; файл есть, но не прочитан/не разобран — «не знаем»);
//   - Docker нет — ближайший существующий из /var/lib/docker → /var/lib →
//     /var → /.

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// ProvDiskAtTag — метка второй пробы: df каталога data-root из daemon.json.
const ProvDiskAtTag = ": aa-prov-diskat;"

// provSafePath — путь, который можно вставить в скрипт: абсолютный, без
// пробелов, кавычек, $ и прочего, что шелл истолкует.
var provSafePath = regexp.MustCompile(`^/[A-Za-z0-9._/-]*$`)

// provDiskAtScript — df ближайшего существующего предка root. root обязан
// пройти provSafePath (иначе в скрипт он не попадает — см. daemonJSONRoot).
func provDiskAtScript(root string) string {
	var chain []string
	for p := strings.TrimRight(root, "/"); p != "" && p != "/"; p = p[:strings.LastIndexByte(p, '/')] {
		chain = append(chain, p)
	}
	var b strings.Builder
	b.WriteString(ProvDiskAtTag + ` p=/;`)
	for i, c := range chain {
		if i == 0 {
			b.WriteString(` if [ -d ` + c + ` ]; then p=` + c + `;`)
		} else {
			b.WriteString(` elif [ -d ` + c + ` ]; then p=` + c + `;`)
		}
	}
	if len(chain) > 0 {
		b.WriteString(` fi;`)
	}
	b.WriteString(` echo "DFPATH=$p"; o=$(df -Pk "$p" 2>&1); echo "DFRC=$?"; echo "$o" | tail -n 1 | sed "s/^/DF=/"; echo END`)
	return b.String()
}

type djState int

const (
	djUnknown djState = iota // daemon.json не прочитан / не разобран / путь непригоден
	djNone                   // daemon.json не нужен (демон работает, Docker нет) или его нет, или data-root не задан
	djPath                   // data-root задан
)

// daemonJSONRoot — data-root из daemon.json пробы диска. Нужен только при
// остановленном демоне; в прочих случаях — djNone.
func daemonJSONRoot(p probe) (string, djState, string) {
	if !p.ok || !p.has("DRRC") || p.get("DRRC") == "0" {
		return "", djNone, ""
	}
	switch {
	case p.has("DJFILE"):
		return "", djNone, ""
	case p.get("DJRC") != "0":
		return "", djUnknown, "демон Docker остановлен, а /etc/docker/daemon.json прочитать не удалось: " + srvText(strings.Join(p.kv["DJ"], " "))
	}
	var cfg map[string]any
	if err := json.Unmarshal([]byte(strings.Join(p.kv["DJ"], "\n")), &cfg); err != nil {
		return "", djUnknown, "демон Docker остановлен, а /etc/docker/daemon.json не разобран: " + srvText(err.Error())
	}
	v, ok := cfg["data-root"]
	if !ok {
		v, ok = cfg["graph"] // старое имя того же параметра
	}
	if !ok {
		return "", djNone, ""
	}
	s, isStr := v.(string)
	if !isStr || !provSafePath.MatchString(s) {
		return "", djUnknown, fmt.Sprintf("в /etc/docker/daemon.json data-root «%s» — путь не разобран", srvText(fmt.Sprint(v)))
	}
	return s, djPath, ""
}

func classifyDisk(p, at probe) ProvItem {
	const what = "свободное место"
	switch {
	case !p.ok:
		return notRan(what, p)
	case p.get("DFPATH") == "":
		return unk(what, "каталог данных Docker определить не удалось")
	// M1: при работающем демоне меряется DockerRootDir; если он назван, но
	// мерили не его, — «не знаем», а не цепочка по умолчанию.
	case p.get("DRRC") == "0" && (strings.TrimSpace(p.get("DROOT")) == "" || p.get("DFPATH") != p.get("DROOT")):
		return unk(what, "Docker назвал каталог данных «"+srvText(p.get("DROOT"))+"», а измерить его не удалось")
	// Docker есть, но DockerRootDir не прочитан не потому, что демон лежит
	// (нет прав, иная ошибка): data-root может быть где угодно — не знаем.
	case p.has("DRRC") && p.get("DRRC") != "0" && !strings.Contains(p.get("DROOT"), "Cannot connect to the Docker daemon"):
		return unk(what, "каталог данных Docker прочитать не удалось: "+srvText(p.get("DROOT")))
	}
	src := "ближайший существующий каталог по цепочке /var/lib/docker → /var/lib → /var → /"
	switch root, st, why := daemonJSONRoot(p); {
	case p.get("DRRC") == "0":
		src = "каталог данных Docker (DockerRootDir)"
	case st == djUnknown:
		return unk(what, why)
	case st == djPath:
		if !at.ok {
			return unk(what, "data-root «"+root+"» из /etc/docker/daemon.json измерить не удалось: "+at.err)
		}
		p = at
		src = "data-root " + root + " из /etc/docker/daemon.json (демон остановлен), ближайший существующий каталог"
	case p.has("DRRC"):
		src += "; демон Docker остановлен, data-root в /etc/docker/daemon.json не задан"
	}
	return measureDisk(what, p, src)
}

func measureDisk(what string, p probe, src string) ProvItem {
	if p.get("DFRC") != "0" {
		return unk(what, "df не выполнился: "+srvText(p.get("DF")))
	}
	f := strings.Fields(p.get("DF"))
	if len(f) < 4 {
		return unk(what, "вывод df не разобран")
	}
	kb, err := strconv.ParseInt(f[3], 10, 64)
	if err != nil {
		return unk(what, "вывод df не разобран: «"+srvText(f[3])+"»")
	}
	free := fmt.Sprintf("%.1f ГиБ свободно на %s (%s)", float64(kb)/1024/1024, srvText(p.get("DFPATH")), src)
	if kb < provMinFreeKB {
		return ProvItem{what, ProvBad, free + " — нужно не меньше 1 ГиБ"}
	}
	return ProvItem{what, ProvOK, free}
}
