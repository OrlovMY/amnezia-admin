package core

// Предпроверка ЦЕЛЕВОГО сервера перед установкой Amnezia «с нуля» (А1).
// Только чтение: ни одна проба ничего не меняет на сервере.
//
// У каждого пункта ТРИ исхода (CLAUDE.md, «незнание не выдаётся за
// знание»): годится / не годится / узнать не удалось — с причиной.
// Нулевое значение ProvState — «узнать не удалось»: забытое присваивание не
// превращается ни в «да», ни в «нет». Ошибка команды, оборванный или пустой
// вывод — всегда «узнать не удалось», а не «нет».
//
// Каждая проба — отдельная команда со строками КЛЮЧ=значение и последней
// строкой END (разбор — parseProbe из hostdiag.go): без END проба не
// считается выполненной. Транспорт — Session.run (Runner), то есть та же
// единственная точка маскировки stderr, что и у всех команд.
//
// Итог: есть «не годится» — нельзя; иначе есть «узнать не удалось» —
// неизвестно; иначе — можно. «Не годится» стоит выше «не удалось»:
// измеренный запрет не отменяется тем, что другой пункт не измерен.

import (
	"fmt"
	"strconv"
	"strings"
	"unicode"
)

// ProvState — исход одного пункта предпроверки.
type ProvState int

const (
	// ProvUnknown — узнать не удалось. Нулевое значение намеренно.
	ProvUnknown ProvState = iota
	// ProvOK — годится (проверено).
	ProvOK
	// ProvBad — не годится (проверено).
	ProvBad
)

func (s ProvState) String() string {
	switch s {
	case ProvOK:
		return "годится"
	case ProvBad:
		return "НЕ годится"
	}
	return "узнать не удалось"
}

// ProvVerdict — итог предпроверки.
type ProvVerdict int

const (
	// ProvVerdictUnknown — неизвестно, можно ли ставить. Нулевое значение.
	ProvVerdictUnknown ProvVerdict = iota
	// ProvVerdictYes — можно ставить.
	ProvVerdictYes
	// ProvVerdictNo — нельзя ставить.
	ProvVerdictNo
)

func (v ProvVerdict) String() string {
	switch v {
	case ProvVerdictYes:
		return "можно ставить"
	case ProvVerdictNo:
		return "НЕЛЬЗЯ ставить"
	}
	return "неизвестно, можно ли ставить"
}

// ProvItem — один пункт предпроверки.
type ProvItem struct {
	What   string // что проверялось (для человека)
	State  ProvState
	Reason string // что увидели / почему не годится / почему узнать не удалось
}

// ProvisionReport — итог предпроверки цели.
type ProvisionReport struct {
	Items []ProvItem
}

// Verdict — итог по пунктам. Пустой отчёт — неизвестно.
func (r ProvisionReport) Verdict() ProvVerdict {
	if len(r.Items) == 0 {
		return ProvVerdictUnknown
	}
	unknown := false
	for _, it := range r.Items {
		switch it.State {
		case ProvBad:
			return ProvVerdictNo
		case ProvOK:
		default:
			unknown = true
		}
	}
	if unknown {
		return ProvVerdictUnknown
	}
	return ProvVerdictYes
}

// Порты протоколов ПО УМОЛЧАНИЮ (порт выбирается при установке, проверяется
// только умолчание — в выводе так и сказано). В коде протоколов core портов
// по умолчанию нет (порт всегда читается с сервера). Источник СВЕРЕН
// 05.11.2026: amnezia-vpn/amnezia-client, ветка dev, коммит
// ac175c8a8147cfe56f98c8372ec17ea2ba00bb02, файл
// client/core/utils/constants/protocolConstants.h:
// строка 270 — protocols::awg defaultPort "55424";
// строка 62 — protocols::xray defaultPort "443".
const (
	ProvAWGPort  = 55424
	ProvXRayPort = 443
)

// provMinFreeKB — меньше этого свободного места установка не годится:
// образы контейнеров Amnezia с Docker занимают сотни мегабайт.
const provMinFreeKB = 1024 * 1024 // 1 ГиБ

// Метки проб: первая команда скрипта (ничего не делает), по ней фейк
// узнаёт команду.
const (
	ProvOSTag     = ": aa-prov-os;"
	ProvKernelTag = ": aa-prov-kernel;"
	ProvSudoTag   = ": aa-prov-sudo;"
	ProvDockerTag = ": aa-prov-docker;"
	ProvCtrTag    = ": aa-prov-ctr;"
	ProvPortsTag  = ": aa-prov-ports;"
	ProvDiskTag   = ": aa-prov-disk;"
)

// Скрипты проб. Без одинарных кавычек — идут в sh -c '…'.
const (
	provOSScript     = ProvOSTag + ` if [ -r /etc/os-release ]; then . /etc/os-release; echo "ID=$ID"; echo "VERSION_ID=$VERSION_ID"; echo "PRETTY=$PRETTY_NAME"; else echo OSREL=none; fi; echo END`
	provKernelScript = ProvKernelTag + ` echo "KERNEL=$(uname -r)"; echo "ARCH=$(uname -m)"; echo END`
	provSudoScript   = ProvSudoTag + ` u=$(id -u); echo "UID=$u"; if [ "$u" != 0 ]; then if command -v sudo >/dev/null 2>&1; then o=$(sudo -n true 2>&1); echo "SUDORC=$?"; echo "SUDOERR=$(echo "$o" | head -n 1)"; else echo SUDO=none; fi; fi; echo END`
	provDockerScript = ProvDockerTag + ` if command -v docker >/dev/null 2>&1; then echo DOCKER=yes; o=$(docker version --format "{{.Server.Version}}" 2>&1); echo "SRVRC=$?"; echo "SRV=$(echo "$o" | head -n 1)"; else echo DOCKER=no; fi; echo END`
	provCtrScript    = ProvCtrTag + ` o=$(docker ps -a --format "{{.Names}}|{{.Ports}}" 2>&1); echo "RC=$?"; echo "$o" | sed "s/^/N=/"; echo END`
	provPortsScript  = ProvPortsTag + ` if command -v ss >/dev/null 2>&1; then o=$(ss -lntu 2>&1); echo "SSRC=$?"; echo "$o" | sed "s/^/L=/"; else echo SS=none; fi; echo END`
	provDiskScript   = ProvDiskTag + ` c=/; if [ -d /var/lib/docker ]; then c=/var/lib/docker; elif [ -d /var/lib ]; then c=/var/lib; elif [ -d /var ]; then c=/var; fi; echo "CHAIN=$c"; p=$c;` +
		` if command -v docker >/dev/null 2>&1; then r=$(docker info --format "{{.DockerRootDir}}" 2>&1); rc=$?; r=$(echo "$r" | head -n 1); echo "DRRC=$rc"; echo "DROOT=$r"; if [ "$rc" = 0 ] && [ -d "$r" ]; then p=$r; fi;` +
		` if [ "$rc" != 0 ]; then if [ -e /etc/docker/daemon.json ]; then j=$(cat /etc/docker/daemon.json 2>&1); echo "DJRC=$?"; echo "$j" | sed "s/^/DJ=/"; else echo DJFILE=none; fi; fi; fi; echo "DFPATH=$p"; o=$(df -Pk "$p" 2>&1); echo "DFRC=$?"; echo "$o" | tail -n 1 | sed "s/^/DF=/"; echo END`
)

func provCmd(script string) string { return "sh -c '" + script + "'" }

// provProbe — проба; если needSudo говорит, что не хватило прав, и мы не
// root — повтор через sudo -n (не ждёт пароля). Повтор берётся, только если
// он сам выполнился до конца.
func (s *Session) provProbe(script string, needSudo func(probe) bool) probe {
	out, err := s.run(provCmd(script), nil)
	p := parseProbe(out, err)
	if needSudo != nil && p.ok && needSudo(p) && !s.isRoot() {
		out2, err2 := s.run("sudo -n "+provCmd(script), nil)
		if p2 := parseProbe(out2, err2); p2.ok {
			return p2
		}
	}
	return p
}

func deniedIn(v string) bool { return strings.Contains(strings.ToLower(v), "permission denied") }

// ProvisionCheck — предпроверка цели по открытой сессии. Ошибок не
// возвращает: всё, что узнать не удалось, — ProvUnknown с причиной.
func (s *Session) ProvisionCheck() ProvisionReport {
	return s.provisionCheck([]ProvPort{
		{Name: "порт AmneziaWG", Proto: "udp", Port: ProvAWGPort, Note: "порт по умолчанию"},
		{Name: "порт XRay", Proto: "tcp", Port: ProvXRayPort, Note: "порт по умолчанию"},
	}, nil)
}

// ProvPort — порт, свободу которого проверяет предпроверка.
type ProvPort struct {
	Name, Proto string
	Port        int
	Note        string // «порт по умолчанию» / «порт из копии»
}

// ProvisionPortsFromBackup — порты контейнеров копии, которые будут
// поставлены (NotIncluded пропускаются). Порт, который не читается числом,
// — отдельный пункт «узнать не удалось», а не умолчание вместо ответа.
func ProvisionPortsFromBackup(b *Backup) (ports []ProvPort, bad []ProvItem) {
	if b == nil {
		return nil, []ProvItem{unk("порты из копии", "копии источника нет")}
	}
	for _, c := range b.Containers {
		if c.Status == CtrNotIncluded {
			continue
		}
		proto := "udp"
		if c.Name == "amnezia-xray" {
			proto = "tcp"
		}
		n, err := strconv.Atoi(strings.TrimSpace(c.Port))
		if err != nil || n < 1 || n > 65535 {
			bad = append(bad, unk("порт "+c.Name+" (из копии)", fmt.Sprintf("порт в копии не читается числом: %q", c.Port)))
			continue
		}
		ports = append(ports, ProvPort{Name: "порт " + c.Name, Proto: proto, Port: n, Note: "порт из копии"})
	}
	if len(ports) == 0 && len(bad) == 0 {
		bad = append(bad, unk("порты из копии", "в копии нет ни одного контейнера, который будет поставлен"))
	}
	return ports, bad
}

// ProvisionCheckFor — предпроверка с портами КОПИИ источника (план БК §1:
// «ProvisionCheck(порты из копии)»): ставиться будут именно они, умолчания
// приложения здесь ни при чём.
func (s *Session) ProvisionCheckFor(b *Backup) ProvisionReport {
	ports, bad := ProvisionPortsFromBackup(b)
	return s.provisionCheck(ports, bad)
}

func (s *Session) provisionCheck(ports []ProvPort, portItems []ProvItem) ProvisionReport {
	var r ProvisionReport
	osP := s.provProbe(provOSScript, nil)
	r.Items = append(r.Items, classifyOS(osP))
	kP := s.provProbe(provKernelScript, nil)
	r.Items = append(r.Items, classifyKernel(kP), classifyArch(kP))
	r.Items = append(r.Items, classifyProvAppArmor(s.hostProbe()))
	r.Items = append(r.Items, classifySudo(s.provProbe(provSudoScript, nil)))
	dP := s.provProbe(provDockerScript, func(p probe) bool { return deniedIn(p.get("SRV")) })
	r.Items = append(r.Items, classifyDocker(dP))
	var cP probe
	if dockerUsable(dP) {
		cP = s.provProbe(provCtrScript, func(p probe) bool { return p.get("RC") != "0" && deniedIn(strings.Join(p.kv["N"], " ")) })
	}
	r.Items = append(r.Items, classifyContainers(dP, cP))
	pP := s.provProbe(provPortsScript, nil)
	pub := publishedPorts(dP, cP)
	for _, pp := range ports {
		it := classifyPort(pP, pub, pp.Name, pp.Proto, pp.Port)
		if pp.Note != "порт по умолчанию" {
			it.What = strings.Replace(it.What, "(порт по умолчанию)", "("+pp.Note+")", 1)
		}
		r.Items = append(r.Items, it)
	}
	r.Items = append(r.Items, portItems...)
	diskP := s.provProbe(provDiskScript, func(p probe) bool {
		return deniedIn(p.get("DROOT")) || (p.get("DJRC") != "" && p.get("DJRC") != "0")
	})
	var atP probe
	if root, st, _ := daemonJSONRoot(diskP); st == djPath {
		atP = s.provProbe(provDiskAtScript(root), nil)
	}
	r.Items = append(r.Items, classifyDisk(diskP, atP))
	return r
}

func unk(what, why string) ProvItem { return ProvItem{what, ProvUnknown, why} }

func notRan(what string, p probe) ProvItem {
	return unk(what, "проверка не выполнилась: "+p.err)
}

// ---------- разбор ----------

// provMinVersion — минимальные версии дистрибутивов, на которых ставится
// Docker; ID вне списка — «узнать не удалось» (не «нет»: программа — под
// любой сервер, но годность чужого дистрибутива мы не знаем).
var provMinVersion = map[string]float64{
	"ubuntu": 20.04, "debian": 10, "centos": 8, "rhel": 8, "almalinux": 8, "rocky": 8, "fedora": 38,
}

func classifyOS(p probe) ProvItem {
	const what = "ОС"
	id, ver, pretty := p.get("ID"), p.get("VERSION_ID"), p.get("PRETTY")
	label := pretty
	if label == "" {
		label = strings.TrimSpace(id + " " + ver)
	}
	switch {
	case !p.ok:
		return notRan(what, p)
	case p.has("OSREL"):
		return unk(what, "файла /etc/os-release нет — дистрибутив не определить")
	case id == "":
		return unk(what, "в /etc/os-release нет ID — дистрибутив не определить")
	}
	min, known := provMinVersion[id]
	if !known {
		return unk(what, label+": дистрибутив не из проверенного списка (Ubuntu, Debian, CentOS/RHEL/Alma/Rocky, Fedora) — годится ли, неизвестно")
	}
	v, err := strconv.ParseFloat(ver, 64)
	if err != nil {
		return unk(what, label+": версию «"+ver+"» разобрать не удалось")
	}
	if v < min {
		return ProvItem{what, ProvBad, fmt.Sprintf("%s: слишком старая версия, нужна не ниже %g", label, min)}
	}
	return ProvItem{what, ProvOK, label}
}

// kernelMajorMinor — «5.15.0-91-generic» → 5, 15.
func kernelMajorMinor(k string) (int, int, bool) {
	parts := strings.SplitN(k, ".", 3)
	if len(parts) < 2 {
		return 0, 0, false
	}
	maj, err1 := strconv.Atoi(parts[0])
	minS := parts[1]
	if i := strings.IndexFunc(minS, func(r rune) bool { return r < '0' || r > '9' }); i >= 0 {
		minS = minS[:i]
	}
	mn, err2 := strconv.Atoi(minS)
	if err1 != nil || err2 != nil {
		return 0, 0, false
	}
	return maj, mn, true
}

func classifyKernel(p probe) ProvItem {
	const what = "ядро"
	k := strings.TrimSpace(p.get("KERNEL"))
	switch {
	case !p.ok:
		return notRan(what, p)
	case k == "":
		return unk(what, "uname -r ничего не вернул")
	}
	maj, mn, ok := kernelMajorMinor(k)
	switch {
	case !ok:
		return unk(what, "версию ядра «"+k+"» разобрать не удалось")
	case maj < 3 || (maj == 3 && mn < 10):
		return ProvItem{what, ProvBad, k + ": Docker требует ядро не ниже 3.10"}
	}
	return ProvItem{what, ProvOK, k}
}

func classifyArch(p probe) ProvItem {
	const what = "архитектура"
	a := strings.TrimSpace(p.get("ARCH"))
	switch {
	case !p.ok:
		return notRan(what, p)
	case a == "":
		return unk(what, "uname -m ничего не вернул")
	case a == "x86_64" || a == "amd64" || a == "aarch64" || a == "arm64":
		return ProvItem{what, ProvOK, a}
	}
	// Аудит AU р1, L1: проверенного источника о годности других архитектур
	// нет (контейнеры собираются на сервере из Dockerfile) — «не знаем», а
	// не «нет».
	return unk(what, a+": не проверено, что образы Amnezia собираются на "+a+" (проверены только x86_64 и aarch64)")
}

// classifyProvAppArmor — профили wg/wg-quick хоста ломают WireGuard в
// контейнерах (Ubuntu 26.04, hostdiag.go). Проба — та же, что у diagnose.
func classifyProvAppArmor(h probe) ProvItem {
	const what = "AppArmor"
	loaded := wgProfiles(h.kv["LOADED"])
	switch {
	case !h.ok:
		return notRan(what, h)
	case h.get("AA") == "none":
		return ProvItem{what, ProvOK, "AppArmor на сервере нет"}
	case h.get("AA") != "yes":
		return unk(what, "наличие AppArmor определить не удалось")
	case h.get("PROF") != "readable":
		return unk(what, "AppArmor есть, список профилей прочитать не удалось (нужны права root)")
	case len(loaded) > 0:
		return ProvItem{what, ProvBad, "загружены профили " + strings.Join(loaded, ", ") + " — они не дают поднять WireGuard/AmneziaWG в контейнерах; выгрузите их (diagnose -fix после установки или apparmor_parser -R)"}
	}
	return ProvItem{what, ProvOK, "AppArmor есть, профилей wg/wg-quick нет"}
}

func classifySudo(p probe) ProvItem {
	const what = "права (root/sudo)"
	switch {
	case !p.ok:
		return notRan(what, p)
	case p.get("UID") == "0":
		return ProvItem{what, ProvOK, "вход под root"}
	case p.get("UID") == "":
		return unk(what, "id -u ничего не вернул")
	case p.has("SUDO"):
		return ProvItem{what, ProvBad, "не root и sudo не установлен"}
	case p.get("SUDORC") == "0":
		return ProvItem{what, ProvOK, "sudo без пароля работает"}
	case p.get("SUDORC") != "":
		return ProvItem{what, ProvBad, "не root и sudo без пароля не разрешён: " + srvText(p.get("SUDOERR"))}
	}
	return unk(what, "проверить sudo не удалось")
}

// dockerUsable — Docker установлен и демон ответил.
func dockerUsable(p probe) bool {
	return p.ok && p.get("DOCKER") == "yes" && p.get("SRVRC") == "0" && strings.TrimSpace(p.get("SRV")) != ""
}

func classifyDocker(p probe) ProvItem {
	const what = "Docker"
	srv := srvText(strings.TrimSpace(p.get("SRV")))
	switch {
	case !p.ok:
		return notRan(what, p)
	case p.get("DOCKER") == "no":
		return ProvItem{what, ProvOK, "не установлен — установщик Amnezia поставит его сам"}
	case p.get("DOCKER") != "yes":
		return unk(what, "наличие Docker определить не удалось")
	case dockerUsable(p):
		return ProvItem{what, ProvOK, "версия " + srv + ", демон работает"}
	case deniedIn(srv):
		return unk(what, "Docker установлен, а спросить демон не хватило прав: "+srv)
	// Решение ядра (ревью р1, M1): остановленный демон — поправимо, официальный
	// установщик сам делает systemctl enable --now docker. Не «нельзя».
	case dockerStopped(p):
		return ProvItem{what, ProvOK, "Docker установлен, демон остановлен — официальный установщик запустит его (" + srv + ")"}
	case srv == "":
		return unk(what, "Docker установлен, демон не ответил (пустой вывод)")
	}
	return unk(what, "Docker установлен, состояние демона непонятно: "+srv)
}

// dockerStopped — Docker установлен, демон измеренно не запущен.
func dockerStopped(p probe) bool {
	srv := p.get("SRV")
	return p.ok && p.get("DOCKER") == "yes" && p.get("SRVRC") != "0" &&
		(strings.Contains(srv, "Cannot connect to the Docker daemon") || strings.Contains(srv, "Is the docker daemon running"))
}

// srvMax — сколько рун текста сервера попадает в причину.
const srvMax = 200

// srvText — текст сервера для причины: управляющие символы (в т.ч. ESC
// терминальных последовательностей) заменяются пробелом, длина обрезается.
func srvText(s string) string {
	var b strings.Builder
	n := 0
	for _, r := range s {
		if n == srvMax {
			b.WriteString("…")
			break
		}
		if unicode.IsControl(r) {
			r = ' '
		}
		b.WriteRune(r)
		n++
	}
	return b.String()
}

// pubPorts — порты, опубликованные контейнерами Docker (docker ps): ss их не
// видит, если docker-proxy выключен (правила iptables). known=false —
// список получить не удалось.
type pubPorts struct {
	known bool
	why   string            // почему не known
	set   map[string]string // "tcp:443" → имя контейнера
	// ranges — опубликованные диапазоны (docker ps: 400-500->400-500/tcp).
	ranges []pubRange
}

type pubRange struct {
	proto    string
	from, to int
	name     string
}

// busy — кем занят proto:port ("" — никем).
func (pp pubPorts) busy(proto string, port int) string {
	if n := pp.set[proto+":"+strconv.Itoa(port)]; n != "" {
		return n
	}
	for _, r := range pp.ranges {
		if r.proto == proto && port >= r.from && port <= r.to {
			return r.name
		}
	}
	return ""
}

func publishedPorts(d, c probe) pubPorts {
	switch {
	case d.ok && d.get("DOCKER") == "no":
		return pubPorts{known: true} // Docker нет — и опубликованных портов нет (измерено: command -v docker)
	case dockerStopped(d):
		// Ревью р2, N2: демон лежит — docker ps не выполнялся; контейнеры с
		// restart: always опубликуют порты, когда установщик поднимет демон.
		return pubPorts{why: "демон Docker остановлен — порты его контейнеров неизвестны"}
	case !dockerUsable(d) || !c.ok || c.get("RC") != "0":
		return pubPorts{why: "список портов контейнеров Docker (docker ps) получить не удалось — ss их может не видеть"}
	}
	pp := pubPorts{known: true, set: map[string]string{}}
	for _, line := range c.kv["N"] {
		name, ports, _ := strings.Cut(line, "|")
		for _, part := range strings.Split(ports, ",") {
			host, ctr, ok := strings.Cut(strings.TrimSpace(part), "->")
			if !ok {
				continue // порт только объявлен (EXPOSE), не опубликован
			}
			_, proto, _ := strings.Cut(ctr, "/")
			hp := host[strings.LastIndexByte(host, ':')+1:]
			name = strings.TrimSpace(name)
			lo, hi, isRange := strings.Cut(hp, "-")
			a, err1 := strconv.Atoi(lo)
			b, err2 := a, error(nil)
			if isRange {
				b, err2 = strconv.Atoi(hi)
			}
			if err1 != nil || err2 != nil || b < a || (proto != "tcp" && proto != "udp") {
				// N4: не разобрали — не «свободно», а «не знаем». N6: уже
				// найденные занятые порты не сбрасываются — список неполный.
				if pp.known {
					pp.known = false
					pp.why = "порты контейнеров Docker разобраны не все («" + srvText(strings.TrimSpace(part)) + "»)"
				}
				continue
			}
			if isRange {
				pp.ranges = append(pp.ranges, pubRange{proto, a, b, name})
			} else {
				pp.set[proto+":"+strconv.Itoa(a)] = name
			}
		}
	}
	return pp
}

// provCtrWhat — подпись пункта о контейнерах Amnezia.
const provCtrWhat = "контейнеры amnezia-*"

func classifyContainers(d, c probe) ProvItem {
	const what = provCtrWhat
	switch {
	case d.ok && d.get("DOCKER") == "no":
		return ProvItem{what, ProvOK, "нет (Docker не установлен)"}
	case !dockerUsable(d):
		return unk(what, "Docker недоступен — список контейнеров не получить")
	case !c.ok:
		return notRan(what, c)
	case c.get("RC") != "0":
		return unk(what, "docker ps не выполнился: "+srvText(strings.Join(c.kv["N"], " ")))
	}
	var found []string
	for _, n := range c.kv["N"] {
		n, _, _ = strings.Cut(n, "|")
		if n = strings.TrimSpace(n); strings.HasPrefix(n, "amnezia-") {
			found = append(found, n)
		}
	}
	if len(found) > 0 {
		return ProvItem{what, ProvBad, "уже есть: " + strings.Join(found, ", ") + " — сервер не пустой, установка «с нуля» их затронет"}
	}
	return ProvItem{what, ProvOK, "нет"}
}

// listenPorts — «proto:port» прослушиваемых сокетов из вывода ss -lntu.
func listenPorts(lines []string) (map[string]bool, int) {
	m := map[string]bool{}
	n := 0
	for _, l := range lines {
		f := strings.Fields(l)
		if len(f) < 5 || f[0] == "Netid" {
			continue
		}
		local := f[4]
		i := strings.LastIndexByte(local, ':')
		if i < 0 {
			continue
		}
		if _, err := strconv.Atoi(local[i+1:]); err != nil {
			continue
		}
		n++
		m[f[0]+":"+local[i+1:]] = true
	}
	return m, n
}

func classifyPort(p probe, pub pubPorts, name, proto string, port int) ProvItem {
	what := fmt.Sprintf("%s %d/%s (порт по умолчанию)", name, port, proto)
	key := proto + ":" + strconv.Itoa(port)
	switch {
	// Опубликованный контейнером порт — измеренное «занят», даже если ss
	// не ответил: docker ps его видит.
	case pub.busy(proto, port) != "":
		note := ""
		if !pub.known {
			note = " (список портов контейнеров неполный: " + pub.why + ")"
		}
		return ProvItem{what, ProvBad, "порт опубликован контейнером " + srvText(pub.busy(proto, port)) + " — освободите его или выберите другой порт при установке" + note}
	case !p.ok:
		return notRan(what, p)
	case p.has("SS"):
		return unk(what, "утилиты ss на сервере нет — занятость портов не проверить")
	case p.get("SSRC") != "0":
		return unk(what, "ss не выполнился: "+srvText(strings.Join(p.kv["L"], " ")))
	}
	m, n := listenPorts(p.kv["L"])
	switch {
	case n == 0:
		// На живом сервере слушает хотя бы sshd: пустой список — не «свободно».
		return unk(what, "ss не показал ни одного прослушиваемого сокета (даже SSH) — данным не верим")
	case m[key]:
		return ProvItem{what, ProvBad, "порт занят другой программой — освободите его или выберите другой порт при установке"}
	case !pub.known:
		// ss не видит порты контейнеров с выключенным docker-proxy.
		why := pub.why
		if why == "" {
			why = "порты контейнеров Docker неизвестны"
		}
		return unk(what, "по ss свободен, но "+why)
	}
	return ProvItem{what, ProvOK, "свободен (по ss и docker ps; ss не видит порты контейнеров с выключенным docker-proxy, их сверили по docker ps)"}
}
