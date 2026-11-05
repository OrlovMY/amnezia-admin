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

// Порты протоколов по умолчанию. В коде протоколов core портов по умолчанию
// нет (порт всегда читается с сервера); значения — умолчания приложения
// Amnezia: AmneziaWG — 55424/udp, XRay (VLESS Reality) — 443/tcp.
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
	provCtrScript    = ProvCtrTag + ` o=$(docker ps -a --format "{{.Names}}" 2>&1); echo "RC=$?"; echo "$o" | sed "s/^/N=/"; echo END`
	provPortsScript  = ProvPortsTag + ` if command -v ss >/dev/null 2>&1; then o=$(ss -lntu 2>&1); echo "SSRC=$?"; echo "$o" | sed "s/^/L=/"; else echo SS=none; fi; echo END`
	provDiskScript   = ProvDiskTag + ` p=/; if [ -d /var/lib/docker ]; then p=/var/lib/docker; fi; echo "DFPATH=$p"; o=$(df -Pk "$p" 2>&1); echo "DFRC=$?"; echo "$o" | tail -n 1 | sed "s/^/DF=/"; echo END`
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
	r.Items = append(r.Items,
		classifyPort(pP, "порт AmneziaWG", "udp", ProvAWGPort),
		classifyPort(pP, "порт XRay", "tcp", ProvXRayPort))
	r.Items = append(r.Items, classifyDisk(s.provProbe(provDiskScript, nil)))
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
	return ProvItem{what, ProvBad, a + ": образы Amnezia собираются для x86_64 и aarch64"}
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
		return ProvItem{what, ProvBad, "не root и sudo без пароля не разрешён: " + p.get("SUDOERR")}
	}
	return unk(what, "проверить sudo не удалось")
}

// dockerUsable — Docker установлен и демон ответил.
func dockerUsable(p probe) bool {
	return p.ok && p.get("DOCKER") == "yes" && p.get("SRVRC") == "0" && strings.TrimSpace(p.get("SRV")) != ""
}

func classifyDocker(p probe) ProvItem {
	const what = "Docker"
	srv := strings.TrimSpace(p.get("SRV"))
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
	case strings.Contains(srv, "Cannot connect to the Docker daemon") || strings.Contains(srv, "Is the docker daemon running"):
		return ProvItem{what, ProvBad, "Docker установлен, демон не работает: " + srv}
	case srv == "":
		return unk(what, "Docker установлен, демон не ответил (пустой вывод)")
	}
	return unk(what, "Docker установлен, состояние демона непонятно: "+srv)
}

func classifyContainers(d, c probe) ProvItem {
	const what = "контейнеры amnezia-*"
	switch {
	case d.ok && d.get("DOCKER") == "no":
		return ProvItem{what, ProvOK, "нет (Docker не установлен)"}
	case !dockerUsable(d):
		return unk(what, "Docker недоступен — список контейнеров не получить")
	case !c.ok:
		return notRan(what, c)
	case c.get("RC") != "0":
		return unk(what, "docker ps не выполнился: "+strings.Join(c.kv["N"], " "))
	}
	var found []string
	for _, n := range c.kv["N"] {
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

func classifyPort(p probe, name, proto string, port int) ProvItem {
	what := fmt.Sprintf("%s %d/%s", name, port, proto)
	switch {
	case !p.ok:
		return notRan(what, p)
	case p.has("SS"):
		return unk(what, "утилиты ss на сервере нет — занятость портов не проверить")
	case p.get("SSRC") != "0":
		return unk(what, "ss не выполнился: "+strings.Join(p.kv["L"], " "))
	}
	m, n := listenPorts(p.kv["L"])
	switch {
	case n == 0:
		// На живом сервере слушает хотя бы sshd: пустой список — не «свободно».
		return unk(what, "ss не показал ни одного прослушиваемого сокета (даже SSH) — данным не верим")
	case m[proto+":"+strconv.Itoa(port)]:
		return ProvItem{what, ProvBad, "порт занят другой программой — освободите его или выберите другой порт при установке"}
	}
	return ProvItem{what, ProvOK, "свободен"}
}

func classifyDisk(p probe) ProvItem {
	const what = "свободное место"
	switch {
	case !p.ok:
		return notRan(what, p)
	case p.get("DFRC") != "0":
		return unk(what, "df не выполнился: "+p.get("DF"))
	}
	f := strings.Fields(p.get("DF"))
	if len(f) < 4 {
		return unk(what, "вывод df не разобран")
	}
	kb, err := strconv.ParseInt(f[3], 10, 64)
	if err != nil {
		return unk(what, "вывод df не разобран: «"+f[3]+"»")
	}
	free := fmt.Sprintf("%.1f ГиБ свободно на %s", float64(kb)/1024/1024, p.get("DFPATH"))
	if kb < provMinFreeKB {
		return ProvItem{what, ProvBad, free + " — нужно не меньше 1 ГиБ"}
	}
	return ProvItem{what, ProvOK, free}
}
