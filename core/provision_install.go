package core

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"amnezia-admin/core/provision"
)

// Установка контейнеров на ЧИСТЫЙ сервер официальными скриптами (план БК
// «перенос на чистый сервер», PR 5). Ключи, обфускацию и клиентов потом
// переносит Restore; здесь поднимается «пустой» контейнер того же
// семейства, порта и подсети, и установка ИЗМЕРЯЕТСЯ CheckTarget.
//
// Порядок на контейнер — эталон ручной установки на живом сервере 05.11:
// prepare_host.sh → Dockerfile в /opt/amnezia/<контейнер> → build_container.sh
// → run_container.sh → configure_container.sh внутри контейнера → start.sh в
// контейнер → (XRay: server.json) → clientsTable «[]» → docker restart.
// install_docker.sh — один раз до контейнеров. setup_host_firewall.sh НЕ
// запускается (меняет весь хост — аудит AMNEZIA-SCRIPTS-1 M2/M3).
//
// Каждый шаг отвечает тремя состояниями: выполнен / отказал (известный код
// выхода) / неизвестно (ответа нет — связь оборвалась или ответ без метки).
// Код выхода берётся из метки в stdout, а не из ошибки Runner: так «отказал»
// и «не знаем» различимы и на поддельном Runner.

// InstallOutcome — исход контейнера. Нулевое значение — «неизвестно».
// Метода String нет намеренно: печатается InstallContainerResult.Verdict().
type InstallOutcome int

const (
	InstallOutcomeUnknown InstallOutcome = iota // связь оборвалась / откат не подтверждён
	InstallNotInstalled                         // не ставился или снят откатом (подтверждено)
	InstallInstalled                            // все шаги выполнены
)

// RollbackState — откат контейнера. Нулевое — «не знаем».
type RollbackState int

const (
	RollbackUnknown   RollbackState = iota // откат запускали, исход не подтверждён
	RollbackNotNeeded                      // контейнер не создавался (или откат не требовался)
	RollbackDone                           // контейнера больше нет — измерено
	RollbackFailed                         // контейнер остался — измерено
)

// InstallContainerResult — исход одного контейнера.
type InstallContainerResult struct {
	Container string
	Revision  string
	Outcome   InstallOutcome
	// Measured — сверка с копией после установки (CheckTarget). Значимо
	// только у InstallInstalled; нулевое — не измерено.
	Measured CompatState
	Step     string // последний начатый шаг
	Reason   string
	Rollback RollbackState
	// RollbackLeft — что по измерению осталось после отката (контейнер, том).
	RollbackLeft []string
}

// MeasuredMatchText — подпись измеренного совпадения. Измеряются семейство
// параметров, порт и подсеть; версию бинаря сравнивать не с чем — она не
// обещается (ревью PR 5 M2).
const MeasuredMatchText = "поставлен; совпадает с копией по семейству параметров, порту и подсети; версия бинаря не закреплена и не измерялась"

// Verdict — подпись исхода для человека (печатать вместе с Reason).
func (r InstallContainerResult) Verdict() string {
	switch r.Outcome {
	case InstallInstalled:
		switch r.Measured {
		case CompatMatch:
			return MeasuredMatchText
		case CompatMismatch:
			return "поставлен, но измерение НЕ совпало с копией"
		}
		return "поставлен, измерить не удалось"
	case InstallNotInstalled:
		return "не поставлен"
	}
	return "неизвестно"
}

// InstallOptions — входные данные установки.
type InstallOptions struct {
	// Backup — копия источника: параметры AWG и измерение после установки.
	Backup *Backup
	// Resolve — для CheckTarget (адрес выдачи); может быть nil.
	Resolve Resolver
	// PreviewAccepted — человек видел InstallPreview(plan) и согласился.
	// Без этого ни одна команда записи не выполняется.
	PreviewAccepted bool
}

// InstallResult — итог установки.
type InstallResult struct {
	// Refused — отказ ДО любой записи на сервер (причина). Пусто — запись
	// начиналась.
	Refused    string
	Containers []InstallContainerResult
	Skipped    []InstallSkip
	// Measure — повторная проверка цели; nil — не выполнялась или не удалась.
	Measure *CompatReport
	// Stop — переносить клиентов нельзя; StopReason — почему.
	Stop       bool
	StopReason string
}

// ReadyForRestore — каждый контейнер поставлен И измерен как совпадающий.
// Адрес выдачи (Measure.NeedAddressConfirm) здесь НЕ учитывается: его
// подтверждение перед Restore — обязанность потребителя.
func (r InstallResult) ReadyForRestore() bool {
	if r.Refused != "" || r.Stop || len(r.Containers) == 0 || r.Measure == nil {
		return false
	}
	for _, c := range r.Containers {
		if c.Outcome != InstallInstalled || c.Measured != CompatMatch {
			return false
		}
	}
	return true
}

// Lines — текст итога для человека: отказ/стоп, каждый контейнер
// (Verdict + Reason), откат и не поставленные из копии (Skipped) целиком.
func (r InstallResult) Lines() []string {
	var out []string
	if r.Refused != "" {
		out = append(out, "Установка не начата: "+r.Refused)
		return append(out, skippedLines(r.Skipped)...)
	}
	for _, c := range r.Containers {
		l := c.Container + ": " + c.Verdict()
		if c.Reason != "" {
			l += " — " + c.Reason
		}
		switch c.Rollback {
		case RollbackDone:
			l += " (снят откатом)"
		case RollbackFailed:
			l += " (откат НЕ удался: на сервере остался " + strings.Join(c.RollbackLeft, ", ") +
				" — повторная установка откажет «сервер не чистый»)"
		case RollbackUnknown:
			l += " (откат не подтверждён)"
		}
		out = append(out, l)
	}
	out = append(out, skippedLines(r.Skipped)...)
	if r.Stop {
		out = append(out, "Перенос клиентов остановлен: "+r.StopReason)
	} else if r.ReadyForRestore() {
		out = append(out, "Все контейнеры поставлены и совпадают с копией — можно переносить клиентов.")
	}
	return out
}

func skippedLines(sk []InstallSkip) []string {
	var out []string
	for _, s := range sk {
		out = append(out, "Не ставится: "+s.Container+" — "+s.Reason)
	}
	return out
}

// ---------- шаги на сервере ----------

// instRC — метка кода выхода шага в stdout.
const instRC = "AMNEZIA_ADMIN_RC="

type stepState int

const (
	stepUnknown stepState = iota
	stepOK
	stepFailed
)

// instStep — выполнить cmd (обязан печатать метку instRC последней строкой).
// Ошибка Runner или отсутствие метки — «неизвестно».
func (s *Session) instStep(cmd string, stdin []byte) (stepState, string, int) {
	out, err := s.run(cmd, stdin)
	if err != nil {
		return stepUnknown, "", -1
	}
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	last := lines[len(lines)-1]
	v, ok := strings.CutPrefix(last, instRC)
	if !ok {
		return stepUnknown, "", -1
	}
	rc, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil {
		return stepUnknown, "", -1
	}
	body := strings.Join(lines[:len(lines)-1], "\n")
	if rc != 0 {
		return stepFailed, body, rc
	}
	return stepOK, body, 0
}

// hostScriptCmd — скрипт хоста из stdin: во временный файл и bash без stdin
// (иначе `docker exec -i` внутри скрипта съел бы его хвост).
const hostScriptCmd = `sh -c 't=$(mktemp) && cat > "$t" && bash "$t" </dev/null; rc=$?; rm -f "$t"; echo ` + instRC + `$rc'`

func rcTail(cmd string) string { return `sh -c '` + cmd + `; echo ` + instRC + `$?'` }

func execInCmd(ctr, inner string) string {
	return rcTail("sudo -n docker exec -i " + ctr + " " + inner)
}

// listNames — `docker ps -a` / `docker volume ls`; ok=false — не знаем.
// Docker не установлен — пустой список (ok=true).
func (s *Session) listNames(what string) ([]string, bool) {
	q := `sudo -n docker ps -a --format "{{.Names}}"`
	switch what {
	case "volume":
		q = `sudo -n docker volume ls --format "{{.Name}}"`
	case "image":
		q = `sudo -n docker images --format "{{.Repository}}"`
	}
	cmd := `sh -c 'if ! command -v docker >/dev/null 2>&1; then echo ` + instRC + `0; exit 0; fi; ` + q + `; echo ` + instRC + `$?'`
	st, body, _ := s.instStep(cmd, nil)
	if st != stepOK {
		return nil, false
	}
	return strings.Fields(body), true
}

// ---------- подготовка скриптов ----------

// containerScripts — всё, что уйдёт на сервер для контейнера; собирается
// ДО первой записи, чтобы ошибка подстановки не оставила полуустановку.
type containerScripts struct {
	item                              InstallItem
	folder, dockerDir, dataDir        string
	prepare, dockerfile, build, run   string
	configure, start, remove, srvJSON string
	removeVolume                      string // XRay: именованный том
}

var reSNI = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$`)

// awgConfVars — ключ [Interface] → переменная configure_container.sh.
var awgConfVars = map[string]string{
	"Jc": "JUNK_PACKET_COUNT", "Jmin": "JUNK_PACKET_MIN_SIZE", "Jmax": "JUNK_PACKET_MAX_SIZE",
	"S1": "INIT_PACKET_JUNK_SIZE", "S2": "RESPONSE_PACKET_JUNK_SIZE",
	"S3": "COOKIE_REPLY_PACKET_JUNK_SIZE", "S4": "TRANSPORT_PACKET_JUNK_SIZE",
	"H1": "INIT_PACKET_MAGIC_HEADER", "H2": "RESPONSE_PACKET_MAGIC_HEADER",
	"H3": "UNDERLOAD_PACKET_MAGIC_HEADER", "H4": "TRANSPORT_PACKET_MAGIC_HEADER",
	"HeaderProtectionKey": "HEADER_PROTECTION_KEY", "ContentPaddingAddition": "CONTENT_PADDING_ADDITION",
	"RekeyAfterTime": "REKEY_AFTER_TIME", "RekeyTimeout": "REKEY_TIMEOUT", "RejectAfterTime": "REJECT_AFTER_TIME",
	"KeepaliveTimeout": "KEEPALIVE_TIMEOUT", "MaxHandshakeAttempts": "MAX_HANDSHAKE_ATTEMPTS",
	"RandomTrailers": "RANDOM_TRAILERS", "DisableCookies": "DISABLE_COOKIES",
	"I1": "SPECIAL_JUNK_1", "I2": "SPECIAL_JUNK_2", "I3": "SPECIAL_JUNK_3", "I4": "SPECIAL_JUNK_4", "I5": "SPECIAL_JUNK_5",
}

// renderFor — Render с переменными из all, отфильтрованными по закрытому
// списку файла (недостающие — пустые: Render сам решит, можно ли).
func renderFor(rev, file string, all map[string]string) (string, error) {
	names, ok := provision.RequiredVars(rev, file)
	if !ok {
		return "", fmt.Errorf("в ревизии %s нет файла %s", rev, file)
	}
	vars := map[string]string{}
	for _, n := range names {
		vars[n] = all[n]
	}
	return provision.Render(rev, file, vars)
}

func backupContainer(b *Backup, name string) *BackupContainer {
	for i := range b.Containers {
		if b.Containers[i].Name == name {
			return &b.Containers[i]
		}
	}
	return nil
}

// xrayServerScript — скрипт внутри контейнера XRay: читает ключи, которые
// сгенерировал configure_container.sh, и пишет server.json формы
// parseXRayServer. Значения ключей подставляет оболочка сервера; в Go и в
// вывод они не попадают.
func xrayServerScript(port, sni, flow string) (string, error) {
	if p, err := strconv.Atoi(port); err != nil || p < 1 || p > 65535 || strconv.Itoa(p) != port {
		return "", fmt.Errorf("порт XRay из копии не число 1..65535")
	}
	if len(sni) > 253 || !reSNI.MatchString(sni) {
		return "", fmt.Errorf("SNI XRay из копии — не имя хоста")
	}
	if flow != "" && flow != xrayFlowVision {
		return "", fmt.Errorf("flow XRay из копии незнаком")
	}
	cl := map[string]any{"id": "@@U@@"}
	if flow != "" {
		cl["flow"] = flow
	}
	pn, _ := strconv.Atoi(port)
	tree := map[string]any{
		"log": map[string]any{"loglevel": "error"},
		"inbounds": []any{map[string]any{
			"port": pn, "protocol": "vless",
			"settings": map[string]any{"clients": []any{cl}, "decryption": "none"},
			"streamSettings": map[string]any{"network": "tcp", "security": "reality",
				"realitySettings": map[string]any{"dest": sni + ":443", "serverNames": []any{sni},
					"privateKey": "@@K@@", "shortIds": []any{"@@S@@"}}},
		}},
		"outbounds": []any{map[string]any{"protocol": "freedom"}},
	}
	js, err := marshalXRay(tree)
	if err != nil {
		return "", err
	}
	body := strings.NewReplacer(`"@@U@@"`, `"$U"`, `"@@K@@"`, `"$K"`, `"@@S@@"`, `"$S"`).Replace(string(js))
	return "D=" + xrayDir + "\n" +
		"U=$(tr -d '[:space:]' < $D/xray_uuid.key 2>/dev/null)\n" +
		"K=$(tr -d '[:space:]' < $D/xray_private.key 2>/dev/null)\n" +
		"S=$(tr -d '[:space:]' < $D/xray_short_id.key 2>/dev/null)\n" +
		"if [ -z \"$U\" ] || [ -z \"$K\" ] || [ -z \"$S\" ]; then echo amnezia_admin_xray_keys=missing; exit 3; fi\n" +
		"umask 077\n" +
		"cat > $D/server.json.tmp <<EOF\n" + body + "EOF\n" +
		"mv $D/server.json.tmp $D/server.json\n", nil
}

func prepareScripts(sess *Session, it InstallItem, b *Backup) (*containerScripts, error) {
	folder, ok := provision.FolderOf(it.Container)
	if !ok {
		return nil, fmt.Errorf("контейнер %s вне закрытого списка установки", it.Container)
	}
	lc, _, ok := lookupContainer(it.Container)
	if !ok || lc.Dir == "" {
		return nil, fmt.Errorf("каталог протокола %s неизвестен", it.Container)
	}
	bc := backupContainer(b, it.Container)
	if bc == nil || bc.Status != CtrSaved {
		return nil, fmt.Errorf("контейнера %s нет в копии среди сохранённых", it.Container)
	}
	cs := &containerScripts{item: it, folder: folder, dockerDir: "/opt/amnezia/" + it.Container, dataDir: lc.Dir}
	all := map[string]string{
		"CONTAINER_NAME": it.Container, "DOCKERFILE_FOLDER": cs.dockerDir,
		"SERVER_IP_ADDRESS": sess.Creds.Host,
		"AWG_SERVER_PORT":   it.Port, "WIREGUARD_SERVER_PORT": it.Port, "XRAY_SERVER_PORT": it.Port,
	}
	if folder != "xray" {
		ip, cidr, ok := strings.Cut(it.Subnet, "/")
		if !ok {
			return nil, fmt.Errorf("%s: подсеть копии без длины префикса", it.Container)
		}
		all["AWG_SUBNET_IP"], all["WIREGUARD_SUBNET_IP"], all["WIREGUARD_SUBNET_CIDR"] = ip, ip, cidr
	}
	if folder == "awg" || folder == "awg_legacy" {
		var conf *BackupFile
		for i := range bc.Files {
			if strings.HasSuffix(bc.Files[i].Name, ".conf") && bc.Files[i].Status == FileSaved {
				conf = &bc.Files[i]
				break
			}
		}
		if conf == nil {
			return nil, fmt.Errorf("%s: в копии нет сохранённого файла конфигурации — параметры AWG неизвестны", it.Container)
		}
		for k, v := range parseWgConf(string(conf.Data.Bytes())).iface {
			if n, ok := awgConfVars[k]; ok {
				all[n] = v
			}
		}
	}
	rev := it.Revision
	var err error
	r := func(file string) string {
		if err != nil {
			return ""
		}
		var out string
		out, err = renderFor(rev, file, all)
		return out
	}
	cs.prepare = r("prepare_host.sh")
	cs.dockerfile = r(folder + "/Dockerfile")
	cs.build = r("build_container.sh")
	cs.run = r(folder + "/run_container.sh")
	cs.configure = r(folder + "/configure_container.sh")
	cs.start = r(folder + "/start.sh")
	cs.remove = r("remove_container.sh")
	if err != nil {
		return nil, fmt.Errorf("%s: %w", it.Container, err)
	}
	if folder == "xray" {
		if cs.srvJSON, err = xrayServerScript(it.Port, it.SNI, it.Flow); err != nil {
			return nil, fmt.Errorf("%s: %w", it.Container, err)
		}
		cs.removeVolume = it.Container + "-data"
	}
	return cs, nil
}

// ---------- предпросмотр ----------

var (
	reFrom      = regexp.MustCompile(`(?m)^FROM\s+(\S+)`)
	reXrayRel   = regexp.MustCompile(`ARG XRAY_RELEASE="([^"]+)"`)
	reNetSubnet = regexp.MustCompile(`--subnet=(\S+)`)
	rePublish   = regexp.MustCompile(`-p \$[A-Z_]+:\$[A-Z_]+/(udp|tcp)`)
)

// InstallPreview — перечень ВСЕГО, что установка изменит на хосте (аудит
// AMNEZIA-SCRIPTS-1 M1–M3). Факты берутся из текста закреплённых скриптов,
// а не из памяти: поменяется скрипт — поменяется и перечень.
func InstallPreview(plan InstallPlan) ([]string, error) {
	if len(plan.Items) == 0 {
		return nil, fmt.Errorf("план пуст — ставить нечего")
	}
	rev0 := plan.Items[0].Revision
	read := func(rev, f string) (string, error) {
		b, err := provision.Script(rev, f)
		return string(b), err
	}
	prep, err := read(rev0, "prepare_host.sh")
	if err != nil {
		return nil, err
	}
	netSubnet := "(подсеть не найдена в prepare_host.sh)"
	if m := reNetSubnet.FindStringSubmatch(prep); m != nil {
		netSubnet = m[1]
	}
	out := []string{
		"Хост, пакеты (install_docker.sh, ревизия " + rev0 + "): sudo, which, psmisc, lsof, docker.io (на Fedora/CentOS/SUSE/Arch — docker), " +
			"apparmor при включённом AppArmor — из репозитория ОС, версии не закреплены; служба docker включается (systemctl enable --now docker).",
		"Хост, сеть Docker amnezia-dns-net " + netSubnet + " (мост amn0) — создаётся, если её нет.",
		"Хост: setup_host_firewall.sh НЕ запускается — файрвол хоста, ping и глобальные sysctl не меняются " +
			"(скрипт приложения запрещает ping, меняет sysctl всего сервера, в 5.1.0.6 — DROP TCP с IP-опциями).",
	}
	for _, it := range plan.Items {
		folder, ok := provision.FolderOf(it.Container)
		if !ok {
			return nil, fmt.Errorf("контейнер %s вне закрытого списка установки", it.Container)
		}
		df, err := read(it.Revision, folder+"/Dockerfile")
		if err != nil {
			return nil, err
		}
		run, err := read(it.Revision, folder+"/run_container.sh")
		if err != nil {
			return nil, err
		}
		p := it.Container + " (ревизия " + it.Revision + "): каталог /opt/amnezia/" + it.Container + " на хосте; образ собирается docker build --no-cache --pull"
		if m := reFrom.FindStringSubmatch(df); m != nil {
			p += " FROM " + m[1]
			switch {
			case strings.HasSuffix(m[1], ":latest"):
				p += " — плавающий тег :latest без дайджеста, версия не закреплена"
			case m[1] == "alpine:3.15":
				p += " — ветка Alpine 3.15 вне поддержки (EOL с ноября 2023)"
			}
		}
		if strings.Contains(df, "apk --update upgrade") || strings.Contains(df, "apk add") {
			p += "; пакеты apk без закреплённых версий"
		}
		if strings.Contains(df, "Xray-linux-64.zip") {
			rel := "?"
			if m := reXrayRel.FindStringSubmatch(df); m != nil {
				rel = m[1]
			}
			p += "; XRay " + rel + " качается zip с GitHub без сверки контрольной суммы и распаковывается в /usr/bin"
		}
		var flags []string
		for _, f := range []string{"--privileged", "SYS_MODULE", "NET_ADMIN"} {
			if strings.Contains(run, f) {
				flags = append(flags, f)
			}
		}
		if strings.Contains(run, "-v /lib/modules:/lib/modules") {
			flags = append(flags, "-v /lib/modules (модули ядра хоста)")
		}
		if strings.Contains(run, "--restart always") {
			flags = append(flags, "--restart always")
		}
		p += "; контейнер запускается с " + strings.Join(flags, ", ")
		var ports []string
		for _, m := range rePublish.FindAllStringSubmatch(run, -1) {
			ports = append(ports, it.Port+"/"+m[1])
		}
		p += "; наружу открывается порт " + strings.Join(ports, " и ")
		if strings.Contains(run, "-v $CONTAINER_NAME-data:") {
			p += "; том Docker " + it.Container + "-data"
		}
		if it.Subnet != "" {
			p += "; подсеть клиентов " + it.Subnet
		}
		if folder == "xray" {
			p += "; server.json пишет программа (VLESS/Reality, порт " + it.Port + ", SNI " + it.SNI + "), ключи генерирует configure_container.sh внутри контейнера"
		}
		p += "; в контейнере создаётся пустой clientsTable."
		out = append(out, p)
		if strings.Contains(run, "--privileged") {
			out = append(out, it.Container+": --privileged даёт контейнеру полный доступ к хосту — подмена образа или загрузки = root на сервере.")
		}
	}
	for _, s := range plan.Skipped {
		out = append(out, "Не ставится: "+s.Container+" — "+s.Reason)
	}
	out = append(out, "Откат при сбое до переноса клиентов: поставленные в этом запуске контейнеры удаляются remove_container.sh "+
		"(с образом; у XRay — и том); пакеты, служба docker, сеть amnezia-dns-net и каталоги /opt/amnezia/<контейнер> остаются.")
	return out, nil
}

// ---------- установка ----------

// installMeasure — повторная проверка цели (подменяется только тестом
// отказа измерения; по умолчанию — настоящий CheckTarget).
var installMeasure = func(s *Session, b *Backup, r Resolver) (*CompatReport, error) {
	return s.CheckTarget(b, r)
}

// Install — установка по плану на чистый сервер. Подробности — в шапке файла.
func Install(sess *Session, plan InstallPlan, opt InstallOptions) InstallResult {
	res := InstallResult{Skipped: plan.Skipped}
	refuse := func(why string) InstallResult {
		res.Refused, res.Stop, res.StopReason = why, true, why
		return res
	}
	if sess == nil || sess.Creds == nil {
		return refuse("нет сессии с новым сервером")
	}
	if !plan.Ready() {
		var why []string
		for _, it := range plan.Items {
			if it.Compat != CompatMatch {
				why = append(why, it.Container+": "+it.Verdict()+" — "+it.Reason)
			}
		}
		if len(plan.Items) == 0 {
			why = append(why, "в плане нет ни одного контейнера")
		}
		return refuse("план не готов: " + strings.Join(why, "; "))
	}
	if !opt.PreviewAccepted {
		return refuse("перечень изменений на хосте (InstallPreview) не подтверждён")
	}
	if opt.Backup == nil {
		return refuse("нет копии источника — измерить установку не с чем")
	}
	var all []*containerScripts
	for _, it := range plan.Items {
		cs, err := prepareScripts(sess, it, opt.Backup)
		if err != nil {
			return refuse("скрипты не подготовлены: " + err.Error())
		}
		all = append(all, cs)
	}
	installDocker, err := renderFor(plan.Items[0].Revision, "install_docker.sh", nil)
	if err != nil {
		return refuse("скрипты не подготовлены: " + err.Error())
	}

	// Цель обязана быть чистой: снос существующего — отдельный шаг с
	// подтверждением и копией цели (решение владельца), здесь — отказ.
	// Образы — тоже: откат делает `docker rmi <имя>` и не должен снести
	// существовавший до запуска (ревью PR 5 L1).
	ctrs, ok1 := sess.listNames("container")
	vols, ok2 := sess.listNames("volume")
	imgs, ok3 := sess.listNames("image")
	if !ok1 || !ok2 || !ok3 {
		return refuse("не удалось узнать, есть ли на сервере контейнеры, тома и образы Amnezia — чистота цели не проверена")
	}
	var dirty []string
	for _, n := range append(append(ctrs, vols...), imgs...) {
		if strings.HasPrefix(n, "amnezia-") {
			dirty = append(dirty, n)
		}
	}
	if len(dirty) > 0 {
		sort.Strings(dirty)
		return refuse("сервер не чистый: уже есть " + strings.Join(dirty, ", ") +
			" — установка только на чистый сервер; снос с подтверждением и копией цели в этой версии не сделан")
	}

	for _, cs := range all {
		res.Containers = append(res.Containers, InstallContainerResult{
			Container: cs.item.Container, Revision: cs.item.Revision,
			Outcome: InstallNotInstalled, Rollback: RollbackNotNeeded, Reason: "не ставился",
		})
	}
	stop := func(why string) InstallResult {
		res.Stop, res.StopReason = true, why
		return res
	}

	switch st, _, rc := sess.instStep(hostScriptCmd, []byte(installDocker)); st {
	case stepUnknown:
		return stop("install_docker.sh: ответа нет — связь оборвалась; установлен ли Docker, неизвестно")
	case stepFailed:
		return stop(fmt.Sprintf("install_docker.sh завершился с кодом %d", rc))
	}
	switch st, body, rc := sess.instStep(rcTail(`sudo -n docker version --format "{{.Server.Version}}"`), nil); {
	case st == stepUnknown:
		return stop("проверка Docker после install_docker.sh: ответа нет")
	case st == stepFailed || strings.TrimSpace(body) == "":
		return stop(fmt.Sprintf("Docker после install_docker.sh не отвечает (код %d)", rc))
	}

	var created []int // индексы контейнеров, которые создавали МЫ
	for i, cs := range all {
		r := &res.Containers[i]
		r.Reason = ""
		failed, why, unknown := sess.installOne(cs, r, &created, i)
		if !failed {
			r.Outcome = InstallInstalled
			continue
		}
		if unknown {
			r.Outcome = InstallOutcomeUnknown
		} else {
			r.Outcome = InstallNotInstalled
		}
		r.Reason = why
		for j := i + 1; j < len(all); j++ {
			res.Containers[j].Reason = "не ставился: установка остановлена на " + cs.item.Container
		}
		sess.rollback(all, &res, created)
		return stop(cs.item.Container + ": " + why)
	}

	rep, err := installMeasure(sess, opt.Backup, opt.Resolve)
	if err != nil {
		for i := range res.Containers {
			res.Containers[i].Measured = CompatUnknown
		}
		sess.rollback(all, &res, created)
		return stop("измерение после установки не выполнено: " + err.Error())
	}
	res.Measure = rep
	var bad []string
	for i := range res.Containers {
		r := &res.Containers[i]
		r.Measured = measuredOf(rep, r.Container)
		if r.Measured != CompatMatch {
			var texts []string
			for _, row := range rep.Rows {
				if row.Container == r.Container && row.State != CompatMatch {
					texts = append(texts, row.What+": "+row.State.String()+" — "+row.Text)
				}
			}
			r.Reason = "измерение: " + strings.Join(texts, "; ")
			bad = append(bad, r.Container)
		}
	}
	if len(bad) > 0 {
		sess.rollback(all, &res, created)
		return stop("после установки не совпало с копией: " + strings.Join(bad, ", ") + " — клиенты не переносятся")
	}
	return res
}

// measuredOf — сводка строк CheckTarget по контейнеру: все Match — Match;
// есть Mismatch — Mismatch; иначе (в т.ч. строк нет) — Unknown.
func measuredOf(rep *CompatReport, ctr string) CompatState {
	n, mis, unk := 0, false, false
	for _, row := range rep.Rows {
		if row.Container != ctr {
			continue
		}
		n++
		switch row.State {
		case CompatMismatch:
			mis = true
		case CompatMatch:
		default:
			unk = true
		}
	}
	switch {
	case n == 0 || unk:
		return CompatUnknown
	case mis:
		return CompatMismatch
	}
	return CompatMatch
}

// installOne — шаги одного контейнера. failed=false — все выполнены.
// unknown — последний шаг без ответа.
func (s *Session) installOne(cs *containerScripts, r *InstallContainerResult, created *[]int, idx int) (failed bool, why string, unknown bool) {
	c := cs.item.Container
	type step struct {
		name, cmd string
		stdin     string
		creates   bool // с этого шага контейнер/образ мог появиться
		check     func(body string) string
	}
	steps := []step{
		{name: "prepare_host.sh", cmd: hostScriptCmd, stdin: cs.prepare},
		{name: "Dockerfile", cmd: rcTail("sudo -n tee " + cs.dockerDir + "/Dockerfile >/dev/null"), stdin: cs.dockerfile},
		{name: "build_container.sh", cmd: hostScriptCmd, stdin: cs.build, creates: true},
		{name: "run_container.sh", cmd: hostScriptCmd, stdin: cs.run},
		{name: "configure_container.sh", cmd: execInCmd(c, "bash -s"), stdin: cs.configure,
			check: func(b string) string {
				if strings.Contains(b, "amnezia_xray_keygen=failed") {
					return "configure_container.sh: ключи XRay не сгенерированы"
				}
				return ""
			}},
		{name: "start.sh", cmd: execInCmd(c, `sh -c "cat > /opt/amnezia/start.sh && chmod a+x /opt/amnezia/start.sh"`), stdin: cs.start},
	}
	if cs.srvJSON != "" {
		steps = append(steps, step{name: "server.json", cmd: execInCmd(c, "sh -s"), stdin: cs.srvJSON})
	}
	steps = append(steps,
		step{name: "clientsTable", cmd: execInCmd(c, `sh -c "mkdir -p `+cs.dataDir+` && cat > `+cs.dataDir+`/clientsTable"`), stdin: "[]"},
		step{name: "docker restart", cmd: rcTail("sudo -n docker restart " + c)},
		// Два замера через паузу: контейнер в цикле перезапуска может
		// показать Running=true в момент одного замера (ревью PR 5 L3).
		step{name: "контейнер запущен", cmd: rcTail(`i="sudo -n docker inspect -f {{.State.Running}}/{{.RestartCount}} ` + c +
			`" && $i && sleep ` + instSettleSeconds + ` && $i`),
			check: runningStable},
	)
	for _, st := range steps {
		r.Step = st.name
		if st.creates {
			*created = append(*created, idx)
		}
		var in []byte
		if st.stdin != "" {
			in = []byte(st.stdin)
		}
		state, body, rc := s.instStep(st.cmd, in)
		switch state {
		case stepUnknown:
			return true, "шаг «" + st.name + "»: ответа нет — связь оборвалась, состояние контейнера неизвестно", true
		case stepFailed:
			return true, fmt.Sprintf("шаг «%s» завершился с кодом %d", st.name, rc), false
		}
		if st.check != nil {
			if w := st.check(body); w != "" {
				return true, "шаг «" + st.name + "»: " + w, false
			}
		}
	}
	return false, "", false
}

// instSettleSeconds — пауза между двумя замерами работы контейнера.
const instSettleSeconds = "5"

// runningStable — два замера «Running/RestartCount»: оба true и счётчик
// перезапусков не вырос.
func runningStable(b string) string {
	f := strings.Fields(b)
	if len(f) != 2 {
		return "состояние контейнера не прочитано двумя замерами"
	}
	r1, c1, _ := strings.Cut(f[0], "/")
	r2, c2, _ := strings.Cut(f[1], "/")
	if r1 != "true" || r2 != "true" {
		return "контейнер после перезапуска не работает"
	}
	if c1 == "" || c1 != c2 {
		return "контейнер перезапускается сам (RestartCount " + c1 + " → " + c2 + ")"
	}
	return ""
}

// rollback — remove_container.sh для контейнеров, созданных в этом запуске
// (в обратном порядке), затем ИЗМЕРЕНИЕ: остался ли контейнер.
func (s *Session) rollback(all []*containerScripts, res *InstallResult, created []int) {
	for k := len(created) - 1; k >= 0; k-- {
		i := created[k]
		cs, r := all[i], &res.Containers[i]
		r.Rollback = RollbackUnknown
		s.instStep(hostScriptCmd, []byte(cs.remove)) // исход — по измерению ниже
		if cs.removeVolume != "" {
			s.instStep(rcTail("sudo -n docker volume rm "+cs.removeVolume), nil)
		}
		// Измеряем всё, что откат обязан убрать: контейнер и (XRay) том с
		// ключами этого запуска (ревью PR 5 M1).
		want := map[string]string{"container": cs.item.Container}
		if cs.removeVolume != "" {
			want["volume"] = cs.removeVolume
		}
		var left []string
		unknown := false
		for _, kind := range []string{"container", "volume"} {
			name, has := want[kind]
			if !has {
				continue
			}
			names, ok := s.listNames(kind)
			if !ok {
				unknown = true
				continue
			}
			for _, n := range names {
				if n == name {
					left = append(left, map[string]string{"container": "контейнер ", "volume": "том с ключами "}[kind]+n)
				}
			}
		}
		switch {
		case len(left) > 0:
			r.Rollback, r.Outcome, r.RollbackLeft = RollbackFailed, InstallOutcomeUnknown, left
		case unknown:
			r.Outcome = InstallOutcomeUnknown
			r.Reason += "; откат: удалено ли всё, узнать не удалось"
		default:
			// Ничего не осталось — измерено: «не поставлен» известно, даже
			// если шаг до отката оборвался.
			r.Rollback, r.Outcome = RollbackDone, InstallNotInstalled
		}
	}
}
