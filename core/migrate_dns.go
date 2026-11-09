package core

// AmneziaDNS при переносе сервера. Контейнер amnezia-dns данных и клиентов
// не несёт (unbound в сети amnezia-dns-net, 172.29.172.254), поэтому
// «перенести» его — значит поставить на новом сервере теми же официальными
// скриптами Amnezia (dns/Dockerfile, dns/run_container.sh), если он есть на
// источнике. Без него клиенты, которым приложение выдало DNS 172.29.172.254,
// на новом сервере остаются без разрешения имён.
//
// Есть ли он на источнике — ТРИ состояния: есть / нет / узнать не удалось.
// Смотрится `docker ps -a`: остановленный контейнер — тоже «есть» (FindContainers
// видит только запущенные). «Не удалось» — не «нет»: такой перенос не
// называется полным.

import (
	"errors"
	"strconv"
	"strings"
)

// DNSContainer — имя контейнера AmneziaDNS.
const DNSContainer = "amnezia-dns"

// DNSPresence — есть ли amnezia-dns на сервере. Нулевое значение — «узнать не
// удалось»: не измерено — не знаем.
type DNSPresence int

const (
	DNSUnknown DNSPresence = iota
	DNSAbsent
	DNSPresent
)

// DNSProbe — что известно об amnezia-dns на сервере.
type DNSProbe struct {
	State DNSPresence
	// Running — запущен ли (только при DNSPresent): Match — да, Mismatch —
	// остановлен, Unknown — не прочитано.
	Running CompatState
	Why     string // почему DNSUnknown
}

// dnsListCmd — все контейнеры, и остановленные (та же команда, что в
// AdminKeyReissuePlan).
const dnsListCmd = "docker ps -a --format '{{.Names}}'"

// ProbeAmneziaDNS — есть ли amnezia-dns на сервере (только чтение).
func (s *Session) ProbeAmneziaDNS() DNSProbe {
	out, err := s.docker(dnsListCmd, nil)
	if err != nil {
		return DNSProbe{Why: "список всех контейнеров (docker ps -a) не прочитан: " + MaskText(err.Error())}
	}
	if !hasName(out, DNSContainer) {
		return DNSProbe{State: DNSAbsent}
	}
	p := DNSProbe{State: DNSPresent}
	if run, err := s.docker("docker ps --format '{{.Names}}'", nil); err == nil {
		p.Running = CompatMismatch
		if hasName(run, DNSContainer) {
			p.Running = CompatMatch
		}
	}
	return p
}

func hasName(list, name string) bool {
	for _, n := range strings.Fields(list) {
		if n == name {
			return true
		}
	}
	return false
}

func (p DNSProbe) srcText() string {
	switch p.State {
	case DNSAbsent:
		return "на источнике его нет"
	case DNSPresent:
		switch p.Running {
		case CompatMatch:
			return "на источнике есть (запущен)"
		case CompatMismatch:
			return "на источнике есть (остановлен; на новом сервере будет запущен — скрипты Amnezia ставят его с --restart always)"
		}
		return "на источнике есть (запущен ли — не прочитано)"
	}
	why := p.Why
	if why == "" {
		why = "не проверялось"
	}
	return "есть ли он на источнике, узнать не удалось (" + why + ") — это не «его нет»"
}

// dnsRevision — ревизия скриптов для AmneziaDNS: самая свежая закреплённая.
func dnsRevision() string { return DefaultRevisionPreference[0] }

// SourceDNSLines — строка плана установки на чистый сервер (migrate
// -to-host, GUI): что будет с AmneziaDNS.
func SourceDNSLines(p DNSProbe) []string {
	switch p.State {
	case DNSAbsent:
		return []string{"  AmneziaDNS: " + p.srcText() + " — не ставится."}
	case DNSPresent:
		return []string{"  AmneziaDNS: " + p.srcText() + " — будет поставлен на новом сервере после переноса клиентов официальными скриптами Amnezia [скрипты " + dnsRevision() + "]; данных у него нет, переносить нечего."}
	}
	return []string{"  AmneziaDNS: " + p.srcText() + ". На новый сервер он не ставится, и перенос не будет назван полным: проверьте docker ps -a на источнике."}
}

// DNSLines — строки предпросмотра переноса про AmneziaDNS (CLI и GUI — один
// текст). nil — на источнике его нет и на цели ставить нечего.
func (m *Migration) DNSLines() []string {
	if m == nil {
		return nil
	}
	head := "AmneziaDNS: " + m.SrcDNS.srcText()
	switch m.SrcDNS.State {
	case DNSAbsent:
		return nil
	case DNSUnknown:
		return []string{head + ". На новый сервер он не ставится; итог переноса будет «частично»: проверьте docker ps -a на источнике."}
	}
	switch m.DstDNS.State {
	case DNSPresent:
		return []string{head + "; на новом сервере он уже есть — не трогается."}
	case DNSAbsent:
		return []string{head + "; на новом сервере его нет — после переноса клиентов он будет поставлен официальными скриптами Amnezia [скрипты " + dnsRevision() +
			"]: образ собирается FROM mvance/unbound:latest (плавающий тег, версия не закреплена), контейнер amnezia-dns в сети amnezia-dns-net с адресом 172.29.172.254, --restart always, портов наружу не открывает."}
	}
	why := m.DstDNS.Why
	if why == "" {
		why = "не проверялось"
	}
	return []string{head + "; есть ли он на новом сервере, узнать не удалось (" + why + ") — ставиться не будет, итог переноса будет «частично»."}
}

// applyDNS — исход AmneziaDNS после переноса клиентов. ok=false — на
// источнике его нет (строки в итоге не будет).
func (m *Migration) applyDNS() (RestoreOutcome, bool) {
	o := RestoreOutcome{Container: DNSContainer}
	switch m.SrcDNS.State {
	case DNSAbsent:
		return o, false
	case DNSUnknown:
		o.State, o.Err = RestoreNotWritten, errors.New("AmneziaDNS: "+m.SrcDNS.srcText()+"; на новый сервер он не ставился — проверьте docker ps -a на источнике")
		return o, true
	}
	switch m.DstDNS.State {
	case DNSPresent:
		o.State, o.Checked = RestoreDone, "AmneziaDNS на новом сервере уже был — не трогался"
		return o, true
	case DNSUnknown:
		o.State, o.Err = RestoreNotWritten, errors.New("есть ли AmneziaDNS на новом сервере, узнать не удалось — не ставился")
		return o, true
	}
	return m.dst.InstallAmneziaDNS(dnsRevision()), true
}

// InstallAmneziaDNS — установка amnezia-dns официальными скриптами ревизии
// rev: prepare_host.sh → Dockerfile → build_container.sh →
// dns/run_container.sh → два замера «запущен». configure_container.sh у
// AmneziaDNS пуст (в обеих ревизиях) и не выполняется; не пуст — отказ до
// записи. При сбое после сборки — remove_container.sh и измерение, что
// контейнера и образа нет.
func (s *Session) InstallAmneziaDNS(rev string) RestoreOutcome {
	o := RestoreOutcome{Container: DNSContainer}
	fail := func(st RestoreState, why string) RestoreOutcome {
		o.State, o.Err = st, errors.New("AmneziaDNS: "+why)
		return o
	}
	dir := "/opt/amnezia/" + DNSContainer
	vars := map[string]string{"CONTAINER_NAME": DNSContainer, "DOCKERFILE_FOLDER": dir}
	var err error
	r := func(file string) string {
		if err != nil {
			return ""
		}
		var out string
		out, err = renderFor(rev, file, vars)
		return out
	}
	prepare, dockerfile, build := r("prepare_host.sh"), r("dns/Dockerfile"), r("build_container.sh")
	run, configure, remove := r("dns/run_container.sh"), r("dns/configure_container.sh"), r("remove_container.sh")
	if err != nil {
		return fail(RestoreNotWritten, "скрипты не подготовлены: "+err.Error())
	}
	if strings.TrimSpace(configure) != "" {
		return fail(RestoreNotWritten, "configure_container.sh ревизии "+rev+" не пуст — порядок его выполнения для AmneziaDNS не проверен; не ставился")
	}
	switch st, _, _ := s.instStep(rcTail(`if command -v sudo >/dev/null 2>&1; then sudo -n true; else [ "$(id -u)" = 0 ]; fi`), nil); st {
	case stepUnknown:
		return fail(RestoreNotWritten, "права на новом сервере проверить не удалось — не ставился")
	case stepFailed:
		return fail(RestoreNotWritten, "нужен root или sudo без пароля — не ставился")
	}
	ctrs, ok1 := s.listNames("container")
	imgs, ok2 := s.listNames("image")
	if !ok1 || !ok2 {
		return fail(RestoreNotWritten, "не удалось узнать, нет ли уже на новом сервере контейнера или образа amnezia-dns — не ставился")
	}
	if hasName(strings.Join(ctrs, " "), DNSContainer) || hasName(strings.Join(imgs, " "), DNSContainer) {
		return fail(RestoreNotWritten, "на новом сервере уже есть контейнер или образ amnezia-dns — не ставился (откат удалил бы существовавший)")
	}
	type step struct {
		name, cmd, stdin string
		creates          bool
		check            func(string) string
	}
	steps := []step{
		{name: "prepare_host.sh", cmd: hostScriptCmd, stdin: prepare},
		{name: "Dockerfile", cmd: rcTail("sudo -n tee " + dir + "/Dockerfile >/dev/null"), stdin: dockerfile},
		{name: "build_container.sh", cmd: hostScriptCmd, stdin: build, creates: true},
		{name: "run_container.sh", cmd: hostScriptCmd, stdin: run},
		{name: "контейнер запущен", cmd: rcTail(`i="sudo -n docker inspect -f {{.State.Running}}/{{.RestartCount}} ` + DNSContainer +
			`" && $i && sleep ` + instSettleSeconds + ` && $i`), check: runningStable},
	}
	created := false
	for _, st := range steps {
		created = created || st.creates
		state, body, rc := s.instStep(st.cmd, []byte(st.stdin))
		why := ""
		switch state {
		case stepUnknown:
			why = "шаг «" + st.name + "»: " + s.noAnswer()
		case stepFailed:
			why = "шаг «" + st.name + "» завершился с кодом " + strconv.Itoa(rc)
		default:
			if st.check != nil {
				if w := st.check(body); w != "" {
					why = "шаг «" + st.name + "»: " + w
				}
			}
		}
		if why == "" {
			continue
		}
		if !created {
			if state == stepUnknown {
				return fail(RestoreUnknown, why+"; что успело выполниться на новом сервере — неизвестно")
			}
			return fail(RestoreNotWritten, why+"; контейнер не создавался (каталог "+dir+" и сеть amnezia-dns-net, если созданы, остаются)")
		}
		return s.dnsRollback(o, remove, why)
	}
	o.State = RestoreDone
	o.Checked = "AmneziaDNS поставлен официальными скриптами Amnezia (ревизия " + rev + ") и работает (два замера docker inspect); образ mvance/unbound:latest — версия не закреплена"
	return o
}

// dnsRollback — remove_container.sh и измерение: остались ли контейнер и
// образ amnezia-dns.
func (s *Session) dnsRollback(o RestoreOutcome, remove, why string) RestoreOutcome {
	s.instStep(hostScriptCmd, []byte(remove)) // исход — по измерению ниже
	var left []string
	unknown := false
	for _, kind := range []string{"container", "image"} {
		names, ok := s.listNames(kind)
		if !ok {
			unknown = true
			continue
		}
		if hasName(strings.Join(names, " "), DNSContainer) {
			left = append(left, map[string]string{"container": "контейнер ", "image": "образ "}[kind]+DNSContainer)
		}
	}
	switch {
	case len(left) > 0:
		o.State, o.Err = RestoreUnknown, errors.New("AmneziaDNS: "+why+"; откат НЕ удался: на новом сервере остался "+strings.Join(left, ", "))
	case unknown:
		o.State, o.Err = RestoreUnknown, errors.New("AmneziaDNS: "+why+"; откат: удалено ли всё, узнать не удалось")
	default:
		o.State, o.Err = RestoreRolledBack, errors.New("AmneziaDNS: "+why+"; снят откатом (контейнера и образа amnezia-dns нет — измерено)")
	}
	return o
}
