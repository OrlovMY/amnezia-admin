package provision

// Подстановка переменных в официальные скрипты.
//
// Как это делает amnezia-client (94b51df и 5.1.0.6 — файлы одинаковы):
//   - client/core/utils/selfhosted/sshSession.cpp SshSession::replaceVars —
//     для каждой пары (имя, значение) по очереди QString::replace("$ИМЯ",
//     значение) по всему тексту; ни проверки значения, ни кавычек;
//   - client/core/utils/selfhosted/scriptsRegistry.cpp genBaseVars,
//     genAwgVars, genWireGuardVars, genXrayVars — источники значений;
//   - client/core/controllers/selfhosted/installController.cpp — Dockerfile
//     выгружается БЕЗ подстановки (buildContainerWorker), остальные файлы —
//     после replaceVars(base + protocol vars).
//
// Здесь — то же замещение «$ИМЯ», но:
//   - список переменных каждого файла ЗАКРЫТ: нужно ровно то, что файл
//     использует; неизвестная, лишняя или недостающая — ошибка;
//   - каждое значение проверяется по типу; символы оболочки, «$», перевод
//     строки и прочее, чем можно выйти из строки или heredoc, — ошибка;
//   - после подстановки в тексте не должно остаться ни одной `$ИМЯ`/`${ИМЯ`
//     с именем в верхнем регистре, кроме закрытого списка переменных самого
//     скрипта (их задаёт оболочка или Docker ARG, а не приложение).
// Значения в текст ошибок не попадают — только имена (HEADER_PROTECTION_KEY
// — секрет того же рода, что приватный ключ).

import (
	"encoding/base64"
	"fmt"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// kind — тип значения переменной.
type kind int

const (
	kPort       kind = iota // 1..65535, десятичное без ведущих нулей
	kContainer              // имя контейнера из закрытого списка
	kDockerDir              // /opt/amnezia/<контейнер>
	kHost                   // IP или имя хоста [a-z0-9.-]
	kIPv4                   // адрес подсети IPv4 в каноническом виде
	kPrefix                 // длина префикса 1..32
	kUint16                 // 0..65535
	kHeader                 // uint32 или диапазон "a-b" (a<=b) — H1..H4
	kNumOrRange             // uint32 или "a-b" — параметры AWG 3.1
	kToggle                 // "on"
	kIJunk                  // теги I1..I5: <b 0x..><r N><rc N><rd N><t><c>
	kWGKey                  // base64 ровно 32 байта (44 символа)
)

// rule — правило переменной в конкретном файле.
type rule struct {
	kind     kind
	optional bool // пустое значение допустимо (строка удаляется/комментарий)
	// container — для kContainer/kDockerDir: допустимое имя; "" — любой из
	// закрытого списка.
	container string
}

// fileSpec — закрытые списки файла.
type fileSpec struct {
	vars  map[string]rule // переменные приложения
	shell []string        // переменные самого скрипта (оболочка, Docker ARG)
}

// Контейнеры и папки скриптов: scriptsRegistry.cpp scriptFolder (Awg2 →
// awg, Awg → awg_legacy) и containerUtils.cpp containerToString
// ("amnezia-awg2", "amnezia-awg"; прочие — "amnezia-" + ключ в нижнем
// регистре).
var folderContainer = map[string]string{
	"awg":        "amnezia-awg2",
	"awg_legacy": "amnezia-awg",
	"wireguard":  "amnezia-wireguard",
	"xray":       "amnezia-xray",
}

// awgObf — параметры обфускации в awg/configure_container.sh (строки 17-41).
// Все необязательны: строка с пустым значением удаляется (строка 45, sed).
var awgObf = []string{
	"JUNK_PACKET_COUNT", "JUNK_PACKET_MIN_SIZE", "JUNK_PACKET_MAX_SIZE",
	"INIT_PACKET_JUNK_SIZE", "RESPONSE_PACKET_JUNK_SIZE",
	"COOKIE_REPLY_PACKET_JUNK_SIZE", "TRANSPORT_PACKET_JUNK_SIZE",
	"INIT_PACKET_MAGIC_HEADER", "RESPONSE_PACKET_MAGIC_HEADER",
	"UNDERLOAD_PACKET_MAGIC_HEADER", "TRANSPORT_PACKET_MAGIC_HEADER",
	"HEADER_PROTECTION_KEY", "CONTENT_PADDING_ADDITION", "REKEY_AFTER_TIME",
	"REKEY_TIMEOUT", "REJECT_AFTER_TIME", "KEEPALIVE_TIMEOUT",
	"MAX_HANDSHAKE_ATTEMPTS", "RANDOM_TRAILERS", "DISABLE_COOKIES",
	"SPECIAL_JUNK_1", "SPECIAL_JUNK_2", "SPECIAL_JUNK_3", "SPECIAL_JUNK_4", "SPECIAL_JUNK_5",
}

// obfKind — тип параметра обфускации.
func obfKind(name string) kind {
	switch {
	case strings.HasSuffix(name, "_MAGIC_HEADER"):
		return kHeader
	case strings.HasPrefix(name, "SPECIAL_JUNK_"):
		return kIJunk
	case name == "HEADER_PROTECTION_KEY":
		return kWGKey
	case name == "RANDOM_TRAILERS" || name == "DISABLE_COOKIES":
		return kToggle
	case name == "CONTENT_PADDING_ADDITION", name == "REKEY_AFTER_TIME", name == "REKEY_TIMEOUT",
		name == "REJECT_AFTER_TIME", name == "KEEPALIVE_TIMEOUT", name == "MAX_HANDSHAKE_ATTEMPTS":
		return kNumOrRange
	}
	return kUint16
}

var wgShellKeys = []string{"WIREGUARD_PSK", "WIREGUARD_SERVER_PRIVATE_KEY", "WIREGUARD_SERVER_PUBLIC_KEY"}

// specFor — закрытые списки файла file ревизии rev; ok=false — файла нет.
// Списки сняты с вендоренных файлов (grep `$[A-Z]`), сторож
// TestSpecMatchesScripts сверяет их с текстом заново.
func specFor(rev, file string) (fileSpec, bool) {
	r, ok := revisions[rev]
	if !ok {
		return fileSpec{}, false
	}
	if _, ok := r.Files[file]; !ok {
		return fileSpec{}, false
	}
	req := func(k kind) rule { return rule{kind: k} }
	folder, base, _ := strings.Cut(file, "/")
	if base == "" { // общие скрипты
		switch file {
		case "build_container.sh":
			return fileSpec{vars: map[string]rule{"CONTAINER_NAME": req(kContainer), "DOCKERFILE_FOLDER": req(kDockerDir)}}, true
		case "install_docker.sh":
			return fileSpec{vars: map[string]rule{}, shell: []string{"LANG"}}, true
		case "prepare_host.sh":
			return fileSpec{vars: map[string]rule{"DOCKERFILE_FOLDER": req(kDockerDir)}, shell: []string{"CUR_USER", "HOME"}}, true
		case "setup_host_firewall.sh":
			if rev == Rev5106 {
				return fileSpec{vars: map[string]rule{}, shell: []string{"R"}}, true
			}
			return fileSpec{vars: map[string]rule{}}, true
		case "remove_container.sh":
			return fileSpec{vars: map[string]rule{"CONTAINER_NAME": req(kContainer)}}, true
		}
		return fileSpec{}, false
	}
	cname := folderContainer[folder]
	cont := rule{kind: kContainer, container: cname}
	switch base {
	case "Dockerfile":
		// Dockerfile выгружается без подстановки (installController.cpp
		// buildContainerWorker); ${XRAY_RELEASE} — Docker ARG.
		if folder == "xray" {
			return fileSpec{vars: map[string]rule{}, shell: []string{"XRAY_RELEASE"}}, true
		}
		return fileSpec{vars: map[string]rule{}}, true
	case "run_container.sh":
		port := map[string]string{"awg": "AWG_SERVER_PORT", "awg_legacy": "AWG_SERVER_PORT",
			"wireguard": "WIREGUARD_SERVER_PORT", "xray": "XRAY_SERVER_PORT"}[folder]
		return fileSpec{vars: map[string]rule{"CONTAINER_NAME": cont, "SERVER_IP_ADDRESS": req(kHost), port: req(kPort)}}, true
	case "start.sh":
		switch folder {
		case "awg", "awg_legacy":
			return fileSpec{vars: map[string]rule{"AWG_SUBNET_IP": req(kIPv4), "SERVER_IP_ADDRESS": req(kHost), "WIREGUARD_SUBNET_CIDR": req(kPrefix)}}, true
		case "wireguard":
			return fileSpec{vars: map[string]rule{"WIREGUARD_SUBNET_IP": req(kIPv4), "SERVER_IP_ADDRESS": req(kHost), "WIREGUARD_SUBNET_CIDR": req(kPrefix)}}, true
		case "xray":
			return fileSpec{vars: map[string]rule{"SERVER_IP_ADDRESS": req(kHost), "XRAY_SERVER_PORT": req(kPort)}}, true
		}
	case "configure_container.sh":
		switch folder {
		case "awg":
			v := map[string]rule{"AWG_SERVER_PORT": req(kPort), "AWG_SUBNET_IP": req(kIPv4), "WIREGUARD_SUBNET_CIDR": req(kPrefix)}
			for _, n := range awgObf {
				v[n] = rule{kind: obfKind(n), optional: true}
			}
			return fileSpec{vars: v, shell: wgShellKeys}, true
		case "awg_legacy":
			// Старый AWG: пустые строки НЕ удаляются (sed нет) — Jc..H4
			// обязательны; I1..I5 — комментарии, могут быть пустыми.
			v := map[string]rule{"AWG_SERVER_PORT": req(kPort), "AWG_SUBNET_IP": req(kIPv4), "WIREGUARD_SUBNET_CIDR": req(kPrefix)}
			for _, n := range []string{"JUNK_PACKET_COUNT", "JUNK_PACKET_MIN_SIZE", "JUNK_PACKET_MAX_SIZE",
				"INIT_PACKET_JUNK_SIZE", "RESPONSE_PACKET_JUNK_SIZE", "INIT_PACKET_MAGIC_HEADER",
				"RESPONSE_PACKET_MAGIC_HEADER", "UNDERLOAD_PACKET_MAGIC_HEADER", "TRANSPORT_PACKET_MAGIC_HEADER"} {
				v[n] = rule{kind: obfKind(n)}
			}
			for i := 1; i <= 5; i++ {
				v["SPECIAL_JUNK_"+strconv.Itoa(i)] = rule{kind: kIJunk, optional: true}
			}
			return fileSpec{vars: v, shell: wgShellKeys}, true
		case "wireguard":
			return fileSpec{vars: map[string]rule{"WIREGUARD_SERVER_PORT": req(kPort), "WIREGUARD_SUBNET_IP": req(kIPv4),
				"WIREGUARD_SUBNET_CIDR": req(kPrefix)}, shell: wgShellKeys}, true
		case "xray":
			sh := []string{"KEYPAIR", "XRAY_CLIENT_ID", "XRAY_PRIVATE_KEY", "XRAY_PUBLIC_KEY", "XRAY_SHORT_ID"}
			if rev == Rev5106 {
				sh = append(sh, "XRAY_DIR", "DERIVED")
			}
			return fileSpec{vars: map[string]rule{}, shell: sh}, true
		}
	}
	return fileSpec{}, false
}

// RequiredVars — закрытый список переменных файла (имена без «$»), по
// алфавиту. ok=false — файла в ревизии нет.
func RequiredVars(rev, file string) ([]string, bool) {
	s, ok := specFor(rev, file)
	if !ok {
		return nil, false
	}
	names := make([]string, 0, len(s.vars))
	for n := range s.vars {
		names = append(names, n)
	}
	sort.Strings(names)
	return names, true
}

var (
	reDec      = regexp.MustCompile(`^(0|[1-9][0-9]*)$`)
	reHostname = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$`)
	// Теги I1..I5 AmneziaWG. Грамматика — [ПРЕДП] по документации
	// AmneziaWG (в коде установки amnezia-client значение не проверяется);
	// закрытая: незнакомый тег — ошибка, а не пропуск.
	reIJunk = regexp.MustCompile(`^(<(b 0x[0-9a-fA-F]+|r [0-9]+|rc [0-9]+|rd [0-9]+|t|c)>)+$`)
)

// dec — десятичное без ведущих нулей в [lo, hi].
func dec(s string, lo, hi uint64) bool {
	if !reDec.MatchString(s) || len(s) > 10 {
		return false
	}
	n, err := strconv.ParseUint(s, 10, 64)
	return err == nil && n >= lo && n <= hi
}

// numOrRange — "n" или "a-b" (a<=b), оба в [0, hi].
func numOrRange(s string, hi uint64) bool {
	a, b, isRange := strings.Cut(s, "-")
	if !isRange {
		return dec(s, 0, hi)
	}
	if !dec(a, 0, hi) || !dec(b, 0, hi) {
		return false
	}
	x, _ := strconv.ParseUint(a, 10, 64)
	y, _ := strconv.ParseUint(b, 10, 64)
	return x <= y
}

func knownContainer(s string) bool {
	for _, c := range folderContainer {
		if c == s {
			return true
		}
	}
	return false
}

// validate — проверка значения по правилу. Возвращает причину или "".
func validate(r rule, v string) string {
	if v == "" {
		if r.optional {
			return ""
		}
		return "пусто, а значение обязательно"
	}
	const maxU32 = 1<<32 - 1
	switch r.kind {
	case kPort:
		if dec(v, 1, 65535) {
			return ""
		}
		return "не порт 1..65535"
	case kContainer:
		if knownContainer(v) && (r.container == "" || v == r.container) {
			return ""
		}
		return "не то имя контейнера"
	case kDockerDir:
		c, ok := strings.CutPrefix(v, "/opt/amnezia/")
		if ok && knownContainer(c) && (r.container == "" || c == r.container) {
			return ""
		}
		return "не /opt/amnezia/<контейнер из закрытого списка>"
	case kHost:
		if ip := net.ParseIP(v); ip != nil && ip.String() == v {
			return ""
		}
		if len(v) <= 253 && reHostname.MatchString(v) {
			return ""
		}
		return "не IP и не имя хоста [a-z0-9.-]"
	case kIPv4:
		if ip := net.ParseIP(v); ip != nil && ip.To4() != nil && ip.String() == v {
			return ""
		}
		return "не адрес IPv4 в каноническом виде"
	case kPrefix:
		if dec(v, 1, 32) {
			return ""
		}
		return "не длина префикса 1..32"
	case kUint16:
		if dec(v, 0, 65535) {
			return ""
		}
		return "не целое 0..65535"
	case kHeader, kNumOrRange:
		if numOrRange(v, maxU32) {
			return ""
		}
		return "не целое 0..4294967295 и не диапазон a-b"
	case kToggle:
		if v == "on" {
			return ""
		}
		return "не «on»"
	case kIJunk:
		if len(v) <= 4096 && reIJunk.MatchString(v) {
			return ""
		}
		return "не последовательность тегов <b 0x..>/<r N>/<rc N>/<rd N>/<t>/<c>"
	case kWGKey:
		if len(v) == 44 {
			if b, err := base64.StdEncoding.Strict().DecodeString(v); err == nil && len(b) == 32 {
				return ""
			}
		}
		return "не ключ base64 из 32 байт"
	}
	return "тип не известен"
}

// reLeft — ссылка на переменную в верхнем регистре: $ИМЯ или ${ИМЯ.
var reLeft = regexp.MustCompile(`\$\{?([A-Z_][A-Z0-9_]*)`)

// Render — текст файла file ревизии rev с подставленными vars (ключи — имена
// без «$»). Ошибка, если: ревизии/файла нет; сумма файла не сходится;
// переменная неизвестна файлу или лишняя; обязательной нет; значение не
// прошло проверку типа; после подстановки осталась ссылка вне закрытого
// списка переменных самого скрипта.
func Render(rev, file string, vars map[string]string) (string, error) {
	data, err := Script(rev, file)
	if err != nil {
		return "", err
	}
	return render(rev, file, string(data), vars)
}

func render(rev, file, text string, vars map[string]string) (string, error) {
	spec, ok := specFor(rev, file)
	if !ok {
		return "", fmt.Errorf("для %s/%s нет списка переменных", rev, file)
	}
	for _, n := range sortedKeys(vars) {
		if _, ok := spec.vars[n]; !ok {
			return "", fmt.Errorf("%s/%s: переменная %s не входит в закрытый список файла", rev, file, n)
		}
	}
	for _, n := range sortedRuleKeys(spec.vars) {
		v, ok := vars[n]
		if !ok {
			return "", fmt.Errorf("%s/%s: нет переменной %s", rev, file, n)
		}
		if why := validate(spec.vars[n], v); why != "" {
			return "", fmt.Errorf("%s/%s: значение %s отвергнуто: %s", rev, file, n, why)
		}
	}
	if c, ok := vars["CONTAINER_NAME"]; ok {
		if d, ok := vars["DOCKERFILE_FOLDER"]; ok && d != "/opt/amnezia/"+c {
			return "", fmt.Errorf("%s/%s: DOCKERFILE_FOLDER не соответствует CONTAINER_NAME", rev, file)
		}
	}
	out := reLeft.ReplaceAllStringFunc(text, func(m string) string {
		if strings.HasPrefix(m, "${") {
			return m // приложение такую форму не подставляет
		}
		if v, ok := vars[m[1:]]; ok {
			return v
		}
		return m
	})
	shell := map[string]bool{}
	for _, n := range spec.shell {
		shell[n] = true
	}
	for _, m := range reLeft.FindAllStringSubmatch(out, -1) {
		if !shell[m[1]] {
			return "", fmt.Errorf("%s/%s: после подстановки осталась переменная %s", rev, file, m[1])
		}
	}
	return out, nil
}

func sortedKeys(m map[string]string) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

// FolderOf — папка скриптов контейнера (обратное folderContainer):
// amnezia-awg2 → awg, amnezia-awg → awg_legacy и т.д. ok=false — контейнер
// вне закрытого списка.
func FolderOf(container string) (string, bool) {
	for f, c := range folderContainer {
		if c == container {
			return f, true
		}
	}
	return "", false
}

func sortedRuleKeys(m map[string]rule) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}
