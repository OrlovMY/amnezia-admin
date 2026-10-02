package core

// AWG2/AWG3 (PR-W3, проект БК-ПРОТОКОЛЫ-AWG2-XRAY, Р3-1, Р3-2): формат
// awg0.conf контейнера amnezia-awg2, версия параметров и клиентский конфиг.
//
// Источник — amnezia-client dev 94b51df (прочитано дословно):
//   - client/core/models/protocols/awgProtocolConfig.cpp:23-65 — hasAwg3Markers,
//     awgVersionOf; :427-432 — isToggleEnabled (непустое и не "off" без учёта
//     регистра);
//   - client/core/utils/constants/protocolConstants.h:205-219 — "1.5", "2",
//     "3.1", awgBoolOff = "off";
//   - client/server_scripts/awg/configure_container.sh:12-45 — ключи
//     [Interface] awg0.conf, I1-I5 комментариями `# Ik = …`, пустые строки
//     удаляются;
//   - client/server_scripts/awg/template.conf:1-36 — клиентский шаблон.

import (
	"fmt"
	"regexp"
	"strings"
)

// FormatState — что известно о формате awg0.conf. Известен — управление;
// всё прочее — только просмотр с причиной (AWGFormat.Reason).
type FormatState int

const (
	FormatUnreadable FormatState = iota // файла нет или не прочитан — не знаем
	FormatKnown
	FormatUnknownKey // есть ключ вне закрытого списка, управляющий символ или непонятная строка
	FormatIncomplete // файл пуст, нет [Interface] или обязательного параметра
)

// AWGFormat — формат awg0.conf.
type AWGFormat struct {
	State FormatState
	// Version — как у awgVersionOf: "3.1", "2", "1.5" или "" (не определено;
	// сам клиент Amnezia в этом случае тоже не угадывает). Для
	// FormatUnreadable — пусто и не значит «не определено».
	Version string
	// Key — имя незнакомого параметра, только если оно похоже на имя (буквы,
	// цифры, «_», не длиннее awgKeyMax); иначе пусто, а причина — номер
	// строки. Значения параметров никогда не попадают ни сюда, ни в Reason
	// (SEC W3-R2: испорченная строка может нести PrivateKey).
	Key    string
	Reason string // причина «только просмотр» по-человечески; "" у FormatKnown
	Err    error  // причина (FormatUnreadable)
}

// awg2ServerKeys — ЗАКРЫТЫЙ список ключей [Interface] awg0.conf
// (configure_container.sh:13-36). Ключ вне списка — FormatUnknownKey.
var awg2ServerKeys = map[string]bool{
	"PrivateKey": true, "Address": true, "ListenPort": true,
	"Jc": true, "Jmin": true, "Jmax": true,
	"S1": true, "S2": true, "S3": true, "S4": true,
	"H1": true, "H2": true, "H3": true, "H4": true,
	"HeaderProtectionKey": true, "ContentPaddingAddition": true,
	"RekeyAfterTime": true, "RekeyTimeout": true, "RejectAfterTime": true,
	"KeepaliveTimeout": true, "MaxHandshakeAttempts": true,
	"RandomTrailers": true, "DisableCookies": true,
}

// awg2PeerKeys — закрытый список ключей [Peer] сервера.
var awg2PeerKeys = map[string]bool{"PublicKey": true, "PresharedKey": true, "AllowedIPs": true}

// reAWGComment — комментарий `# Ik = значение` (configure_container.sh:37-41).
var reAWGComment = regexp.MustCompile(`^#\s*I([1-5])\s*=\s*(.*)$`)

// awgKeyMax — предел длины имени параметра в подписи и ошибке.
const awgKeyMax = 32

var reAWGKeyName = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]*$`)

// awg2Required — без них сервер amnezia-awg2 не работает; нет любого —
// формат не известен (QA W3, признак 2).
var awg2Required = []string{"PrivateKey", "Address", "ListenPort"}

// hasControl — управляющий символ (кроме табуляции) в строке.
func hasControl(s string) bool {
	for _, r := range s {
		if (r < 0x20 && r != '\t') || r == 0x7f {
			return true
		}
	}
	return false
}

// ParseAWGFormat — формат текста awg0.conf. Комментарии, кроме `# Ik = …`,
// пропускаются. Известен файл только тогда, когда в нём есть [Interface] с
// PrivateKey, Address и ListenPort и всё остальное — из закрытых списков.
func ParseAWGFormat(text string) AWGFormat {
	unknown := func(n int, key, what string) AWGFormat {
		f := AWGFormat{State: FormatUnknownKey}
		if key != "" && len(key) <= awgKeyMax && reAWGKeyName.MatchString(key) {
			f.Key = key
			f.Reason = "на сервере незнакомый параметр «" + key + "»"
		} else {
			f.Reason = fmt.Sprintf("в файле настроек сервера строка %d %s", n, what)
		}
		return f
	}
	section := ""
	seenIface := false
	ifaceKeys := map[string]bool{}
	for i, line := range strings.Split(text, "\n") {
		n := i + 1
		if hasControl(line) {
			return unknown(n, "", "содержит управляющий символ")
		}
		l := strings.TrimSpace(line)
		switch {
		case l == "" || strings.HasPrefix(l, "#"):
			continue
		case strings.HasPrefix(l, "["):
			switch {
			case strings.EqualFold(l, "[Interface]"):
				if seenIface {
					return unknown(n, "", "— вторая секция [Interface]")
				}
				section, seenIface = "i", true
			case strings.EqualFold(l, "[Peer]"):
				section = "p"
			default:
				return unknown(n, "", "— незнакомая секция")
			}
			continue
		}
		kv := strings.SplitN(l, "=", 2)
		if len(kv) != 2 {
			return unknown(n, "", "без «=»")
		}
		k := strings.TrimSpace(kv[0])
		switch section {
		case "i":
			if !awg2ServerKeys[k] {
				return unknown(n, k, "— незнакомый параметр")
			}
			ifaceKeys[k] = true
		case "p":
			if !awg2PeerKeys[k] {
				return unknown(n, k, "— незнакомый параметр")
			}
		default:
			return unknown(n, "", "— параметр вне секции")
		}
	}
	switch {
	case strings.TrimSpace(text) == "":
		return AWGFormat{State: FormatIncomplete, Reason: "файл настроек сервера пуст"}
	case !seenIface:
		return AWGFormat{State: FormatIncomplete, Reason: "в файле настроек сервера нет секции [Interface]"}
	}
	for _, k := range awg2Required {
		if !ifaceKeys[k] {
			return AWGFormat{State: FormatIncomplete, Reason: "в файле настроек сервера нет параметра «" + k + "»"}
		}
	}
	return AWGFormat{State: FormatKnown, Version: awgVersionOf(parseWgConf(text).iface, awgSpecialJunk(text))}
}

// isToggleEnabled — как AwgProtocolConfig::isToggleEnabled
// (awgProtocolConfig.cpp:427-432): непустое и не "off" без учёта регистра.
func isToggleEnabled(v string) bool {
	v = strings.TrimSpace(v)
	return v != "" && !strings.EqualFold(v, "off")
}

// awgVersionOf — дословно awgVersionOf/hasAwg3Markers (awgProtocolConfig.cpp:
// 23-65): признак AWG3 → "3.1"; S3/S4 непусты или H1-H4 содержат «-» → "2";
// I1-I5 непусты → "1.5"; иначе "" (не определено).
func awgVersionOf(iface map[string]string, junk map[string]string) string {
	has := func(k string) bool { return strings.TrimSpace(iface[k]) != "" }
	for _, k := range []string{"HeaderProtectionKey", "ContentPaddingAddition", "RekeyAfterTime",
		"RekeyTimeout", "RejectAfterTime", "KeepaliveTimeout", "MaxHandshakeAttempts"} {
		if has(k) {
			return "3.1"
		}
	}
	if isToggleEnabled(iface["RandomTrailers"]) || isToggleEnabled(iface["DisableCookies"]) {
		return "3.1"
	}
	if has("S3") || has("S4") {
		return "2"
	}
	for _, k := range []string{"H1", "H2", "H3", "H4"} {
		if strings.Contains(iface[k], "-") {
			return "2"
		}
	}
	for i := 1; i <= 5; i++ {
		if strings.TrimSpace(junk[fmt.Sprintf("I%d", i)]) != "" {
			return "1.5"
		}
	}
	return ""
}

// awgSpecialJunk — I1-I5 из комментариев `# Ik = значение` [Interface].
func awgSpecialJunk(text string) map[string]string {
	out := map[string]string{}
	inIface := false
	for _, line := range strings.Split(text, "\n") {
		l := strings.TrimSpace(strings.TrimRight(line, "\r"))
		switch {
		case strings.EqualFold(l, "[Interface]"):
			inIface = true
		case strings.HasPrefix(l, "["):
			inIface = false
		case inIface:
			if m := reAWGComment.FindStringSubmatch(l); m != nil && strings.TrimSpace(m[2]) != "" {
				out["I"+m[1]] = strings.TrimSpace(m[2])
			}
		}
	}
	return out
}

// AWGName — имя протокола amnezia-awg2 (решение ядра, W3 раунд 2, по
// awgProtocolConfig.cpp:433-439): «AmneziaWG», версия параметров — в
// скобках. Версия пишется ТОЛЬКО у известного формата: при незнакомом ключе,
// неполном или непрочитанном файле — просто «AmneziaWG» (решения ядра при
// сведении W2+W3 и AU-UX Л1: «(версия неизвестна) — только просмотр» звучало
// как управляемое «(версия параметров не определена)»).
// Старый контейнер amnezia-awg подписан «AmneziaWG (старый)» (containerTypes).
func AWGName(f AWGFormat) string {
	switch f.State {
	case FormatKnown:
		switch f.Version {
		case "3.1", "2", "1.5":
			return "AmneziaWG (версия " + f.Version + ")"
		}
		return "AmneziaWG (версия параметров не определена)"
	}
	return "AmneziaWG"
}

// AWGReason — причина «только просмотр» для amnezia-awg2; "" у FormatKnown.
func AWGReason(f AWGFormat) string {
	switch f.State {
	case FormatKnown:
		return ""
	case FormatUnreadable:
		return "файл настроек сервера не прочитан"
	}
	if f.Reason == "" {
		return "формат файла настроек сервера не распознан"
	}
	return f.Reason
}

// AWGVersionLabel — полная подпись amnezia-awg2 так, как её покажет
// guiview.ProtoLabel: AWGName, а для не известного формата —
// «… — только просмотр: <AWGReason>». Совпадение с ProtoLabel сторожит
// TestAWG2LabelSameAsProtoLabel.
func AWGVersionLabel(f AWGFormat) string {
	if r := AWGReason(f); r != "" {
		return AWGName(f) + " — только просмотр: " + r
	}
	return AWGName(f)
}

// AWGFormatOf — формат awg0.conf контейнера (только для amnezia-awg2).
func (s *Session) AWGFormatOf(c *Container) AWGFormat {
	text, err := s.catConf(c)
	if err != nil {
		return AWGFormat{State: FormatUnreadable, Err: err}
	}
	return ParseAWGFormat(text)
}

// isAWG2 — контейнер — amnezia-awg2 (AWG2/AWG3).
func isAWG2(c *Container) bool {
	f, err := WGFamilyOf(c)
	return err == nil && f.File == "awg0.conf"
}

// checkAWG2Writable — перед любым планом записи на amnezia-awg2: формат
// прочитанного awg0.conf обязан быть известен. Незнакомый ключ — отказ
// («только просмотр»): что он значит, программа не знает, и выдавать с ним
// конфиги или переписывать файл нельзя.
func checkAWG2Writable(c *Container, raw string) error {
	if !isAWG2(c) {
		return nil
	}
	f := ParseAWGFormat(raw)
	if f.State != FormatKnown {
		return fmt.Errorf("%s: только просмотр — %s", c.Name, f.Reason)
	}
	return nil
}

// awg2ClientKeys — ключи [Interface] клиентского шаблона
// (template.conf:5-29) в его порядке; параметр сервера вне этого списка в
// клиентский конфиг не переносится.
var awg2ClientKeys = []string{"Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4", "H1", "H2", "H3", "H4",
	"I1", "I2", "I3", "I4", "I5",
	"HeaderProtectionKey", "ContentPaddingAddition", "RekeyAfterTime", "RekeyTimeout",
	"RejectAfterTime", "KeepaliveTimeout", "MaxHandshakeAttempts", "RandomTrailers", "DisableCookies"}

// AWG2ConfigNote — строка честности при выдаче конфига amnezia-awg2 (Р3-2):
// параметры маскировки взяты из файла сервера, а клиент Amnezia собирает их
// из настроек на устройстве администратора; расхождение с сервера не видно.
const AWG2ConfigNote = "Параметры маскировки взяты из файла сервера. Если вы меняли их в приложении Amnezia после установки протокола и приложение не обновило сервер, конфиг может не подключиться — тогда выдайте его в приложении Amnezia."

// buildClientConfigAWG2 — клиентский .conf amnezia-awg2 по template.conf:
// параметры маскировки — из серверного [Interface] (I1-I5 — из комментариев
// `# Ik = …`), только ключи шаблона, в его порядке. PersistentKeepalive —
// как в клиенте (scriptsRegistry.cpp:260-261): для версии 3.1 литерально
// «25-35», иначе «25».
func buildClientConfigAWG2(raw string, serverPub, host, listenPort, clientPriv, psk, clientIP string) string {
	iface := parseWgConf(raw).iface
	junk := awgSpecialJunk(raw)
	keepalive := "25"
	if awgVersionOf(iface, junk) == "3.1" {
		keepalive = "25-35"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "[Interface]\nAddress = %s/32\nDNS = 1.1.1.1, 1.0.0.1\nPrivateKey = %s\n", clientIP, clientPriv)
	for _, k := range awg2ClientKeys {
		v := iface[k]
		if strings.HasPrefix(k, "I") && len(k) == 2 {
			v = junk[k]
		}
		// AU-LOGIC L1: RandomTrailers/DisableCookies = off клиент Amnezia
		// заменяет пустым значением, и строки в конфиге нет
		// (scriptsRegistry.cpp:270-272) — так же и здесь.
		if (k == "RandomTrailers" || k == "DisableCookies") && !isToggleEnabled(v) {
			continue
		}
		if strings.TrimSpace(v) != "" {
			fmt.Fprintf(&b, "%s = %s\n", k, v)
		}
	}
	fmt.Fprintf(&b, "\n[Peer]\nPublicKey = %s\nPresharedKey = %s\nAllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = %s:%s\nPersistentKeepalive = %s\n",
		serverPub, psk, host, listenPort, keepalive)
	return b.String()
}
