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

// FormatState — что известно о формате awg0.conf. Три состояния: известен
// (управление), незнакомый параметр (только просмотр), не прочитан.
type FormatState int

const (
	FormatUnreadable FormatState = iota // файла нет или не прочитан — не знаем
	FormatKnown
	FormatUnknownKey // есть ключ вне закрытого списка
)

// AWGFormat — формат awg0.conf.
type AWGFormat struct {
	State FormatState
	// Version — как у awgVersionOf: "3.1", "2", "1.5" или "" (не определено;
	// сам клиент Amnezia в этом случае тоже не угадывает).
	Version string
	Key     string // незнакомый ключ (FormatUnknownKey)
	Err     error  // причина (FormatUnreadable)
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

// ParseAWGFormat — формат текста awg0.conf. Комментарии, кроме `# Ik = …`,
// не влияют ни на что и пропускаются; секция вне [Interface]/[Peer] —
// незнакомый ключ.
func ParseAWGFormat(text string) AWGFormat {
	section := ""
	for _, line := range strings.Split(text, "\n") {
		l := strings.TrimSpace(strings.TrimRight(line, "\r"))
		switch {
		case l == "" || strings.HasPrefix(l, "#"):
			continue
		case strings.HasPrefix(l, "["):
			switch {
			case strings.EqualFold(l, "[Interface]"):
				section = "i"
			case strings.EqualFold(l, "[Peer]"):
				section = "p"
			default:
				return AWGFormat{State: FormatUnknownKey, Key: l}
			}
			continue
		}
		kv := strings.SplitN(l, "=", 2)
		if len(kv) != 2 {
			return AWGFormat{State: FormatUnknownKey, Key: l}
		}
		k := strings.TrimSpace(kv[0])
		switch section {
		case "i":
			if !awg2ServerKeys[k] {
				return AWGFormat{State: FormatUnknownKey, Key: k}
			}
		case "p":
			if !awg2PeerKeys[k] {
				return AWGFormat{State: FormatUnknownKey, Key: k}
			}
		default:
			return AWGFormat{State: FormatUnknownKey, Key: k}
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

// AWGVersionLabel — подпись протокола amnezia-awg2 по формату.
func AWGVersionLabel(f AWGFormat) string {
	switch f.State {
	case FormatUnreadable:
		return "AmneziaWG 2 (awg0.conf не прочитан — версия неизвестна)"
	case FormatUnknownKey:
		return "AmneziaWG 2 (незнакомый параметр «" + f.Key + "»)"
	}
	switch f.Version {
	case "3.1":
		return "AmneziaWG 3"
	case "2":
		return "AmneziaWG 2"
	case "1.5":
		return "AmneziaWG 1.5"
	}
	return "AmneziaWG 2 (версия параметров не определена)"
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
		return fmt.Errorf("%s: незнакомый параметр «%s» в awg0.conf — только просмотр", c.Name, f.Key)
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
// `# Ik = …`), только ключи шаблона, в его порядке; PersistentKeepalive = 25
// (нижняя граница «25-35» protocolConstants.h:215; выбор значения из
// диапазона в клиенте Amnezia не прочитан — берём фиксированное и называем).
func buildClientConfigAWG2(raw string, serverPub, host, listenPort, clientPriv, psk, clientIP string) string {
	iface := parseWgConf(raw).iface
	junk := awgSpecialJunk(raw)
	var b strings.Builder
	fmt.Fprintf(&b, "[Interface]\nAddress = %s/32\nDNS = 1.1.1.1, 1.0.0.1\nPrivateKey = %s\n", clientIP, clientPriv)
	for _, k := range awg2ClientKeys {
		v := iface[k]
		if strings.HasPrefix(k, "I") && len(k) == 2 {
			v = junk[k]
		}
		if strings.TrimSpace(v) != "" {
			fmt.Fprintf(&b, "%s = %s\n", k, v)
		}
	}
	fmt.Fprintf(&b, "\n[Peer]\nPublicKey = %s\nPresharedKey = %s\nAllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = %s:%s\nPersistentKeepalive = 25\n",
		serverPub, psk, host, listenPort)
	return b.String()
}
