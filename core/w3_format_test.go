package core

import (
	"strings"
	"testing"
)

func awgText(iface string) string {
	return "[Interface]\nPrivateKey = k\nAddress = 10.8.1.1/24\nListenPort = 51820\n" + iface +
		"\n[Peer]\nPublicKey = p\nPresharedKey = s\nAllowedIPs = 10.8.1.2/32\n"
}

// TestParseAWGFormat — версия дословно по awgVersionOf/hasAwg3Markers
// (amnezia-client dev 94b51df, awgProtocolConfig.cpp:23-65, 427-432) и
// закрытый список ключей.
func TestParseAWGFormat(t *testing.T) {
	for _, c := range []struct {
		name, iface string
		state       FormatState
		version     string
		key         string
	}{
		{"AWG3: HeaderProtectionKey", "HeaderProtectionKey = x\n", FormatKnown, "3.1", ""},
		{"AWG3: MaxHandshakeAttempts", "MaxHandshakeAttempts = 15-20\n", FormatKnown, "3.1", ""},
		{"AWG3: RandomTrailers = on", "RandomTrailers = on\n", FormatKnown, "3.1", ""},
		{"AWG3: DisableCookies = yes (не off — включено)", "DisableCookies = yes\n", FormatKnown, "3.1", ""},
		{"RandomTrailers = off — не AWG3", "RandomTrailers = off\nDisableCookies = OFF\n", FormatKnown, "", ""},
		{"RandomTrailers = off и S3 — AWG2", "RandomTrailers = off\nS3 = 15\n", FormatKnown, "2", ""},
		{"AWG2: S4", "S4 = 25\n", FormatKnown, "2", ""},
		{"AWG2: диапазон H2", "H2 = 300-400\n", FormatKnown, "2", ""},
		{"H1 числом — не AWG2", "H1 = 100\nJc = 4\n", FormatKnown, "", ""},
		{"1.5: только I1 комментарием", "# I1 = <b 0x01>\n", FormatKnown, "1.5", ""},
		{"пустой # I1 — не 1.5", "# I1 = \n", FormatKnown, "", ""},
		{"чужой комментарий — не мешает", "# что-то\nJc = 4\n", FormatKnown, "", ""},
		{"незнакомый ключ", "S3 = 1\nPostUp = x\n", FormatUnknownKey, "", "PostUp"},
		{"I1 ключом, а не комментарием — незнакомый", "I1 = x\n", FormatUnknownKey, "", "I1"},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := ParseAWGFormat(awgText(c.iface))
			if f.State != c.state || f.Version != c.version || f.Key != c.key {
				t.Errorf("%+v, ждали состояние %d, версия %q, ключ %q", f, c.state, c.version, c.key)
			}
		})
	}
	if f := ParseAWGFormat(awgText("") + "[Other]\nX = 1\n"); f.State != FormatUnknownKey {
		t.Errorf("незнакомая секция: %+v", f)
	}
	if f := ParseAWGFormat("[Interface]\nPrivateKey = k\n\n[Peer]\nPublicKey = p\nEndpoint = 1.2.3.4:1\n"); f.State != FormatUnknownKey || f.Key != "Endpoint" {
		t.Errorf("незнакомый ключ [Peer]: %+v", f)
	}
}

// TestParseAWGFormatNotKnown — QA W3 (признак 2), SEC W3-R1, W3-R2: файл,
// по которому нельзя сказать «формат известен», — только просмотр с
// причиной. Ни подпись, ни причина не несут значения из файла.
func TestParseAWGFormatNotKnown(t *testing.T) {
	const secret = "SECRETKEYxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
	long := strings.Repeat("A", 40)
	for _, c := range []struct {
		name, text string
		state      FormatState
		reason     string
	}{
		{"файл пуст", "", FormatIncomplete, "файл настроек сервера пуст"},
		{"только перевод строки", "\n", FormatIncomplete, "файл настроек сервера пуст"},
		{"без [Interface]", "[Peer]\nPublicKey = p\n", FormatIncomplete, "нет секции [Interface]"},
		{"без PrivateKey", "[Interface]\nAddress = 10.8.1.1/24\nListenPort = 1\n", FormatIncomplete, "нет параметра «PrivateKey»"},
		{"без Address", "[Interface]\nPrivateKey = k\nListenPort = 1\n", FormatIncomplete, "нет параметра «Address»"},
		{"без ListenPort", "[Interface]\nPrivateKey = k\nAddress = a\n", FormatIncomplete, "нет параметра «ListenPort»"},
		{"\\r в значении", awgText("Jc = 4\r\n"), FormatUnknownKey, "строка 5 содержит управляющий символ"},
		{"нулевой байт", awgText("Jc = 4\x00\n"), FormatUnknownKey, "управляющий символ"},
		{"строка без =", "[Interface]\nPrivateKey " + secret + "\n", FormatUnknownKey, "строка 2 без «=»"},
		{"длинное имя", awgText(long + " = x\n"), FormatUnknownKey, "строка 5 — незнакомый параметр"},
		{"имя с ключом внутри", awgText("PrivateKey" + secret + " = x\n"), FormatUnknownKey, "незнакомый параметр"},
		{"вторая [Interface]", awgText("") + "[Interface]\nPrivateKey = k\n", FormatUnknownKey, "вторая секция [Interface]"},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := ParseAWGFormat(c.text)
			if f.State != c.state || !strings.Contains(f.Reason, c.reason) {
				t.Errorf("%+v, ждали состояние %d, причина ⊃ %q", f, c.state, c.reason)
			}
			l := AWGVersionLabel(f)
			if !strings.Contains(l, "— только просмотр: ") || strings.Contains(l, "SECRET") || strings.Contains(l, long) {
				t.Errorf("подпись %q: нет «только просмотр» или есть значение из файла", l)
			}
			if err := checkAWG2Writable(&Container{Name: "amnezia-awg2", Dir: "/opt/amnezia/awg"}, c.text); err == nil || strings.Contains(err.Error(), "SECRET") {
				t.Errorf("запись: %v", err)
			}
		})
	}
}

// TestAWG2Keepalive — scriptsRegistry.cpp:260-261: для 3.1 — «25-35»,
// иначе «25».
func TestAWG2Keepalive(t *testing.T) {
	for iface, want := range map[string]string{
		"HeaderProtectionKey = x\n": "PersistentKeepalive = 25-35\n",
		"S3 = 15\n":                 "PersistentKeepalive = 25\n",
		"Jc = 4\n":                  "PersistentKeepalive = 25\n",
	} {
		got := buildClientConfigAWG2(awgText(iface), "spub", "h", "1", "cpriv", "psk", "10.8.1.9")
		if !strings.HasSuffix(got, want) {
			t.Errorf("%q: конфиг кончается не на %q:\n%s", iface, want, got)
		}
	}
}

// TestAWGVersionLabel — подписи; «не определено» не выдаётся за «AWG2».
func TestAWGVersionLabel(t *testing.T) {
	for f, want := range map[AWGFormat]string{
		{State: FormatKnown, Version: "3.1"}: "AmneziaWG (версия 3.1)",
		{State: FormatKnown, Version: "2"}:   "AmneziaWG (версия 2)",
		{State: FormatKnown, Version: "1.5"}: "AmneziaWG (версия 1.5)",
		{State: FormatKnown}:                 "AmneziaWG (версия параметров не определена)",
		{State: FormatUnknownKey, Key: "X", Reason: "на сервере незнакомый параметр «X»"}: "AmneziaWG — только просмотр: на сервере незнакомый параметр «X»",
		{State: FormatIncomplete, Reason: "файл настроек сервера пуст"}:                   "AmneziaWG — только просмотр: файл настроек сервера пуст",
		{State: FormatUnreadable}: "AmneziaWG (версия неизвестна) — только просмотр: файл настроек сервера не прочитан",
	} {
		if got := AWGVersionLabel(f); got != want {
			t.Errorf("%+v: %q, ждали %q", f, got, want)
		}
	}
}

// TestAWG2ClientKeysMatchTemplate — ключи клиентского конфига — ровно
// [Interface] template.conf:5-29 (amnezia-client dev 94b51df), в его порядке.
func TestAWG2ClientKeysMatchTemplate(t *testing.T) {
	const template = "Jc Jmin Jmax S1 S2 S3 S4 H1 H2 H3 H4 I1 I2 I3 I4 I5 HeaderProtectionKey ContentPaddingAddition " +
		"RekeyAfterTime RekeyTimeout RejectAfterTime KeepaliveTimeout MaxHandshakeAttempts RandomTrailers DisableCookies"
	if got := strings.Join(awg2ClientKeys, " "); got != template {
		t.Errorf("ключи клиента:\n%s\nждали (template.conf):\n%s", got, template)
	}
}

// TestAWG2NoteOnIssue — строка честности приходит с конфигом amnezia-awg2 и
// не приходит с amnezia-awg.
func TestAWG2NoteOnIssue(t *testing.T) {
	text := awgText("S3 = 15\n")
	raw := buildClientConfigAWG2(text, "spub", "h", "1", "cpriv", "psk", "10.8.1.9")
	if !strings.Contains(raw, "S3 = 15") {
		t.Fatalf("конфиг: %s", raw)
	}
	if AWG2ConfigNote == "" || !strings.Contains(AWG2ConfigNote, "приложении Amnezia") {
		t.Errorf("строка честности пуста или не говорит, где выдать конфиг: %q", AWG2ConfigNote)
	}
}
