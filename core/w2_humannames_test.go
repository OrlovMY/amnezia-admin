package core

import "testing"

// TestContainerHumanNames — W2 раунд 2 (решение ядра): человеческие имена
// ДОСЛОВНО из amnezia-client 94b51df, containerHumanNames в
// client/core/utils/containers/containerUtils.cpp. Исключение одно — Awg:
// «AmneziaWG (старый)» (решение ядра по awgProtocolConfig.cpp:433–439: awg2 —
// «AmneziaWG», версию суффиксом допишет W3).
func TestContainerHumanNames(t *testing.T) {
	const rev = "amnezia-client 94b51df"
	want := []struct{ enum, name string }{
		{"Awg", "AmneziaWG (старый)"}, // решение ядра, не containerHumanNames
		{"WireGuard", "WireGuard"},
		{"Awg2", "AmneziaWG"},
		{"Xray", "XRay"},
		{"OpenVpn", "OpenVPN"},
		{"ShadowSocks", "OpenVPN over SS"},
		{"Cloak", "OpenVPN over Cloak"},
		{"Ipsec", "IPsec"},
		{"SSXray", "Shadowsocks"},
		{"TorWebSite", "Website in Tor network"},
		{"Dns", "AmneziaDNS"},
		{"Sftp", "SFTP file sharing service"},
		{"Socks5Proxy", "SOCKS5 proxy server"},
		{"MtProxy", "MTProxy (Telegram)"},
		{"Telemt", "Telemt (Telegram)"},
		{"TProxy", "TProxy (Telegram WEB)"},
	}
	if len(containerTypes) != len(want) {
		t.Fatalf("типов %d, в списке %s — %d", len(containerTypes), rev, len(want))
	}
	for i, w := range want {
		ct := containerTypes[i]
		if ct.Enum != w.enum || ct.Proto != w.name {
			t.Errorf("%d: %s %q, по %s %s %q", i, ct.Enum, ct.Proto, rev, w.enum, w.name)
		}
	}
	if c, _, _ := lookupContainer("amnezia-openvpn-cloak"); c.Dir != "/opt/amnezia/cloak" {
		t.Errorf("каталог Cloak %q, по %s /opt/amnezia/cloak", c.Dir, rev)
	}
}
