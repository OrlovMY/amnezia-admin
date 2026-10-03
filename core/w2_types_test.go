package core

import (
	"strings"
	"testing"
)

// TestContainerTypesComplete — закрытый список по amnezia-client (dev
// 94b51df, containerUtils.cpp): ровно 16 значений перечисления, каждое один
// раз; первое имя — особый случай или правило "amnezia-" + имя в нижнем
// регистре; имена не повторяются; синонимы — только ikev2 и tor.
func TestContainerTypesComplete(t *testing.T) {
	enums := []string{"Awg", "WireGuard", "Awg2", "Xray", "OpenVpn", "ShadowSocks", "Cloak", "Ipsec",
		"SSXray", "TorWebSite", "Dns", "Sftp", "Socks5Proxy", "MtProxy", "Telemt", "TProxy"}
	special := map[string]string{"Cloak": "amnezia-openvpn-cloak", "Awg": "amnezia-awg", "Awg2": "amnezia-awg2"}
	if len(containerTypes) != len(enums) {
		t.Fatalf("типов %d, ожидалось %d (%s)", len(containerTypes), len(enums), amneziaClientRevision)
	}
	seen := map[string]bool{}
	for i, ct := range containerTypes {
		if ct.Enum != enums[i] {
			t.Errorf("[%d] %s, ожидалось %s (порядок типов фиксирован)", i, ct.Enum, enums[i])
		}
		want := "amnezia-" + strings.ToLower(ct.Enum)
		if s, ok := special[ct.Enum]; ok {
			want = s
		}
		if ct.Names[0] != want {
			t.Errorf("%s: имя %q, по исходникам %q", ct.Enum, ct.Names[0], want)
		}
		for _, n := range ct.Names {
			if seen[n] {
				t.Errorf("имя %s повторяется", n)
			}
			seen[n] = true
		}
		if ct.Proto == "" {
			t.Errorf("%s: нет подписи", ct.Enum)
		}
	}
	for _, syn := range []string{"amnezia-ikev2", "amnezia-tor"} {
		if !seen[syn] {
			t.Errorf("синоним %s потерян", syn)
		}
	}
	if len(seen) != 18 {
		t.Errorf("имён %d, ожидалось 16 + 2 синонима", len(seen))
	}
}
