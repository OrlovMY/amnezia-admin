package core_test

// QR по размерам конфига (находка владельца 12.10.2026: «Конфиг готов» на
// AmneziaWG 2 — «Не удалось построить QR-код»). Конфиги AWG2 собираются
// БОЕВЫМ путём — AddUser на fakesrv с awg0.conf, где I1 длинный, как
// пакет маскировки. На 699ab55 (только уровень M, предел 2331 байт)
// случай «AWG2, длинный I1» падает ПОВЕДЕНИЕМ: ошибка вместо QR, а
// «слишком большой» — безымянной ошибкой без размеров.

import (
	"errors"
	"strings"
	"testing"

	"amnezia-admin/core"
)

// awg2Config — клиентский конфиг AWG2, выданный AddUser, при I1 из n
// шестнадцатеричных знаков.
func awg2Config(t *testing.T, n int) string {
	t.Helper()
	extra := strings.Replace(awg3Extra, "# I1 = <r 2><b 0x8580>", "# I1 = <r 2><b 0x"+strings.Repeat("c7", n/2)+">", 1)
	sess := core.NewSessionWithRunner(awg2With(t, extra), raceCreds())
	cs, err := sess.FindContainers()
	if err != nil || len(cs) != 1 {
		t.Fatalf("%v %+v", err, cs)
	}
	u, err := sess.AddUser(&cs[0], "Carol")
	if err != nil {
		t.Fatalf("AddUser на AWG2: %v", err)
	}
	return u.QRText()
}

func TestQRBySize(t *testing.T) {
	wg := "[Interface]\nPrivateKey = " + strings.Repeat("A", 43) + "=\nAddress = 10.8.1.5/32\nDNS = 1.1.1.1, 1.0.0.1\n\n" +
		"[Peer]\nPublicKey = " + strings.Repeat("B", 43) + "=\nPresharedKey = " + strings.Repeat("C", 43) + "=\n" +
		"AllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = 203.0.113.10:51820\nPersistentKeepalive = 25\n"
	awg := strings.Replace(wg, "DNS", "Jc = 4\nJmin = 10\nJmax = 50\nS1 = 20\nS2 = 30\nH1 = 1\nH2 = 2\nH3 = 3\nH4 = 4\nDNS", 1)
	for _, c := range []struct {
		name    string
		text    string
		tooBig  bool // ждём *QRTooLargeError (свойство конфига, не сбой)
		minSize int  // проверка ничего не значит, если конфиг меньше
	}{
		{"WireGuard", wg, false, 200},
		{"AmneziaWG", awg, false, 300},
		{"AWG2, короткий I1", awg2Config(t, 4), false, 400},
		{"AWG2, длинный I1 (больше предела M 2331)", awg2Config(t, 2000), false, 2332},
		{"ровно предел", strings.Repeat("x", core.QRMaxBytes), false, core.QRMaxBytes},
		{"на байт больше предела", strings.Repeat("x", core.QRMaxBytes+1), true, 0},
		{"AWG2, огромный I1", awg2Config(t, 6000), true, 6000},
	} {
		t.Run(c.name, func(t *testing.T) {
			if len(c.text) < c.minSize {
				t.Fatalf("проверка ничего не значит: конфиг %d байт < %d", len(c.text), c.minSize)
			}
			png, err := core.QRPNG(c.text, 256)
			t.Logf("%d байт: err=%v", len(c.text), err)
			var big *core.QRTooLargeError
			switch {
			case c.tooBig && !errors.As(err, &big):
				t.Fatalf("ждали «слишком большой» с размерами, получили %v", err)
			case c.tooBig && (big.Len != len(c.text) || big.Max != core.QRMaxBytes ||
				!strings.Contains(err.Error(), "слишком большой") || strings.Contains(err.Error(), c.text[:20])):
				t.Fatalf("ошибка без размеров или с содержимым: %v", err)
			case !c.tooBig && (err != nil || len(png) == 0):
				t.Fatalf("QR не построен: %v", err)
			}
		})
	}
}
