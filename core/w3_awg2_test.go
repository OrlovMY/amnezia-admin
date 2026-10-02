package core_test

// PR-W3: управление amnezia-awg2 (AWG2/AWG3). Только публичный API, что был
// и на 60057cf (PR-W1), — файл собирается там и падает ПОВЕДЕНИЕМ.

import (
	"strings"
	"testing"

	"amnezia-admin/core"
	"amnezia-admin/internal/fakesrv"
)

// awg2Iface — сервер amnezia-awg2 с [Interface] из extra (строки после
// ListenPort).
func awg2With(t *testing.T, extra string) *fakesrv.Server {
	t.Helper()
	srv := fakesrv.New()
	srv.Names = []string{"amnezia-awg2"}
	wg, _ := srv.File("/opt/amnezia/awg/wg0.conf")
	srv.DeleteFile("/opt/amnezia/awg/wg0.conf")
	srv.SetFile("/opt/amnezia/awg/awg0.conf", []byte(strings.Replace(string(wg), "ListenPort = 51820\n", "ListenPort = 51820\n"+extra, 1)))
	return srv
}

const awg3Extra = "Jc = 4\nJmin = 10\nJmax = 50\nS1 = 20\nS2 = 30\nS3 = 15\nS4 = 25\nH1 = 100-200\nH2 = 300-400\nH3 = 500-600\nH4 = 700-800\n" +
	"HeaderProtectionKey = hpk-value\nContentPaddingAddition = 10-100\nRekeyAfterTime = 100-120\nRekeyTimeout = 3-7\n" +
	"RejectAfterTime = 150-180\nKeepaliveTimeout = 5-15\nMaxHandshakeAttempts = 15-20\nRandomTrailers = on\nDisableCookies = on\n" +
	"# I1 = <r 2><b 0x8580>\n# I2 = <b 0xdead>\n"

// TestAWG2DiscoveryByFormat — доезд: подпись и управление amnezia-awg2 — по
// формату awg0.conf, найденному программой на сервере.
func TestAWG2DiscoveryByFormat(t *testing.T) {
	for _, c := range []struct {
		name, extra, proto string
		managed            bool
	}{
		{"AWG3", awg3Extra, "AmneziaWG 3", true},
		{"AWG2", "S3 = 15\nS4 = 25\nH1 = 100-200\n", "AmneziaWG 2", true},
		{"без признаков", "Jc = 4\nJmin = 10\nJmax = 50\n", "AmneziaWG 2 (версия параметров не определена)", true},
		{"незнакомый ключ", "S3 = 15\nPostUp = rm -rf /\n", "AmneziaWG 2 (незнакомый параметр «PostUp»)", false},
	} {
		t.Run(c.name, func(t *testing.T) {
			srv := awg2With(t, c.extra)
			cs, err := core.NewSessionWithRunner(srv, raceCreds()).FindContainers()
			if err != nil {
				t.Fatal(err)
			}
			if len(cs) != 1 || cs[0].Proto != c.proto || cs[0].Managed != c.managed {
				t.Errorf("%+v, ждали Proto=%q Managed=%v", cs, c.proto, c.managed)
			}
		})
	}
}

// TestAWG2ClientConfigFromServer — доезд: выданный на AWG3 конфиг собран по
// template.conf из серверного файла: параметры маскировки, I1/I2 из
// комментариев, без серверных ключей; PersistentKeepalive = 25.
func TestAWG2ClientConfigFromServer(t *testing.T) {
	srv := awg2With(t, awg3Extra)
	sess := core.NewSessionWithRunner(srv, raceCreds())
	cs, err := sess.FindContainers()
	if err != nil || len(cs) != 1 {
		t.Fatalf("%v %+v", err, cs)
	}
	u, err := sess.AddUser(&cs[0], "Carol")
	if err != nil {
		t.Fatalf("AddUser на AWG3: %v", err)
	}
	for _, want := range []string{"S3 = 15", "S4 = 25", "H1 = 100-200", "I1 = <r 2><b 0x8580>", "I2 = <b 0xdead>",
		"HeaderProtectionKey = hpk-value", "ContentPaddingAddition = 10-100", "RandomTrailers = on", "DisableCookies = on",
		"MaxHandshakeAttempts = 15-20", "PersistentKeepalive = 25", "Endpoint = 1.2.3.4:51820"} {
		if !strings.Contains(u.Config, want+"\n") {
			t.Errorf("в клиентском конфиге нет %q:\n%s", want, u.Config)
		}
	}
	for _, bad := range []string{"ListenPort", "# I1", "I3 ="} {
		if strings.Contains(u.Config, bad) {
			t.Errorf("в клиентском конфиге лишнее %q:\n%s", bad, u.Config)
		}
	}
}

// TestAWG2UnknownKeyRefusesWrite — незнакомый параметр — только просмотр:
// запись отклонена, файлы не тронуты (даже если вызывающий передал
// контейнер как управляемый).
func TestAWG2UnknownKeyRefusesWrite(t *testing.T) {
	srv := awg2With(t, "S3 = 15\nPostUp = echo x\n")
	before, _ := srv.File("/opt/amnezia/awg/awg0.conf")
	c := &core.Container{Name: "amnezia-awg2", Dir: "/opt/amnezia/awg", Proto: "awg2", Managed: true}
	_, err := core.NewSessionWithRunner(srv, raceCreds()).AddUser(c, "Carol")
	if err == nil || !strings.Contains(err.Error(), "PostUp") {
		t.Errorf("запись при незнакомом параметре: %v", err)
	}
	after, _ := srv.File("/opt/amnezia/awg/awg0.conf")
	if string(after) != string(before) {
		t.Errorf("awg0.conf изменён, хотя запись отклонена")
	}
}

// TestAWG2AllOperations — add, rename, toggle (выкл/вкл), rekey, delete на
// amnezia-awg2 записью под замком; после каждой — файлы и работающий
// сервер согласованы.
func TestAWG2AllOperations(t *testing.T) {
	srv := awg2With(t, awg3Extra)
	sess := core.NewSessionWithRunner(srv, raceCreds())
	cs, err := sess.FindContainers()
	if err != nil || len(cs) != 1 {
		t.Fatalf("%v %+v", err, cs)
	}
	c := &cs[0]
	if _, err := sess.AddUser(c, "Carol"); err != nil {
		t.Fatalf("add: %v", err)
	}
	id := func(name string) string {
		cl, err := sess.LoadClients(c)
		if err != nil {
			t.Fatal(err)
		}
		for _, x := range cl {
			if x.Name() == name {
				return x.ClientID
			}
		}
		return ""
	}
	inRuntime := func(key string) bool {
		for _, p := range srv.RuntimePeers() {
			if p == key {
				return true
			}
		}
		return false
	}
	k := id("Carol")
	if k == "" || !inRuntime(k) {
		t.Fatalf("после add Carol нет в таблице или в работающем сервере")
	}
	if err := sess.RenameUser(c, k, "Carol2"); err != nil || id("Carol2") != k {
		t.Fatalf("rename: %v", err)
	}
	if err := sess.SetEnabled(c, k, false); err != nil || inRuntime(k) {
		t.Fatalf("toggle выкл: %v (в работающем сервере %v)", err, inRuntime(k))
	}
	if err := sess.SetEnabled(c, k, true); err != nil || !inRuntime(k) {
		t.Fatalf("toggle вкл: %v", err)
	}
	if _, err := sess.RegenerateUser(c, k); err != nil {
		t.Fatalf("rekey: %v", err)
	}
	k2 := id("Carol2")
	if k2 == k || !inRuntime(k2) || inRuntime(k) {
		t.Fatalf("rekey: ключ не сменился или старый остался в работающем сервере")
	}
	if err := sess.DeleteByID(c, k2); err != nil || id("Carol2") != "" || inRuntime(k2) {
		t.Fatalf("delete: %v", err)
	}
	conf, _ := srv.File("/opt/amnezia/awg/awg0.conf")
	if !strings.Contains(string(conf), "HeaderProtectionKey = hpk-value") || !strings.Contains(string(conf), "# I1 = <r 2><b 0x8580>") {
		t.Errorf("после операций параметры AWG3 или комментарии I1 в awg0.conf потеряны:\n%s", conf)
	}
}
