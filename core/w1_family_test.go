package core_test

// PR-W1: запись A3б для семейства WG. Только публичный API и fakesrv.New()
// с ручной подготовкой — файл собирается на e1c942b и падает там ПОВЕДЕНИЕМ.

import (
	"strings"
	"testing"

	"amnezia-admin/core"
	"amnezia-admin/internal/fakesrv"
)

// awg2Server — fakesrv с одним контейнером amnezia-awg2: /opt/amnezia/awg/
// awg0.conf (параметры AWG2 в [Interface]) и clientsTable; wg0.conf нет.
func awg2Server(t *testing.T) *fakesrv.Server {
	t.Helper()
	srv := fakesrv.New()
	srv.Names = []string{"amnezia-awg2"}
	wg, ok := srv.File("/opt/amnezia/awg/wg0.conf")
	if !ok {
		t.Fatal("в fakesrv.New нет wg0.conf")
	}
	srv.DeleteFile("/opt/amnezia/awg/wg0.conf")
	awg := strings.Replace(string(wg), "ListenPort = 51820\n",
		"ListenPort = 51820\nJc = 4\nJmin = 10\nJmax = 50\nS1 = 20\nS2 = 30\nS3 = 15\nS4 = 25\nH1 = 100-200\nH2 = 300-400\nH3 = 500-600\nH4 = 700-800\n", 1)
	srv.SetFile("/opt/amnezia/awg/awg0.conf", []byte(awg))
	return srv
}

func findAWG2(t *testing.T, sess *core.Session) *core.Container {
	t.Helper()
	cs, err := sess.FindContainers()
	if err != nil {
		t.Fatalf("FindContainers: %v", err)
	}
	for i := range cs {
		if cs[i].Name == "amnezia-awg2" {
			return &cs[i]
		}
	}
	t.Fatalf("amnezia-awg2 не найден: %+v", cs)
	return nil
}

// TestAWG2DiscoveryDir — каталог amnezia-awg2 — /opt/amnezia/awg (исходники
// amnezia-client), а не угаданный по суффиксу /opt/amnezia/awg2. Управление
// (Managed) включает PR-W3.
func TestAWG2DiscoveryDir(t *testing.T) {
	srv := awg2Server(t)
	c := findAWG2(t, core.NewSessionWithRunner(srv, raceCreds()))
	if c.Dir != "/opt/amnezia/awg" {
		t.Errorf("каталог amnezia-awg2 = %q, ждали /opt/amnezia/awg", c.Dir)
	}
	// PR-W3 (после сведения с W2): формат awg0.conf известен (S3/S4,
	// диапазоны H) — «поддерживается», Proto — имя с версией.
	if !c.Managed() || c.Proto != "AmneziaWG (версия 2)" {
		t.Errorf("amnezia-awg2 с известным форматом: Managed=%v, Proto=%q (ждали true, «AmneziaWG (версия 2)»)", c.Managed(), c.Proto)
	}
}

// TestAWG2WriteFamily — доезд записи A3б на amnezia-awg2: добавление пишет
// awg0.conf (а не wg0.conf), применяет его `awg syncconf awg0`, проверяет
// `awg show awg0 dump`. Файлы и работающий сервер согласованы, wg0.conf не
// создан.
func TestAWG2WriteFamily(t *testing.T) {
	srv := awg2Server(t)
	sess := core.NewSessionWithRunner(srv, raceCreds())
	// Managed=true — как включит PR-W3 после определения формата; здесь
	// проверяется путь ЗАПИСИ (файл, утилита, интерфейс из таблицы).
	c := &core.Container{Name: "amnezia-awg2", Dir: "/opt/amnezia/awg", Proto: "awg2", Support: core.SupportYes}
	u, err := sess.AddUser(c, "Carol")
	if err != nil {
		t.Fatalf("AddUser на amnezia-awg2: %v", err)
	}
	awg, _ := srv.File("/opt/amnezia/awg/awg0.conf")
	clients, err := sess.LoadClients(c)
	if err != nil {
		t.Fatal(err)
	}
	id := ""
	for _, cl := range clients {
		if cl.Name() == "Carol" {
			id = cl.ClientID
		}
	}
	if id == "" || !strings.Contains(string(awg), "PublicKey = "+id) {
		t.Errorf("Carol нет в clientsTable или её peer'а нет в awg0.conf")
	}
	if !strings.Contains(string(awg), "S3 = 15") || !strings.Contains(string(awg), "H1 = 100-200") {
		t.Errorf("параметры AWG2 в [Interface] потеряны при записи")
	}
	if _, ok := srv.File("/opt/amnezia/awg/wg0.conf"); ok {
		t.Errorf("создан wg0.conf рядом с awg0.conf — записан не тот файл")
	}
	inRuntime := false
	for _, p := range srv.RuntimePeers() {
		if p == id {
			inRuntime = true
		}
	}
	if !inRuntime {
		t.Errorf("peer Carol не применён к работающему серверу (awg syncconf)")
	}
	if u == nil {
		t.Errorf("конфиг клиента не выдан")
	}
}
