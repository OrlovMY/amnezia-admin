package core

// Долги У2/У3 (ДОЛГИ-ПРОДУКТ, 30.09.2026): порт и подсеть в wg0.conf не
// угадываются. Тесты пользуются только API c65420e (AddUser, RegenerateUser,
// fakesrv) и падают там поведением: add и rekey подставляли 51820 и 10.8.1.

import (
	"fmt"
	"regexp"
	"strings"
	"testing"

	"amnezia-admin/internal/fakesrv"
)

const debtsWg0 = "/opt/amnezia/awg/wg0.conf"

var reListenPort = regexp.MustCompile(`(?m)^ListenPort = .*\n`)

// debtsServer — fakesrv, у которого в wg0.conf заменён ListenPort (пустая
// строка — строки нет вовсе).
func debtsServer(t *testing.T, port string) *fakesrv.Server {
	t.Helper()
	srv := fakesrv.New()
	wg0, _ := srv.File(debtsWg0)
	if !reListenPort.Match(wg0) {
		t.Fatal("проверка ПЕРЕСТАЛА ЧТО-ЛИБО ЗНАЧИТЬ: в wg0.conf fakesrv нет ListenPort")
	}
	repl := ""
	if port != "" {
		repl = "ListenPort = " + port + "\n"
	}
	srv.SetFile(debtsWg0, reListenPort.ReplaceAll(wg0, []byte(repl)))
	return srv
}

// TestDebtsListenPortNotGuessed — ТЕСТ РАЗЛИЧЕНИЯ и ДОЕЗДА (боевой путь
// через Session и fakesrv) для add и rekey: указанный порт уходит в конфиг
// клиента как есть; не указанный — отказ, и на сервере ничего не изменено.
func TestDebtsListenPortNotGuessed(t *testing.T) {
	ops := []struct {
		name string
		do   func(s *Session, srv *fakesrv.Server) (*NewUser, error)
	}{
		{"add", func(s *Session, _ *fakesrv.Server) (*NewUser, error) {
			return s.AddUser(awgContainer(), "Mallory")
		}},
		{"rekey", func(s *Session, _ *fakesrv.Server) (*NewUser, error) {
			cl, err := s.LoadClients(awgContainer())
			if err != nil || len(cl) == 0 {
				t.Fatalf("проверка ПЕРЕСТАЛА ЧТО-ЛИБО ЗНАЧИТЬ: список %d, %v", len(cl), err)
			}
			return s.RegenerateUser(awgContainer(), cl[0].ClientID)
		}},
	}
	for _, op := range ops {
		t.Run(op.name+" — порт указан", func(t *testing.T) {
			srv := debtsServer(t, "40443")
			nu, err := op.do(a1bSession(srv), srv)
			if err != nil {
				t.Fatalf("%s: %v", op.name, err)
			}
			if !strings.Contains(nu.Config, "Endpoint = 203.0.113.10:40443\n") {
				t.Fatalf("в конфиге клиента не порт сервера:\n%s", endpointLine(nu.Config))
			}
		})
		t.Run(op.name+" — порта нет", func(t *testing.T) {
			srv := debtsServer(t, "")
			wgBefore, _ := srv.File(debtsWg0)
			tblBefore, _ := srv.File("/opt/amnezia/awg/clientsTable")
			nu, err := op.do(a1bSession(srv), srv)
			if err == nil {
				t.Fatalf("%s выдал конфиг при неизвестном порте сервера: %s", op.name, endpointLine(nu.Config))
			}
			if !strings.Contains(fmt.Sprint(err), "не указан ListenPort") { // fmt.Sprint: без паники на nil, если строку выше обезвредят
				t.Errorf("отказ не по причине порта: %v", err)
			}
			wgAfter, _ := srv.File(debtsWg0)
			tblAfter, _ := srv.File("/opt/amnezia/awg/clientsTable")
			if string(wgAfter) != string(wgBefore) || string(tblAfter) != string(tblBefore) {
				t.Error("при отказе сервер изменён")
			}
		})
	}
}

// TestDebtsSubnetNotGuessed — У3: в wg0.conf нет ни Address, ни peer'ов —
// подсеть неоткуда взять. Прежде add выдавал 10.8.1.2.
func TestDebtsSubnetNotGuessed(t *testing.T) {
	srv := fakesrv.New()
	wg0, _ := srv.File(debtsWg0)
	iface := string(wg0)[:strings.Index(string(wg0), "[Peer]")]
	if !strings.Contains(iface, "Address = ") {
		t.Fatal("проверка ПЕРЕСТАЛА ЧТО-ЛИБО ЗНАЧИТЬ: в wg0.conf fakesrv нет Address")
	}
	iface = regexp.MustCompile(`(?m)^Address = .*\n`).ReplaceAllString(iface, "")
	srv.SetFile(debtsWg0, []byte(iface))
	srv.DeleteFile("/opt/amnezia/awg/clientsTable")
	nu, err := a1bSession(srv).AddUser(awgContainer(), "Mallory")
	if err == nil {
		t.Fatalf("add выдал адрес %s при неизвестной подсети сервера", nu.IP)
	}
	if !strings.Contains(fmt.Sprint(err), "не указан Address") { // fmt.Sprint: см. выше
		t.Errorf("отказ не по причине подсети: %v", err)
	}
}

// TestDebtsPeerSubnetsDiverge — раунд 2 (SEC-01, Н-1): в wg0.conf нет
// Address. Все peer'ы в одной подсети — адрес выдан из неё (контроль
// различения); peer'ы в двух подсетях — отказ, на сервере ничего не
// изменено. Боевой путь: AddUser через Session и fakesrv. На c65420e при
// двух подсетях add выдавал 10.8.1.4 (подсеть первого peer'а, занятость —
// по последнему октету чужой подсети).
func TestDebtsPeerSubnetsDiverge(t *testing.T) {
	cases := []struct {
		name     string
		secondIP string
		wantIP   string // "" — ожидается отказ
	}{
		{"одна подсеть", "10.8.1.3", "10.8.1.4"},
		{"две подсети", "10.9.0.3", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv := fakesrv.New()
			wg0, _ := srv.File(debtsWg0)
			s := regexp.MustCompile(`(?m)^Address = .*\n`).ReplaceAllString(string(wg0), "")
			if strings.Contains(s, "Address") || !strings.Contains(s, "AllowedIPs = 10.8.1.3/32") {
				t.Fatalf("проверка ПЕРЕСТАЛА ЧТО-ЛИБО ЗНАЧИТЬ: wg0.conf fakesrv изменился:\n%s", s)
			}
			s = strings.Replace(s, "AllowedIPs = 10.8.1.3/32", "AllowedIPs = "+c.secondIP+"/32", 1)
			srv.SetFile(debtsWg0, []byte(s))
			wgBefore, _ := srv.File(debtsWg0)
			tblBefore, _ := srv.File("/opt/amnezia/awg/clientsTable")
			nu, err := a1bSession(srv).AddUser(awgContainer(), "Mallory")
			if c.wantIP != "" {
				if err != nil {
					t.Fatalf("одна подсеть у всех peer'ов, а add отказал: %v", err)
				}
				if nu.IP != c.wantIP {
					t.Fatalf("выдан %s, ожидался %s", nu.IP, c.wantIP)
				}
				return
			}
			if err == nil {
				t.Fatalf("peer'ы в двух подсетях, а add выдал %s — подсеть выбрана наугад", nu.IP)
			}
			if !strings.Contains(fmt.Sprint(err), "в разных подсетях (10.8.1.x, 10.9.0.x)") {
				t.Errorf("отказ не по причине расхождения подсетей: %v", err)
			}
			wgAfter, _ := srv.File(debtsWg0)
			tblAfter, _ := srv.File("/opt/amnezia/awg/clientsTable")
			if string(wgAfter) != string(wgBefore) || string(tblAfter) != string(tblBefore) {
				t.Error("при отказе сервер изменён")
			}
		})
	}
}

func endpointLine(conf string) string {
	for _, l := range strings.Split(conf, "\n") {
		if strings.HasPrefix(l, "Endpoint") {
			return l
		}
	}
	return "(строки Endpoint нет)"
}
