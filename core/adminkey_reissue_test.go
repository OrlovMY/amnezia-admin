package core

import (
	"errors"
	"strings"
	"testing"

	"amnezia-admin/internal/fakesrv"
)

// TestAdminKeyReissuePlan — три состояния по контейнеру (в ключе / НЕ
// прочитан / тип в ключ не кладётся) и третье для сервера (список не
// прочитан). Доезд — настоящий FindContainers и чтение awg0.conf поверх
// fakesrv; «не прочитан» — ошибка cat от сервера (FailRead), а не
// присваивание Gaps в тесте.
func TestAdminKeyReissuePlan(t *testing.T) {
	const conf = "/opt/amnezia/awg/awg0.conf"
	cases := []struct {
		name     string
		setup    func(*fakesrv.Server)
		prefer   string
		wantErr  bool
		wantIn   []string
		wantGaps []string
		complete bool
		def      string
	}{
		{name: "всё прочитано", wantIn: []string{"amnezia-awg2"}, complete: true, def: "amnezia-awg2"},
		{name: "awg0.conf не прочитан", setup: func(s *fakesrv.Server) {
			s.FailRead = map[string]error{conf: errors.New("Permission denied")}
		}, wantGaps: []string{"amnezia-awg2"}},
		{name: "незнакомый контейнер — в Gaps, не молча", setup: func(s *fakesrv.Server) {
			s.Names = []string{"amnezia-awg2", "amnezia-foo"}
		}, wantIn: []string{"amnezia-awg2"}, wantGaps: []string{"amnezia-foo"}, def: "amnezia-awg2"},
		// тест различения: служба без параметров ≠ незнакомый контейнер
		{name: "amnezia-dns — в ключе, не пробел", setup: func(s *fakesrv.Server) {
			s.Names = []string{"amnezia-awg2", "amnezia-dns"}
		}, wantIn: []string{"amnezia-awg2", "amnezia-dns"}, complete: true, def: "amnezia-awg2"},
		// H2: остановленный виден только docker ps -a — пробел, а не «нет»
		{name: "остановленный контейнер — пробел", setup: func(s *fakesrv.Server) {
			s.Stopped = []string{"amnezia-xray"}
		}, wantIn: []string{"amnezia-awg2"}, wantGaps: []string{"amnezia-xray"}, def: "amnezia-awg2"},
		{name: "предпочтённого по умолчанию нет — первый", prefer: "amnezia-xray", wantIn: []string{"amnezia-awg2"}, complete: true, def: "amnezia-awg2"},
		{name: "список контейнеров не прочитан", setup: func(s *fakesrv.Server) { s.Names = nil }, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := fakesrv.NewAWG2()
			if tc.setup != nil {
				tc.setup(f)
			}
			s := NewSessionWithRunner(f, &ServerCreds{Host: "h", Port: "22", User: "root"})
			r, err := s.AdminKeyReissuePlan(tc.prefer)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("нет ошибки: %+v", r)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			var in, gaps []string
			for _, c := range r.Containers {
				in = append(in, c.Name)
			}
			for _, g := range r.Gaps {
				gaps = append(gaps, g.Container)
				if strings.TrimSpace(g.Reason) == "" {
					t.Errorf("у %s нет причины", g.Container)
				}
			}
			if strings.Join(in, ",") != strings.Join(tc.wantIn, ",") || strings.Join(gaps, ",") != strings.Join(tc.wantGaps, ",") {
				t.Fatalf("в ключе %v (ожидалось %v), пробелы %v (ожидалось %v)", in, tc.wantIn, gaps, tc.wantGaps)
			}
			if r.Complete() != tc.complete || r.Default != tc.def {
				t.Fatalf("Complete=%v Default=%q", r.Complete(), r.Default)
			}
		})
	}
}

// H1 (ревью PR #75): amnezia-dns в ключе — как у приложения 5.1.0.6:
// {"container":"amnezia-dns","dns":{}} (DnsProtocolConfig::toJson — пустой
// объект). Подмена «пропустить dns» роняет тест.
func TestAdminKeyReissueDNSInKey(t *testing.T) {
	f := fakesrv.NewAWG2()
	f.Names = []string{"amnezia-awg2", "amnezia-dns"}
	s := NewSessionWithRunner(f, &ServerCreds{Host: "h", Port: "22", User: "root"})
	r, err := s.AdminKeyReissuePlan("")
	if err != nil {
		t.Fatal(err)
	}
	k, err := BuildAdminKey(AdminKeyInput{Host: "h", Port: 22, User: "root", Password: NewSecret([]byte("p")), PasswordConsent: true,
		Containers: r.Containers, DefaultContainer: r.Default})
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := DecodeVpnKey(k.Reveal())
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, c := range cfg["containers"].([]any) {
		m := c.(map[string]any)
		if Str(m, "container") == "amnezia-dns" {
			d, ok := m["dns"].(map[string]any)
			found = ok && len(d) == 0
		}
	}
	if !found {
		t.Fatal(`в ключе нет {"container":"amnezia-dns","dns":{}}`)
	}
}
