package core

import (
	"errors"
	"net"
	"strings"
	"testing"

	"amnezia-admin/internal/fakesrv"
)

func sourceBackup(t *testing.T, srv *fakesrv.Server, host string) *Backup {
	t.Helper()
	b, err := NewSessionWithRunner(srv, &ServerCreds{Host: host}).CollectBackup("t", backupNow, okResolver)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func rowOf(r *CompatReport, ctr, what string) (CompatRow, bool) {
	for _, x := range r.Rows {
		if x.Container == ctr && x.What == what {
			return x, true
		}
	}
	return CompatRow{}, false
}

func setIface(t *testing.T, srv *fakesrv.Server, path, key, val string) {
	t.Helper()
	b, _ := srv.File(path)
	var out []string
	done := false
	for _, l := range strings.Split(string(b), "\n") {
		if !done && strings.HasPrefix(strings.TrimSpace(l), key+" ") {
			l, done = key+" = "+val, true
		}
		out = append(out, l)
	}
	if !done {
		t.Fatalf("в %s нет %s", path, key)
	}
	srv.SetFile(path, []byte(strings.Join(out, "\n")))
}

// TestCheckTargetTable — каждая сверка в трёх состояниях; «не удалось» и
// «не совпадает» различимы и оба СТОП; «совпадает» везде — не СТОП.
func TestCheckTargetTable(t *testing.T) {
	const wg = "/opt/amnezia/awg/wg0.conf"
	cases := []struct {
		name  string
		setup func(t *testing.T, tgt *fakesrv.Server)
		what  string
		want  CompatState
		text  string
	}{
		{"всё совпало", func(*testing.T, *fakesrv.Server) {}, "порт", CompatMatch, ""},
		{"порт другой", func(t *testing.T, s *fakesrv.Server) { setIface(t, s, wg, "ListenPort", "40000") }, "порт", CompatMismatch, "с портом 51820"},
		{"подсеть другая", func(t *testing.T, s *fakesrv.Server) { setIface(t, s, wg, "Address", "10.9.9.1/24") }, "подсеть", CompatMismatch, "подсетью 10.8.1.1/24"},
		{"порта на цели нет", func(t *testing.T, s *fakesrv.Server) {
			b, _ := s.File(wg)
			s.SetFile(wg, []byte(strings.Replace(string(b), "ListenPort = 51820\n", "", 1)))
		}, "порт", CompatUnknown, "не найден"},
		{"конфигурация цели не читается", func(t *testing.T, s *fakesrv.Server) {
			s.FailRead = map[string]error{wg: errors.New("cat: Input/output error")}
		}, "протокол и версия", CompatUnknown, "версию определить не удалось"},
		{"контейнера на цели нет", func(t *testing.T, s *fakesrv.Server) { s.Names = []string{"amnezia-wireguard"} }, "контейнер", CompatMismatch, "на новом сервере нет"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			b := sourceBackup(t, fakesrv.New(), "203.0.113.1")
			tgt := fakesrv.New()
			c.setup(t, tgt)
			r, err := NewSessionWithRunner(tgt, &ServerCreds{Host: "203.0.113.1"}).CheckTarget(b, okResolver)
			if err != nil {
				t.Fatal(err)
			}
			row, ok := rowOf(r, "amnezia-awg", c.what)
			if !ok || row.State != c.want || !strings.Contains(row.Text, c.text) {
				t.Fatalf("%s: строка %+v (есть=%v), ждали %v с «%s»; все: %+v", c.what, row, ok, c.want, c.text, r.Rows)
			}
			if r.Stop != (c.want != CompatMatch) {
				t.Errorf("СТОП=%v при %v", r.Stop, c.want)
			}
			if c.want != CompatMatch && !strings.Contains(row.Text, "приложение Amnezia → протокол → настройки") && c.what != "протокол и версия" {
				t.Errorf("нет подсказки Р-2: %s", row.Text)
			}
		})
	}
}

// TestCheckTargetVersions — версия AWG2: совпала; не совпала (СТОП
// «переустановите ту же версию»); в копии не определена (СТОП «не удалось»).
func TestCheckTargetVersions(t *testing.T) {
	src := fakesrv.NewAWG2()
	b := sourceBackup(t, src, "203.0.113.1")
	bc := ctrOf(t, b, "amnezia-awg2")
	if bc.VersionState != VersionKnown {
		t.Fatalf("в исходной копии версия не определена: %+v", bc)
	}
	r, _ := NewSessionWithRunner(fakesrv.NewAWG2(), &ServerCreds{Host: "203.0.113.1"}).CheckTarget(b, okResolver)
	if row, _ := rowOf(r, "amnezia-awg2", "протокол и версия"); row.State != CompatMatch {
		t.Errorf("та же версия: %+v", row)
	}
	other := *b
	other.Containers = append([]BackupContainer(nil), b.Containers...)
	for i := range other.Containers {
		if other.Containers[i].Name == "amnezia-awg2" {
			other.Containers[i].Version = "1.5"
		}
	}
	r, _ = NewSessionWithRunner(fakesrv.NewAWG2(), &ServerCreds{Host: "203.0.113.1"}).CheckTarget(&other, okResolver)
	if row, _ := rowOf(r, "amnezia-awg2", "протокол и версия"); row.State != CompatMismatch || !strings.Contains(row.Text, "ту же версию") || !r.Stop {
		t.Errorf("другая версия: %+v", row)
	}
	for i := range other.Containers {
		if other.Containers[i].Name == "amnezia-awg2" {
			other.Containers[i].Version, other.Containers[i].VersionState = "", VersionUnknown
		}
	}
	r, _ = NewSessionWithRunner(fakesrv.NewAWG2(), &ServerCreds{Host: "203.0.113.1"}).CheckTarget(&other, okResolver)
	if row, _ := rowOf(r, "amnezia-awg2", "протокол и версия"); row.State != CompatUnknown || !strings.Contains(row.Text, "определить не удалось") || !r.Stop {
		t.Errorf("версия не определена: %+v", row)
	}
}

// TestCheckTargetUnreadableInBackup — контейнер, не прочитанный при снятии,
// — СТОП «узнать не удалось», не молчаливый пропуск.
func TestCheckTargetUnreadableInBackup(t *testing.T) {
	src := fakesrv.New()
	src.FailRead = map[string]error{"/opt/amnezia/awg/clientsTable": errors.New("cat: Permission denied")}
	b := sourceBackup(t, src, "203.0.113.1")
	r, _ := NewSessionWithRunner(fakesrv.New(), &ServerCreds{Host: "203.0.113.1"}).CheckTarget(b, okResolver)
	if row, ok := rowOf(r, "amnezia-awg", "контейнер"); !ok || row.State != CompatUnknown || !r.Stop {
		t.Errorf("неполная копия: %+v %v", row, r.Stop)
	}
}

// TestAddressVerdicts — четыре итога; «проверить не удалось» ≠ «тот же»
// (тест различения) и возникает боевым путём — резолвер отвечает ошибкой
// (тест доезда через CheckTarget). Подмена «ошибка резолва = тот же адрес»
// роняет оба.
func TestAddressVerdicts(t *testing.T) {
	newIP := func(string) ([]net.IP, error) { return []net.IP{net.ParseIP("198.51.100.9")}, nil }
	thirdIP := func(h string) ([]net.IP, error) {
		if h == "vpn.example.org" {
			return []net.IP{net.ParseIP("192.0.2.50")}, nil
		}
		return []net.IP{net.ParseIP("198.51.100.9")}, nil
	}
	cases := []struct {
		name     string
		srcHost  string
		tgtHost  string
		resolve  Resolver
		want     AddressVerdict
		confirm  bool
		textPart string
	}{
		{"IP тот же (перенесён)", "203.0.113.1", "203.0.113.1", nil, AddrSame, false, "Адрес тот же"},
		{"IP другой", "203.0.113.1", "198.51.100.9", nil, AddrDiffers, true, "НЕ ПРИДУТ"},
		{"имя, цель по тому же имени", "vpn.example.org", "vpn.example.org", okResolver, AddrByName, false, "этому же имени"},
		{"имя указывает на старый", "vpn.example.org", "198.51.100.9", okResolver, AddrDiffers, true, "всё ещё указывает на старый"},
		{"имя указывает на третий адрес", "vpn.example.org", "198.51.100.9", thirdIP, AddrByName, false, "перенаправьте имя"},
		{"имя уже на новом", "vpn.example.org", "198.51.100.9", newIP, AddrByName, false, "уже указывает на новый"},
		{"IP в копии, имя цели не разрешилось", "203.0.113.1", "new.example.org", badResolver, AddrUnknown, true, "не удалось"},
		{"имя в копии не разрешилось", "vpn.example.org", "198.51.100.9", badResolver, AddrUnknown, true, "не разрешились"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			b := sourceBackup(t, fakesrv.New(), c.srcHost)
			r, err := NewSessionWithRunner(fakesrv.New(), &ServerCreds{Host: c.tgtHost}).CheckTarget(b, c.resolve)
			if err != nil {
				t.Fatal(err)
			}
			if r.Address != c.want || r.NeedAddressConfirm != c.confirm || !strings.Contains(r.AddressText, c.textPart) {
				t.Errorf("итог %v подтв=%v «%s», ждали %v подтв=%v «%s»", r.Address, r.NeedAddressConfirm, r.AddressText, c.want, c.confirm, c.textPart)
			}
		})
	}
	// в копии нет адреса — «не удалось»
	if v, _ := addressVerdict(IssuedAddress{}, "203.0.113.1", nil); v != AddrUnknown {
		t.Errorf("без адреса в копии: %v", v)
	}
	if !strings.Contains(ForeignConfigsNote, "не этой программой") {
		t.Error("строка про чужие выдачи")
	}
}

// TestCheckTargetUntouchedAndNoWrites — контейнеры цели вне копии
// перечислены; проверка не пишет на сервер.
func TestCheckTargetUntouchedAndNoWrites(t *testing.T) {
	b := sourceBackup(t, fakesrv.New(), "203.0.113.1")
	tgt := fakesrv.New()
	tgt.Names = append(tgt.Names, "amnezia-openvpn")
	r, _ := NewSessionWithRunner(tgt, &ServerCreds{Host: "203.0.113.1"}).CheckTarget(b, nil)
	if len(r.Untouched) != 1 || r.Untouched[0] != "amnezia-openvpn" {
		t.Errorf("вне копии: %v", r.Untouched)
	}
	for _, c := range tgt.Commands() {
		if strings.Contains(c, "flock") || strings.Contains(c, "restart") || strings.Contains(c, "syncconf") || strings.Contains(c, "backup") {
			t.Errorf("проверка цели выполнила запись: %.80s", c)
		}
	}
}
