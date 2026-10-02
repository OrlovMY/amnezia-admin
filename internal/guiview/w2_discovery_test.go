package guiview

// PR-W2: обнаружение всех типов контейнеров Amnezia (БК-ПРОТОКОЛЫ Р2-1 –
// Р2-3). Доезд: состояние приходит из вывода `docker ps` fakesrv через
// настоящий core.FindContainers, а не присваиванием в тесте. Различение:
// «поддерживается» / «известен, но не поддерживается» / «незнакомый» дают
// разные подписи, статусы и права.

import (
	"errors"
	"strings"
	"testing"

	"amnezia-admin/core"
	"amnezia-admin/internal/fakesrv"
)

type w2want struct {
	name    string
	support core.SupportState
	label   string
}

func w2find(t *testing.T, names []string) (*fakesrv.Server, *core.Session, []core.Container, error) {
	t.Helper()
	srv := fakesrv.New()
	srv.Names = names
	sess := core.NewSessionWithRunner(srv, &core.ServerCreds{Host: "203.0.113.10", User: "root", Password: "x"})
	cs, err := sess.FindContainers()
	return srv, sess, cs, err
}

// defaultContainer — как выбирают CLI и GUI: первый поддерживаемый, иначе
// первый найденный.
func defaultContainer(cs []core.Container) core.Container {
	for _, c := range cs {
		if c.Managed() {
			return c
		}
	}
	return cs[0]
}

const (
	viewOnly = " — только просмотр"
	noList   = " — не поддерживается, пользователей не показать"
	notSup   = " — не поддерживается" // общий корень двух подписей неподдерживаемых
)

func TestW2DiscoveryTable(t *testing.T) {
	all16 := []string{"amnezia-awg", "amnezia-wireguard", "amnezia-awg2", "amnezia-xray", "amnezia-openvpn",
		"amnezia-shadowsocks", "amnezia-openvpn-cloak", "amnezia-ipsec", "amnezia-ssxray", "amnezia-torwebsite",
		"amnezia-dns", "amnezia-sftp", "amnezia-socks5proxy", "amnezia-mtproxy", "amnezia-telemt", "amnezia-tproxy"}
	for _, c := range []struct {
		set    string
		names  []string
		want   []w2want // в порядке, который вернёт FindContainers
		def    string   // протокол по умолчанию
		errHas string
	}{
		{"только amnezia-awg", []string{"amnezia-awg"},
			[]w2want{{"amnezia-awg", core.SupportYes, "AmneziaWG (старый)"}}, "amnezia-awg", ""},
		{"awg + wireguard (docker отдал wireguard первым)", []string{"amnezia-wireguard", "amnezia-awg"},
			[]w2want{{"amnezia-awg", core.SupportYes, "AmneziaWG (старый)"}, {"amnezia-wireguard", core.SupportYes, "WireGuard"}}, "amnezia-awg", ""},
		{"только amnezia-xray", []string{"amnezia-xray"},
			[]w2want{{"amnezia-xray", core.SupportKnownNo, "XRay" + viewOnly}}, "amnezia-xray", ""},
		{"только amnezia-openvpn", []string{"amnezia-openvpn"},
			[]w2want{{"amnezia-openvpn", core.SupportKnownNo, "OpenVPN" + viewOnly}}, "amnezia-openvpn", ""},
		{"amnezia-ipsec, amnezia-torwebsite", []string{"amnezia-torwebsite", "amnezia-ipsec"},
			[]w2want{{"amnezia-ipsec", core.SupportKnownNo, "IPsec" + viewOnly}, {"amnezia-torwebsite", core.SupportKnownNo, "Website in Tor network" + noList}}, "amnezia-ipsec", ""},
		{"старые имена amnezia-ikev2, amnezia-tor", []string{"amnezia-tor", "amnezia-ikev2"},
			[]w2want{{"amnezia-ikev2", core.SupportKnownNo, "IPsec" + viewOnly}, {"amnezia-tor", core.SupportKnownNo, "Website in Tor network" + viewOnly}}, "amnezia-ikev2", ""},
		{"amnezia-foo", []string{"amnezia-foo"},
			[]w2want{{"amnezia-foo", core.SupportUnknown, "незнакомый контейнер amnezia-foo"}}, "amnezia-foo", ""},
		{"amnezia-awg2 без awg0.conf (сведение W2+W3: версия неизвестна, причина)", []string{"amnezia-awg2"},
			[]w2want{{"amnezia-awg2", core.SupportKnownNo, "AmneziaWG (версия неизвестна)" + viewOnly + ": файл настроек сервера не прочитан"}}, "amnezia-awg2", ""},
		{"пусто", nil, nil, "", "контейнеры Amnezia на сервере не найдены"},
		// «только остановленные» — вне W2: docker ps -a вынесен после релиза
		// (Р3-5). Вместо этой строки — все 16 типов разом: каждый опознан.
		{"все 16 типов", all16, nil, "amnezia-awg", ""},
		{"чужие контейнеры вместе с amnezia", []string{"nginx", "amnezia-xray", "portainer", "amnezia-awg"},
			[]w2want{{"amnezia-awg", core.SupportYes, "AmneziaWG (старый)"}, {"amnezia-xray", core.SupportKnownNo, "XRay" + viewOnly}}, "amnezia-awg", ""},
	} {
		t.Run(c.set, func(t *testing.T) {
			srv, sess, cs, err := w2find(t, c.names)
			if c.errHas != "" {
				if err == nil || !strings.Contains(err.Error(), c.errHas) {
					t.Fatalf("ожидалась ошибка %q, получено %v", c.errHas, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if c.set == "все 16 типов" {
				if len(cs) != 16 {
					t.Fatalf("найдено %d из 16", len(cs))
				}
				for _, x := range cs {
					if x.Support == core.SupportUnknown || strings.HasPrefix(ProtoLabel(x), "незнакомый") {
						t.Errorf("%s не опознан", x.Name)
					}
				}
				if cs[0].Name != "amnezia-awg" {
					t.Errorf("первым не awg: %s", cs[0].Name)
				}
				return
			}
			if len(cs) != len(c.want) {
				t.Fatalf("найдено %d, ожидалось %d: %+v", len(cs), len(c.want), cs)
			}
			for i, w := range c.want {
				if cs[i].Name != w.name || cs[i].Support != w.support || ProtoLabel(cs[i]) != w.label {
					t.Errorf("[%d] %s %v %q, ожидалось %s %v %q", i, cs[i].Name, cs[i].Support, ProtoLabel(cs[i]), w.name, w.support, w.label)
				}
			}
			if d := defaultContainer(cs); d.Name != c.def {
				t.Errorf("по умолчанию %s, ожидалось %s", d.Name, c.def)
			}
			// права и статус — из ViewState поверх НАСТОЯЩЕГО LoadClientsView
			for _, x := range cs {
				clients, existed, lerr := sess.LoadClientsView(&x)
				v := ViewState(x, clients, existed, lerr)
				if v.CanManage != (x.Support == core.SupportYes) {
					t.Errorf("%s: CanManage %v", x.Name, v.CanManage)
				}
				if x.Support == core.SupportUnknown {
					if x.Dir != "" {
						t.Errorf("%s: каталог угадан %q", x.Name, x.Dir)
					}
					if !errors.Is(lerr, core.ErrContainerDirUnknown) || !strings.HasPrefix(v.Status, "Незнакомый контейнер "+x.Name) {
						t.Errorf("%s: %v / %q", x.Name, lerr, v.Status)
					}
				}
			}
			for _, cmd := range srv.Commands() {
				if strings.Contains(cmd, "exec amnezia-foo") {
					t.Errorf("команда внутрь незнакомого: %s", cmd)
				}
			}
		})
	}
}

// TestW2ThreeStatesDistinct — различение: три состояния дают три разные
// подписи и разные права; «незнакомый» не похож на подпись протокола.
func TestW2ThreeStatesDistinct(t *testing.T) {
	_, _, cs, err := w2find(t, []string{"amnezia-awg", "amnezia-xray", "amnezia-foo"})
	if err != nil {
		t.Fatal(err)
	}
	labels := map[core.SupportState]string{}
	for _, c := range cs {
		labels[c.Support] = ProtoLabel(c)
	}
	if len(labels) != 3 {
		t.Fatalf("состояний %d из 3: %v", len(labels), labels)
	}
	if labels[core.SupportYes] == labels[core.SupportKnownNo] || labels[core.SupportKnownNo] == labels[core.SupportUnknown] {
		t.Errorf("подписи совпали: %v", labels)
	}
	if !strings.Contains(labels[core.SupportUnknown], "amnezia-foo") || strings.Contains(labels[core.SupportUnknown], notSup) || strings.Contains(labels[core.SupportUnknown], viewOnly) {
		t.Errorf("незнакомый подписан как известный: %q", labels[core.SupportUnknown])
	}
}

// TestW2FourLabels — UX-01 Р1: ЧЕТЫРЕ подписи — поддерживается / только
// просмотр (каталог известен, список читается) / не поддерживается,
// пользователей не показать (каталога нет) / незнакомый. Доезд — через
// FindContainers; «только просмотр» только там, где список действительно
// читается (LoadClientsView без ErrContainerDirUnknown).
func TestW2FourLabels(t *testing.T) {
	_, sess, cs, err := w2find(t, []string{"amnezia-awg", "amnezia-xray", "amnezia-mtproxy", "amnezia-foo"})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"amnezia-awg":     "AmneziaWG (старый)",
		"amnezia-xray":    "XRay — только просмотр",
		"amnezia-mtproxy": "MTProxy (Telegram) — не поддерживается, пользователей не показать",
		"amnezia-foo":     "незнакомый контейнер amnezia-foo",
	}
	seen := map[string]bool{}
	for _, c := range cs {
		l := ProtoLabel(c)
		if l != want[c.Name] {
			t.Errorf("%s: %q, ожидалось %q", c.Name, l, want[c.Name])
		}
		if seen[l] {
			t.Errorf("подпись %q повторяется", l)
		}
		seen[l] = true
		_, _, lerr := sess.LoadClientsView(&c)
		if strings.HasSuffix(l, "— только просмотр") && errors.Is(lerr, core.ErrContainerDirUnknown) {
			t.Errorf("%s: «только просмотр», а список не читается", c.Name)
		}
	}
	if len(seen) != 4 {
		t.Fatalf("подписей %d из 4", len(seen))
	}
}

// TestW2NoDirStatus — UX-01 Р2: протокол без известного каталога — статус
// говорит, что список НЕ показан и почему, а не «пользователей нет».
func TestW2NoDirStatus(t *testing.T) {
	_, sess, cs, err := w2find(t, []string{"amnezia-mtproxy"})
	if err != nil {
		t.Fatal(err)
	}
	clients, existed, lerr := sess.LoadClientsView(&cs[0])
	v := ViewState(cs[0], clients, existed, lerr)
	want := "MTProxy (Telegram) установлен на сервере, но эта программа не знает, где он хранит пользователей, поэтому список не показан. Управлять его пользователями можно в приложении Amnezia."
	if v.Status != want || len(clients) != 0 || v.CanManage {
		t.Errorf("статус: %q", v.Status)
	}
}
