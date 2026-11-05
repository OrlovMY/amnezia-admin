package core_test

import (
	"errors"
	"strings"
	"testing"

	"amnezia-admin/core"
	"amnezia-admin/internal/fakesrv"
)

func awgSession(t *testing.T, srv *fakesrv.Server, name string) (*core.Session, *core.Container) {
	t.Helper()
	sess := core.NewSessionWithRunner(srv, raceCreds())
	cs, err := sess.FindContainers()
	if err != nil {
		t.Fatal(err)
	}
	for i := range cs {
		if cs[i].Name == name {
			return sess, &cs[i]
		}
	}
	t.Fatalf("%s не найден: %+v", name, cs)
	return nil, nil
}

// TestProtoDetailsThreeStates — табличный тест «Подробнее»: значение,
// «не применяется» и «не удалось узнать» различаются состоянием, а не
// пустотой; «не удалось» возникает боевым путём (ReadProtoDetails поверх
// поддельного сервера с отказом чтения), а не присваиванием.
func TestProtoDetailsThreeStates(t *testing.T) {
	const wg0 = "/opt/amnezia/awg/wg0.conf"
	for _, c := range []struct {
		name                             string
		srv                              func() *fakesrv.Server
		ctr                              string
		port, subnet, transport, version string // ожидаемое: значение или "?"/"n/a"
	}{
		{"AWG прочитан", fakesrv.New, "amnezia-awg", "51820", "10.8.1.1/24", "udp", "старый AWG"},
		{"AWG не прочитан", func() *fakesrv.Server {
			s := fakesrv.New()
			s.FailRead = map[string]error{wg0: errors.New("i/o timeout")}
			return s
		}, "amnezia-awg", "?", "?", "udp", "?"},
		{"AWG без ListenPort", func() *fakesrv.Server {
			s := fakesrv.New()
			b, _ := s.File(wg0)
			s.SetFile(wg0, []byte(strings.Replace(string(b), "ListenPort = 51820\n", "", 1)))
			return s
		}, "amnezia-awg", "?", "10.8.1.1/24", "udp", "старый AWG"},
		{"XRay прочитан", func() *fakesrv.Server { return fakesrv.NewXRay("dev") }, core.XRayContainer, "!", "n/a", "tcp/reality", "XRay"},
		{"XRay не прочитан", func() *fakesrv.Server {
			s := fakesrv.NewXRay("dev")
			s.FailRead = map[string]error{xrayConf: errors.New("i/o timeout")}
			return s
		}, core.XRayContainer, "?", "n/a", "?", "?"},
	} {
		t.Run(c.name, func(t *testing.T) {
			srv := c.srv()
			// FailRead на server.json делает XRay неуправляемым — FindContainers
			// всё равно его находит.
			sess, ctr := awgSession(t, srv, c.ctr)
			d := sess.ReadProtoDetails(ctr)
			check := func(what string, f core.DetailField, want string) {
				t.Helper()
				switch want {
				case "?":
					if f.State != core.DetailUnknown || f.Reason == "" || f.Value != "" {
						t.Errorf("%s: ждали «не удалось узнать» с причиной, получили %+v", what, f)
					}
				case "n/a":
					if f.State != core.DetailNotApplies {
						t.Errorf("%s: ждали «не применяется», получили %+v", what, f)
					}
				case "!":
					if f.State != core.DetailKnown || f.Value == "" {
						t.Errorf("%s: ждали значение, получили %+v", what, f)
					}
				default:
					if f.State != core.DetailKnown || f.Value != want {
						t.Errorf("%s: ждали %q, получили %+v", what, want, f)
					}
				}
			}
			check("порт", d.Port, c.port)
			check("подсеть", d.Subnet, c.subnet)
			check("транспорт", d.Transport, c.transport)
			check("версия", d.Version, c.version)
			check("контейнер", d.Container, c.ctr)
		})
	}
}
