package core

// TOCTOU (аудит AU M1): между подтверждением и сносом цель могла измениться.
// Три исхода перечитывания: не изменилось (снос) / изменилось (отказ,
// «запустите заново») / перечитать не удалось (отказ, другой текст).

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"amnezia-admin/internal/fakesrv"
)

// tdMixed — состав цели (docker ps -a/volume ls/images/rm) отвечает tdFake,
// всё остальное — настоящие команды копии на fakesrv.
type tdMixed struct {
	td  *tdFake
	srv *fakesrv.Server
}

func (m *tdMixed) Run(cmd string, stdin []byte) (string, error) {
	if strings.Contains(cmd, "{{.State}}") || strings.Contains(cmd, "docker volume") || strings.Contains(cmd, "docker images") ||
		strings.Contains(cmd, "docker rm -f") || strings.Contains(cmd, "docker rmi") || strings.Contains(cmd, "docker ps -a --format \"{{.Names}}\"") {
		return m.td.Run(cmd, stdin)
	}
	return m.srv.Run(cmd, stdin)
}

func tdMixedEnv(t *testing.T) (*tdMixed, *Session) {
	t.Helper()
	t.Cleanup(SetXRayWaits(0, 0))
	td := &tdFake{ctrs: map[string]string{"amnezia-awg": "0.0.0.0:51820->51820/udp"}, vols: map[string]string{}, imgs: map[string]string{"amnezia-awg": ""}}
	m := &tdMixed{td: td, srv: fakesrv.New()}
	return m, NewSessionWithRunner(m, &ServerCreds{Host: "203.0.113.9"})
}

// Доезд: настоящий CollectBackupCtx; между Plan и Execute на сервере
// меняется clientsTable — снос отказан, команд сноса нет, копии нет.
func TestTeardownRecheckRealCollect(t *testing.T) {
	for _, c := range []struct {
		name    string
		between func(m *tdMixed)
		state   TeardownState
		whyHas  string
		whyNot  string
	}{
		{"не изменилось — снос", func(*tdMixed) {}, TeardownDone, "", "изменился"},
		{"clientsTable изменилась", func(m *tdMixed) {
			m.srv.SetFile("/opt/amnezia/awg/clientsTable", []byte(`[{"clientId":"x","userData":{"clientName":"Новый"}}]`))
		}, TeardownRefused, TeardownChangedText, "перечитать"},
		{"добавился контейнер", func(m *tdMixed) { m.td.ctrs["amnezia-xray"] = "" }, TeardownRefused, TeardownChangedText, "перечитать"},
		{"контейнер остановлен", func(m *tdMixed) { m.td.stopped = map[string]bool{"amnezia-awg": true} }, TeardownRefused, "состояние running → exited", "перечитать"},
		{"состав перечитать не удалось", func(m *tdMixed) { m.td.failInventory = true }, TeardownRefused, "перечитать перед сносом не удалось", "изменился"},
		{"копию снять заново не удалось", func(m *tdMixed) { m.srv.DeleteFile("/opt/amnezia/awg/wg0.conf") }, TeardownRefused, "", ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			withTDMarker(t)
			m, s := tdMixedEnv(t)
			p, err := s.PlanTeardown(context.Background(), "t", time.Now(), nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			if p.CopyState() != CopyFull {
				t.Fatalf("план: копия %v (%s)", p.CopyState(), p.CopyWhy)
			}
			c.between(m)
			dir := t.TempDir()
			r := s.ExecuteTeardown(p, TeardownOptions{Confirmed: true, NoCopyConfirmed: true, CopyDir: dir, Layer: PlainLayer{}, Now: time.Now()})
			if r.State != c.state {
				t.Fatalf("State %v (%s), ждали %v", r.State, r.Why, c.state)
			}
			if c.whyHas != "" && !strings.Contains(r.Why, c.whyHas) {
				t.Errorf("Why %q, нет %q", r.Why, c.whyHas)
			}
			if c.whyNot != "" && strings.Contains(r.Why, c.whyNot) {
				t.Errorf("Why %q, лишнее %q", r.Why, c.whyNot)
			}
			if c.state == TeardownRefused {
				if len(m.td.rmCalls) != 0 {
					t.Errorf("снос при отказе: %v", m.td.rmCalls)
				}
				if files, _ := filepath.Glob(filepath.Join(dir, "*")); len(files) != 0 {
					t.Errorf("копия записана при отказе: %v", files)
				}
			} else if _, err := os.Stat(r.CopyPath); err != nil {
				t.Errorf("копии нет: %v", err)
			}
			if strings.Contains(r.Why, "Новый") || strings.Contains(r.Why, "Alice") {
				t.Errorf("данные клиентов в Why: %s", r.Why)
			}
		})
	}
}
