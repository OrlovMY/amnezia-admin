package core

import (
	"path/filepath"
	"strings"
	"testing"
)

// Живая проверка migrate -to-host: отпечаток из -to-hostkey не совпал с
// предъявленным (частая причина — отпечаток ключа другого типа), а
// программа писала «не совпал с сохранённым… переустановили… забудьте
// старый ключ», хотя сохранённого ключа не было. Тест различения (сохранённый
// ≠ явно переданный) и доезда (настоящее SSH-рукопожатие с fakeSSH).
func TestHostKeyExplicitMismatchText(t *testing.T) {
	const wrong = "SHA256:wrongWrongWrongWrongWrongWrongWrongWrong00"
	cases := []struct {
		name      string
		from      string
		knownSeen bool // known_hosts уже содержит предъявленный ключ (шаг 3)
		want      []string
		notWant   []string
	}{
		{"сохранённый (хранилище), known_hosts пуст", "", false,
			[]string{ConnectHostKeyChangedText}, []string{"передан в"}},
		{"сохранённый (хранилище), known_hosts совпал", "", true,
			[]string{ConnectHostKeyChangedText, "из хранилища"}, []string{"передан в"}},
		{"-to-hostkey, known_hosts пуст", "-to-hostkey", false,
			[]string{"Отпечаток, переданный в -to-hostkey, не совпал", "тип ключа ssh-", "ожидался " + wrong, "другого типа"},
			[]string{"с сохранённым", "забудьте старый ключ"}},
		{"-hostkey, known_hosts совпал", "-hostkey", true,
			[]string{"Отпечаток, переданный в -hostkey, не совпал", "тип ключа ssh-", "передан в -hostkey"},
			[]string{"с сохранённым", "забудьте старый ключ", "из хранилища"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv, _ := newFakeSSHServer(t, "127.0.0.1:0")
			creds := credsForFakeSSH(t, srv)
			kh := filepath.Join(t.TempDir(), "known_hosts")
			var presented string
			if c.knownSeen {
				s, err := ConnectWithHostKey(creds, HostKeyPolicy{KnownHostsPath: kh, Prompt: alwaysTrustPrompt})
				if err != nil {
					t.Fatal(err)
				}
				presented = s.HostKeyFingerprint
				s.Close()
			}
			s, err := ConnectWithHostKey(creds, HostKeyPolicy{KnownHostsPath: kh, ExpectedFingerprint: wrong, ExpectedFrom: c.from})
			closeIfAny(s)
			if err == nil {
				t.Fatal("подключение прошло с неверным отпечатком")
			}
			msg := err.Error()
			for _, w := range c.want {
				if !strings.Contains(msg, w) {
					t.Errorf("нет %q в:\n%s", w, msg)
				}
			}
			for _, w := range c.notWant {
				if strings.Contains(msg, w) {
					t.Errorf("лишнее %q в:\n%s", w, msg)
				}
			}
			if c.from != "" && presented != "" && !strings.Contains(msg, "предъявлен "+presented) {
				t.Errorf("не выведен предъявленный отпечаток %s:\n%s", presented, msg)
			}
		})
	}
}

// Занятый порт: только существующие пути — выбора порта при установке нет;
// без протокола переносится только XRay.
func TestPortBusyAdviceOnlyRealPaths(t *testing.T) {
	cases := []struct {
		name, port string
		want       string
	}{
		{"XRay", "порт amnezia-xray", "перенесите без XRay (командная строка: migrate -to-host -skip-xray)"},
		{"AWG", "порт amnezia-awg2", "выбрать другой порт при установке программа не умеет"},
	}
	for _, c := range cases {
		for _, it := range []ProvItem{
			classifyPort(probe{ok: true, kv: map[string][]string{"SSRC": {"0"}, "L": {"tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:*", "tcp LISTEN 0 511 0.0.0.0:443 0.0.0.0:*", "udp UNCONN 0 0 0.0.0.0:443 0.0.0.0:*"}}}, pubPorts{known: true}, c.port, "tcp", 443),
			classifyPort(probe{}, pubPorts{known: true, set: map[string]string{"tcp:443": "nginx"}}, c.port, "tcp", 443),
		} {
			if it.State != ProvBad || !strings.Contains(it.Reason, c.want) || strings.Contains(it.Reason, "выберите другой порт") {
				t.Errorf("%s: %v %q", c.name, it.State, it.Reason)
			}
			if c.name == "AWG" && strings.Contains(it.Reason, "skip-xray") {
				t.Errorf("%s: подсказка -skip-xray для не-XRay: %q", c.name, it.Reason)
			}
		}
	}
}
