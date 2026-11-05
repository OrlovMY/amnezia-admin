package core

// Ревью р1 PR #63: M1 (остановленный демон), M2 (закрытый список команд),
// M3 (порт по умолчанию), M4 (порты контейнеров по docker ps), L5 (текст
// сервера в причине).

import (
	"strings"
	"testing"
)

// provAllowed — ЗАКРЫТЫЙ список команд предпроверки (M2): сами пробы и они
// же через sudo -n. Любая другая команда — падение: правка скрипта пробы
// меняет и список, видимой строкой диффа.
func provAllowed() map[string]bool {
	m := map[string]bool{}
	for _, c := range []string{
		provCmd(provOSScript), provCmd(provKernelScript), provCmd(provSudoScript),
		provCmd(provDockerScript), provCmd(provCtrScript), provCmd(provPortsScript),
		provCmd(provDiskScript), diagHostCmd(),
	} {
		m[c] = true
		m["sudo -n "+c] = true
	}
	return m
}

func assertProvReadOnly(t *testing.T, cmds []string) {
	t.Helper()
	if len(cmds) == 0 {
		t.Fatal("ни одной команды не выполнено — проверять нечего")
	}
	ok := provAllowed()
	for _, c := range cmds {
		if !ok[c] {
			t.Errorf("команда вне закрытого списка предпроверки: %s", c)
		}
	}
}

// Закрытый список на всех путях: root с Docker (docker ps выполняется) и не
// root с повторами через sudo -n.
func TestProvisionCheckReadOnlyClosedList(t *testing.T) {
	f := healthyFake()
	f.out[ProvDockerTag] = "DOCKER=yes\nSRVRC=0\nSRV=27.1.1\nEND\n"
	f.out[ProvCtrTag] = "RC=0\nN=web|0.0.0.0:80->80/tcp\nEND\n"
	NewSessionWithRunner(f, &ServerCreds{User: "root"}).ProvisionCheck()
	assertProvReadOnly(t, f.cmds)
	ctr := false
	for _, c := range f.cmds {
		ctr = ctr || strings.Contains(c, ProvCtrTag)
	}
	if !ctr {
		t.Fatal("docker ps не выполнялся — закрытый список на нём не проверен")
	}

	g := healthyFake()
	g.out[DiagHostTag] = "AA=yes\nPROF=unreadable\nLOG=unreadable\nEND\n"
	g.out[ProvDockerTag] = "DOCKER=yes\nSRVRC=1\nSRV=permission denied\nEND\n"
	NewSessionWithRunner(g, &ServerCreds{User: "ubuntu"}).ProvisionCheck()
	assertProvReadOnly(t, g.cmds)
	sudo := 0
	for _, c := range g.cmds {
		if strings.HasPrefix(c, "sudo -n ") {
			sudo++
		}
	}
	if sudo == 0 {
		t.Fatal("путь с sudo -n не пройден — закрытый список на нём не проверен")
	}
}

// M4: порт, опубликованный контейнером, — «занят», даже если ss его не видит
// (docker-proxy выключен); docker ps не получен — «не удалось», а не «свободен».
func TestProvPortDockerPublished(t *testing.T) {
	d := parseProbe("DOCKER=yes\nSRVRC=0\nSRV=27.1\nEND\n", nil)
	c := parseProbe("RC=0\nN=caddy|0.0.0.0:443->443/tcp, :::443->443/tcp\nN=x|55424/udp\nEND\n", nil)
	pub := publishedPorts(d, c)
	ss := parseProbe(okPorts, nil)
	if got := classifyPort(ss, pub, "XRay", "tcp", ProvXRayPort); got.State != ProvBad || !strings.Contains(got.Reason, "caddy") {
		t.Fatalf("443 у caddy: %v %s", got.State, got.Reason)
	}
	if got := classifyPort(ss, pub, "AWG", "udp", ProvAWGPort); got.State != ProvOK {
		t.Fatalf("55424/udp только объявлен (EXPOSE), не опубликован: %v %s", got.State, got.Reason)
	}
	if got := classifyPort(ss, publishedPorts(d, probe{}), "XRay", "tcp", ProvXRayPort); got.State != ProvUnknown {
		t.Fatalf("docker ps не получен: %v", got.State)
	}
	stopped := parseProbe("DOCKER=yes\nSRVRC=1\nSRV=Cannot connect to the Docker daemon\nEND\n", nil)
	// N2 (ревью р2), тест различения: демон лежит — docker ps не выполнялся,
	// порты контейнеров неизвестны → «не удалось»; docker ps выполнен и
	// порта нет → «свободен».
	if got := classifyPort(ss, publishedPorts(stopped, probe{}), "XRay", "tcp", ProvXRayPort); got.State != ProvUnknown || !strings.Contains(got.Reason, "остановлен") {
		t.Fatalf("демон остановлен: %v %s, ждали «не удалось»", got.State, got.Reason)
	}
	ran := parseProbe("RC=0\nN=web|0.0.0.0:80->80/tcp\nEND\n", nil)
	if got := classifyPort(ss, publishedPorts(d, ran), "XRay", "tcp", ProvXRayPort); got.State != ProvOK {
		t.Fatalf("docker ps выполнен, 443 не опубликован: %v %s", got.State, got.Reason)
	}
	got := classifyPort(ss, pubPorts{known: true}, "XRay", "tcp", ProvXRayPort)
	if !strings.Contains(got.What, "по умолчанию") {
		t.Fatalf("M3: в выводе не сказано «порт по умолчанию»: %s", got.What)
	}
	if !strings.Contains(got.Reason, "docker-proxy") {
		t.Fatalf("M4: в «свободен» нет оговорки про порты контейнеров: %s", got.Reason)
	}
}

// Доезд M4: чужой контейнер на 443, ss его не видит → итог «нельзя».
func TestProvisionCheckPublishedArrives(t *testing.T) {
	f := healthyFake()
	f.out[ProvDockerTag] = "DOCKER=yes\nSRVRC=0\nSRV=27.1.1\nEND\n"
	f.out[ProvCtrTag] = "RC=0\nN=caddy|0.0.0.0:443->443/tcp\nEND\n"
	r := NewSessionWithRunner(f, &ServerCreds{User: "root"}).ProvisionCheck()
	if it := itemByPrefix(t, r, "порт XRay"); it.State != ProvBad {
		t.Fatalf("443 опубликован caddy: %v %s", it.State, it.Reason)
	}
	if r.Verdict() != ProvVerdictNo {
		t.Fatalf("итог: %v", r.Verdict())
	}
}

// M1 доезд: демон остановлен → Docker «годится» с причиной; не «нельзя».
// N4: диапазоны портов из docker ps; не разобралось — «не удалось».
func TestProvPortRanges(t *testing.T) {
	d := parseProbe("DOCKER=yes\nSRVRC=0\nSRV=27.1\nEND\n", nil)
	ss := parseProbe(okPorts, nil)
	cases := []struct {
		ports string
		want  ProvState
	}{
		{"0.0.0.0:400-500->400-500/tcp", ProvBad},
		{"0.0.0.0:400-500->400-500/udp", ProvOK},
		{"0.0.0.0:444-500->444-500/tcp", ProvOK},
		{"[::]:443->443/tcp", ProvBad},
		{"0.0.0.0:abc->443/tcp", ProvUnknown},
		{"0.0.0.0:500-400->500-400/tcp", ProvUnknown},
		{"0.0.0.0:443->443/sctp", ProvUnknown},
	}
	for _, c := range cases {
		ctr := parseProbe("RC=0\nN=c|"+c.ports+"\nEND\n", nil)
		got := classifyPort(ss, publishedPorts(d, ctr), "XRay", "tcp", ProvXRayPort)
		if got.State != c.want {
			t.Errorf("%s: %v (%s), ждали %v", c.ports, got.State, got.Reason, c.want)
		}
	}
}

// N2 доезд: демон лежит → порты «не удалось» боевым путём.
func TestProvisionCheckStoppedDaemonPortsUnknown(t *testing.T) {
	f := healthyFake()
	f.out[ProvDockerTag] = "DOCKER=yes\nSRVRC=1\nSRV=Cannot connect to the Docker daemon\nEND\n"
	r := NewSessionWithRunner(f, &ServerCreds{User: "root"}).ProvisionCheck()
	if it := itemByPrefix(t, r, "порт XRay"); it.State != ProvUnknown {
		t.Fatalf("демон лежит: %v %s", it.State, it.Reason)
	}
}

func TestProvisionCheckDockerStoppedArrives(t *testing.T) {
	f := healthyFake()
	f.out[ProvDockerTag] = "DOCKER=yes\nSRVRC=1\nSRV=Cannot connect to the Docker daemon at unix:///var/run/docker.sock. Is the docker daemon running?\nEND\n"
	r := NewSessionWithRunner(f, &ServerCreds{User: "root"}).ProvisionCheck()
	it := itemByPrefix(t, r, "Docker")
	if it.State != ProvOK || !strings.Contains(it.Reason, "установщик запустит") {
		t.Fatalf("демон остановлен: %v %s", it.State, it.Reason)
	}
	if r.Verdict() == ProvVerdictNo {
		t.Fatalf("остановленный демон не должен давать «нельзя»: %+v", r.Items)
	}
}

// L5: текст сервера в причине — без управляющих символов и ограничен.
func TestProvServerTextSanitized(t *testing.T) {
	long := "SSRC=1\nL=\x1b[31mboom\x07" + strings.Repeat("x", 5000) + "\nEND\n"
	got := classifyPort(parseProbe(long, nil), pubPorts{known: true}, "XRay", "tcp", ProvXRayPort)
	if got.State != ProvUnknown {
		t.Fatalf("ss упал: %v", got.State)
	}
	if strings.ContainsAny(got.Reason, "\x1b\x07") {
		t.Fatalf("управляющие символы в причине: %q", got.Reason)
	}
	if n := len([]rune(got.Reason)); n > srvMax+100 {
		t.Fatalf("причина не обрезана: %d рун", n)
	}
}
