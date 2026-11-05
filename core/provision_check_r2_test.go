package core

// Ревью р1 PR #63: M1 (остановленный демон), M2 (закрытый список команд),
// M3 (порт по умолчанию), M4 (порты контейнеров по docker ps), L5 (текст
// сервера в причине).

import (
	"regexp"
	"strings"
	"testing"
)

// provPrograms — ЗАКРЫТЫЙ список программ внутри скриптов проб (M2, вторая
// половина): закрытый список команд ниже сравнивает с теми же константами
// и потому не видит правку САМОГО скрипта (touch, docker start). Здесь
// каждый простой вызов в скрипте обязан начинаться с разрешённой программы;
// у docker — только version/ps, у sudo — только «-n true», у sed — без -i;
// перенаправление в файл — только >/dev/null.
var provPrograms = map[string]bool{
	":": true, "[": true, "echo": true, ".": true, "command": true, "uname": true, "id": true,
	"sudo": true, "docker": true, "ss": true, "df": true, "head": true, "tail": true, "sed": true,
}

// provUnquote — текст скрипта, где литералы в двойных кавычках заменены на
// «x», а подстановки $( … ) (и внутри кавычек) вынесены отдельными строками.
func provUnquote(script string) string {
	var b strings.Builder
	var st []byte // стек: 'Q' — в кавычках, 'S' — в $( )
	top := func() byte {
		if len(st) == 0 {
			return 0
		}
		return st[len(st)-1]
	}
	for i := 0; i < len(script); i++ {
		c := script[i]
		switch {
		case c == '$' && i+1 < len(script) && script[i+1] == '(':
			st = append(st, 'S')
			b.WriteByte('\n')
			i++
		case c == ')' && top() == 'S':
			st = st[:len(st)-1]
			b.WriteByte('\n')
		case c == '"' && top() == 'Q':
			st = st[:len(st)-1]
			b.WriteByte('x')
		case c == '"':
			st = append(st, 'Q')
			b.WriteByte('x')
		case top() == 'Q':
			b.WriteByte('x')
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

var provRedir = regexp.MustCompile(`2>&1`)

func provScriptViolations(script string) []string {
	s := provUnquote(provRedir.ReplaceAllString(script, ""))
	for _, sep := range []string{"|", "&", ";"} {
		s = strings.ReplaceAll(s, sep, "\n")
	}
	var bad []string
	for _, seg := range strings.Split(s, "\n") {
		f := strings.Fields(seg)
		for len(f) > 0 && (f[0] == "if" || f[0] == "then" || f[0] == "else" || f[0] == "fi" || f[0] == "!") {
			f = f[1:]
		}
		if len(f) == 0 || (len(f) == 1 && strings.Trim(f[0], "x") == "") {
			continue // пусто или хвост литерала в кавычках после $( )
		}
		p := f[0]
		switch {
		case strings.Contains(p, "=") && !strings.HasPrefix(p, `"`):
			// присваивание: после него допустимо только перенаправление
			if len(f) > 1 && !strings.HasPrefix(f[1], "2>") {
				bad = append(bad, seg)
			}
		case !provPrograms[p]:
			bad = append(bad, seg)
		case p == "docker" && (len(f) < 2 || (f[1] != "version" && f[1] != "ps")):
			bad = append(bad, seg)
		case p == "sudo" && (len(f) < 3 || f[1] != "-n" || f[2] != "true"):
			bad = append(bad, seg)
		case p == "sed" && strings.Contains(seg, "-i"):
			bad = append(bad, seg)
		}
		for _, w := range f {
			if w == ">" || w == ">>" || (strings.HasPrefix(w, ">") && w != ">/dev/null") {
				bad = append(bad, seg)
			}
		}
	}
	return bad
}

func TestProvScriptsClosedProgramList(t *testing.T) {
	for _, sc := range []string{provOSScript, provKernelScript, provSudoScript, provDockerScript, provCtrScript, provPortsScript, provDiskScript} {
		if v := provScriptViolations(sc); len(v) > 0 {
			t.Errorf("в пробе вызов вне закрытого списка: %q\nскрипт: %s", v, sc)
		}
	}
	// Канарейка: сторож обязан споткнуться о заведомо пишущие вызовы.
	for _, canary := range []string{
		ProvDiskTag + ` echo x; touch /tmp/x; echo END`,
		ProvDockerTag + ` docker start x; echo END`,
		ProvOSTag + ` echo x > /etc/motd; echo END`,
		ProvPortsTag + ` o=$(ss -lntu 2>&1); sed -i "s/a/b/" /etc/hosts; echo END`,
	} {
		if len(provScriptViolations(canary)) == 0 {
			t.Errorf("канарейка не поймана: %s", canary)
		}
	}
}

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
	if got := classifyPort(ss, publishedPorts(stopped, probe{}), "XRay", "tcp", ProvXRayPort); got.State != ProvOK {
		t.Fatalf("демон остановлен — опубликованных портов нет: %v", got.State)
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
