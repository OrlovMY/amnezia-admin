package core

import (
	"errors"
	"strings"
	"testing"
)

// provFake — фейковый раннер предпроверки: ответ по метке пробы. Команда,
// не найденная в таблице, — ошибка (как оборванное соединение). Записывает
// все команды: предпроверка обязана только читать.
type provFake struct {
	out  map[string]string // метка → stdout
	err  map[string]error  // метка → ошибка
	cmds []string
}

func (f *provFake) Run(cmd string, _ []byte) (string, error) {
	f.cmds = append(f.cmds, cmd)
	for tag, e := range f.err {
		if strings.Contains(cmd, tag) {
			return "", e
		}
	}
	for tag, o := range f.out {
		if strings.Contains(cmd, tag) {
			return o, nil
		}
	}
	return "", errors.New("нет связи")
}

const (
	okOS     = "ID=ubuntu\nVERSION_ID=24.04\nPRETTY=Ubuntu 24.04 LTS\nEND\n"
	okKernel = "KERNEL=6.8.0-45-generic\nARCH=x86_64\nEND\n"
	okHost   = "AA=yes\nPROF=readable\nLOADED=docker-default\nLOG=readable\nEND\n"
	okSudo   = "UID=0\nEND\n"
	okDocker = "DOCKER=no\nEND\n"
	okPorts  = "SSRC=0\nL=Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port\nL=tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\nEND\n"
	okDisk   = "DFPATH=/\nDFRC=0\nDF=/dev/vda1 41152736 3000000 36000000 8% /\nEND\n"
)

func healthyFake() *provFake {
	return &provFake{out: map[string]string{
		ProvOSTag: okOS, ProvKernelTag: okKernel, DiagHostTag: okHost, ProvSudoTag: okSudo,
		ProvDockerTag: okDocker, ProvPortsTag: okPorts, ProvDiskTag: okDisk,
	}, err: map[string]error{}}
}

func itemByPrefix(t *testing.T, r ProvisionReport, prefix string) ProvItem {
	t.Helper()
	for _, it := range r.Items {
		if strings.HasPrefix(it.What, prefix) {
			return it
		}
	}
	t.Fatalf("нет пункта %q в %+v", prefix, r.Items)
	return ProvItem{}
}

func TestProvStateZeroIsUnknown(t *testing.T) {
	var s ProvState
	var v ProvVerdict
	if s != ProvUnknown || v != ProvVerdictUnknown {
		t.Fatal("нулевое значение обязано значить «не знаем»")
	}
	if (ProvisionReport{}).Verdict() != ProvVerdictUnknown {
		t.Fatal("пустой отчёт — неизвестно, а не «можно»")
	}
}

// Табличный разбор: для каждого пункта — годится / не годится / упала
// команда / пустой вывод. «Упала» и «пусто» обязаны давать Unknown, а не Bad
// и не OK.
func TestProvClassifyTable(t *testing.T) {
	fail := errors.New("команда упала")
	type cls func(probe) ProvItem
	osC := classifyOS
	kC := classifyKernel
	aC := classifyArch
	apC := classifyProvAppArmor
	suC := classifySudo
	dC := classifyDocker
	awgC := func(p probe) ProvItem { return classifyPort(p, pubPorts{known: true}, "AWG", "udp", ProvAWGPort) }
	xC := func(p probe) ProvItem { return classifyPort(p, pubPorts{known: true}, "XRay", "tcp", ProvXRayPort) }
	diC := classifyDisk
	ctrC := func(p probe) ProvItem {
		return classifyContainers(parseProbe("DOCKER=yes\nSRVRC=0\nSRV=27.1\nEND\n", nil), p)
	}
	cases := []struct {
		name string
		f    cls
		out  string
		err  error
		want ProvState
	}{
		{"os ok", osC, okOS, nil, ProvOK},
		{"os old", osC, "ID=ubuntu\nVERSION_ID=18.04\nEND\n", nil, ProvBad},
		{"os foreign", osC, "ID=gentoo\nVERSION_ID=2\nEND\n", nil, ProvUnknown},
		{"os no file", osC, "OSREL=none\nEND\n", nil, ProvUnknown},
		{"os fail", osC, "", fail, ProvUnknown},
		// sshRunner при ошибке возвращает и накопленный stdout: полный вывод
		// с ошибкой — всё равно «не удалось», а не «годится».
		{"os fail with output", osC, okOS, fail, ProvUnknown},
		{"ports fail with output", func(p probe) ProvItem { return classifyPort(p, pubPorts{known: true}, "XRay", "tcp", ProvXRayPort) }, okPorts, fail, ProvUnknown},
		{"os empty", osC, "", nil, ProvUnknown},
		{"os no END", osC, "ID=ubuntu\nVERSION_ID=24.04\n", nil, ProvUnknown},

		{"kernel ok", kC, okKernel, nil, ProvOK},
		{"kernel old", kC, "KERNEL=2.6.32\nEND\n", nil, ProvBad},
		{"kernel blank", kC, "KERNEL=\nEND\n", nil, ProvUnknown},
		{"kernel fail", kC, "", fail, ProvUnknown},
		{"kernel empty", kC, "", nil, ProvUnknown},

		{"arch ok", aC, "ARCH=aarch64\nEND\n", nil, ProvOK},
		{"arch bad", aC, "ARCH=armv7l\nEND\n", nil, ProvBad},
		{"arch blank", aC, "ARCH=\nEND\n", nil, ProvUnknown},
		{"arch fail", aC, "", fail, ProvUnknown},
		{"arch empty", aC, "", nil, ProvUnknown},

		{"aa none", apC, "AA=none\nEND\n", nil, ProvOK},
		{"aa clean", apC, okHost, nil, ProvOK},
		{"aa wg loaded", apC, "AA=yes\nPROF=readable\nLOADED=wg-quick\nEND\n", nil, ProvBad},
		{"aa unreadable", apC, "AA=yes\nPROF=unreadable\nEND\n", nil, ProvUnknown},
		{"aa fail", apC, "", fail, ProvUnknown},
		{"aa empty", apC, "", nil, ProvUnknown},

		{"sudo root", suC, okSudo, nil, ProvOK},
		{"sudo nopasswd", suC, "UID=1000\nSUDORC=0\nSUDOERR=\nEND\n", nil, ProvOK},
		{"sudo needs pw", suC, "UID=1000\nSUDORC=1\nSUDOERR=sudo: a password is required\nEND\n", nil, ProvBad},
		{"sudo absent", suC, "UID=1000\nSUDO=none\nEND\n", nil, ProvBad},
		{"sudo uid blank", suC, "UID=\nEND\n", nil, ProvUnknown},
		{"sudo not asked", suC, "UID=1000\nEND\n", nil, ProvUnknown},
		{"sudo fail", suC, "", fail, ProvUnknown},
		{"sudo empty", suC, "", nil, ProvUnknown},

		{"docker absent", dC, okDocker, nil, ProvOK},
		{"docker running", dC, "DOCKER=yes\nSRVRC=0\nSRV=27.1.1\nEND\n", nil, ProvOK},
		{"docker daemon down", dC, "DOCKER=yes\nSRVRC=1\nSRV=Cannot connect to the Docker daemon at unix:///var/run/docker.sock. Is the docker daemon running?\nEND\n", nil, ProvOK}, // M1: установщик запустит
		{"docker denied", dC, "DOCKER=yes\nSRVRC=1\nSRV=permission denied while trying to connect\nEND\n", nil, ProvUnknown},
		{"docker blank", dC, "DOCKER=yes\nSRVRC=0\nSRV=\nEND\n", nil, ProvUnknown},
		{"docker fail", dC, "", fail, ProvUnknown},
		{"docker empty", dC, "", nil, ProvUnknown},

		{"ctr none", ctrC, "RC=0\nN=\nN=nginx\nEND\n", nil, ProvOK},
		{"ctr amnezia", ctrC, "RC=0\nN=amnezia-awg2\nEND\n", nil, ProvBad},
		{"ctr rc", ctrC, "RC=1\nN=error\nEND\n", nil, ProvUnknown},
		{"ctr fail", ctrC, "", fail, ProvUnknown},
		{"ctr empty", ctrC, "", nil, ProvUnknown},

		{"awg free", awgC, okPorts, nil, ProvOK},
		{"awg busy", awgC, "SSRC=0\nL=udp UNCONN 0 0 0.0.0.0:55424 0.0.0.0:*\nL=tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\nEND\n", nil, ProvBad},
		{"awg tcp only — udp свободен", awgC, "SSRC=0\nL=tcp LISTEN 0 128 0.0.0.0:55424 0.0.0.0:*\nEND\n", nil, ProvOK},
		{"xray busy v6", xC, "SSRC=0\nL=tcp LISTEN 0 511 [::]:443 [::]:*\nEND\n", nil, ProvBad},
		{"ports no ss", xC, "SS=none\nEND\n", nil, ProvUnknown},
		{"ports ss rc", xC, "SSRC=1\nL=boom\nEND\n", nil, ProvUnknown},
		{"ports no sockets", xC, "SSRC=0\nL=Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port\nEND\n", nil, ProvUnknown},
		{"ports fail", xC, "", fail, ProvUnknown},
		{"ports empty", xC, "", nil, ProvUnknown},

		{"disk ok", diC, okDisk, nil, ProvOK},
		{"disk low", diC, "DFPATH=/\nDFRC=0\nDF=/dev/vda1 41152736 41000000 500000 99% /\nEND\n", nil, ProvBad},
		{"disk rc", diC, "DFPATH=/\nDFRC=1\nDF=df: error\nEND\n", nil, ProvUnknown},
		{"disk garbage", diC, "DFPATH=/\nDFRC=0\nDF=x y z abc\nEND\n", nil, ProvUnknown},
		{"disk fail", diC, "", fail, ProvUnknown},
		{"disk empty", diC, "", nil, ProvUnknown},
	}
	for _, c := range cases {
		got := c.f(parseProbe(c.out, c.err))
		if got.State != c.want {
			t.Errorf("%s: %v (%s), ждали %v", c.name, got.State, got.Reason, c.want)
		}
		if got.Reason == "" {
			t.Errorf("%s: пустая причина", c.name)
		}
	}
}

// Контейнеры при недоступном Docker — Unknown, а не «нет контейнеров».
func TestProvContainersDockerUnknown(t *testing.T) {
	d := parseProbe("", errors.New("упало"))
	if got := classifyContainers(d, probe{}); got.State != ProvUnknown {
		t.Fatalf("Docker не проверен → контейнеры %v, ждали «не удалось»", got.State)
	}
}

func TestProvVerdictOrder(t *testing.T) {
	mk := func(ss ...ProvState) ProvisionReport {
		var r ProvisionReport
		for _, s := range ss {
			r.Items = append(r.Items, ProvItem{"x", s, "y"})
		}
		return r
	}
	cases := []struct {
		r    ProvisionReport
		want ProvVerdict
	}{
		{mk(ProvOK, ProvOK), ProvVerdictYes},
		{mk(ProvOK, ProvUnknown), ProvVerdictUnknown},
		{mk(ProvUnknown, ProvBad), ProvVerdictNo},
		{mk(ProvBad, ProvOK), ProvVerdictNo},
	}
	for i, c := range cases {
		if got := c.r.Verdict(); got != c.want {
			t.Errorf("%d: %v, ждали %v", i, got, c.want)
		}
	}
}

// Тест доезда: через Session и раннер. Здоровый сервер — можно; та же
// проба, упавшая боевым путём (ошибка раннера), — неизвестно, а не нельзя
// и не можно.
func TestProvisionCheckArrives(t *testing.T) {
	f := healthyFake()
	s := NewSessionWithRunner(f, &ServerCreds{User: "root"})
	r := s.ProvisionCheck()
	if v := r.Verdict(); v != ProvVerdictYes {
		t.Fatalf("здоровый сервер: %v; %+v", v, r.Items)
	}
	assertProvReadOnly(t, f.cmds)

	for _, tag := range []string{ProvOSTag, ProvKernelTag, DiagHostTag, ProvSudoTag, ProvDockerTag, ProvPortsTag, ProvDiskTag} {
		f := healthyFake()
		f.err[tag] = errors.New("обрыв")
		r := NewSessionWithRunner(f, &ServerCreds{User: "root"}).ProvisionCheck()
		if v := r.Verdict(); v != ProvVerdictUnknown {
			t.Errorf("упала проба %s: итог %v, ждали «неизвестно»; %+v", tag, v, r.Items)
		}
	}

	// Пустой ответ (без END) — тоже неизвестно.
	f = healthyFake()
	f.out[ProvPortsTag] = ""
	r = NewSessionWithRunner(f, &ServerCreds{User: "root"}).ProvisionCheck()
	if it := itemByPrefix(t, r, "порт XRay"); it.State != ProvUnknown {
		t.Fatalf("пустой вывод ss: %v", it.State)
	}

	// Настоящее «нет» тоже доезжает и отличается от «неизвестно».
	f = healthyFake()
	f.out[DiagHostTag] = "AA=yes\nPROF=readable\nLOADED=wg-quick\nLOADED=wg\nLOG=readable\nEND\n"
	r = NewSessionWithRunner(f, &ServerCreds{User: "root"}).ProvisionCheck()
	if v := r.Verdict(); v != ProvVerdictNo {
		t.Fatalf("профили wg загружены: %v", v)
	}
}

// Доезд контейнеров: Docker работает, на сервере уже amnezia-xray → нельзя;
// docker ps упал → неизвестно.
func TestProvisionCheckContainersArrive(t *testing.T) {
	f := healthyFake()
	f.out[ProvDockerTag] = "DOCKER=yes\nSRVRC=0\nSRV=27.1.1\nEND\n"
	f.out[ProvCtrTag] = "RC=0\nN=amnezia-xray\nEND\n"
	r := NewSessionWithRunner(f, &ServerCreds{User: "root"}).ProvisionCheck()
	if it := itemByPrefix(t, r, "контейнеры"); it.State != ProvBad {
		t.Fatalf("amnezia-xray есть: %v", it.State)
	}
	delete(f.out, ProvCtrTag)
	r = NewSessionWithRunner(f, &ServerCreds{User: "root"}).ProvisionCheck()
	if it := itemByPrefix(t, r, "контейнеры"); it.State != ProvUnknown {
		t.Fatalf("docker ps упал: %v", it.State)
	}
}

// Не root, Docker ответил «permission denied» — повтор через sudo -n; если
// повтор выполнился, берётся его ответ.
func TestProvisionCheckDockerSudoRetry(t *testing.T) {
	f := healthyFake()
	f.out[ProvSudoTag] = "UID=1000\nSUDORC=0\nSUDOERR=\nEND\n"
	f.out[ProvDockerTag] = "DOCKER=yes\nSRVRC=1\nSRV=permission denied while trying to connect\nEND\n"
	sf := &sudoFake{provFake: f, sudoOut: "DOCKER=yes\nSRVRC=0\nSRV=27.1.1\nEND\n"}
	r := NewSessionWithRunner(sf, &ServerCreds{User: "ubuntu"}).ProvisionCheck()
	if it := itemByPrefix(t, r, "Docker"); it.State != ProvOK {
		t.Fatalf("после sudo: %v %s", it.State, it.Reason)
	}
}

type sudoFake struct {
	*provFake
	sudoOut string
}

func (f *sudoFake) Run(cmd string, in []byte) (string, error) {
	if strings.HasPrefix(cmd, "sudo -n ") && strings.Contains(cmd, ProvDockerTag) {
		return f.sudoOut, nil
	}
	return f.provFake.Run(cmd, in)
}
