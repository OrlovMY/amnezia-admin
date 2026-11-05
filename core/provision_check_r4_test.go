package core

// Аудит AU р1 PR #63: M1 (диск — каталог данных Docker), N6 (неразобранная
// запись docker ps не сбрасывает найденные занятые порты).

import (
	"strings"
	"testing"
)

const dfLine = "DF=/dev/x 41152736 3000000 %s 8%% /\n"

func diskOut(extra, avail string) string {
	return extra + "DFRC=0\nDF=/dev/x 41152736 3000000 " + avail + " 8% /\nEND\n"
}

// Тест различения M1: мерится каталог данных Docker, а не «/» по умолчанию.
func TestProvDiskWhere(t *testing.T) {
	const big, small = "36000000", "500000"
	cases := []struct {
		name string
		out  string
		want ProvState
		in   string // что обязано быть в причине
	}{
		{"нет Docker, /var отдельно и мал", diskOut("CHAIN=/var\nDFPATH=/var\n", small), ProvBad, "/var"},
		{"нет Docker, цепочка до /", diskOut("CHAIN=/\nDFPATH=/\n", big), ProvOK, "цепочке"},
		{"DockerRootDir измерен", diskOut("CHAIN=/var/lib/docker\nDRRC=0\nDROOT=/data/docker\nDFPATH=/data/docker\n", big), ProvOK, "DockerRootDir"},
		{"DockerRootDir назван, мерили другое", diskOut("CHAIN=/var/lib/docker\nDRRC=0\nDROOT=/data/docker\nDFPATH=/var/lib/docker\n", big), ProvUnknown, "/data/docker"},
		{"DockerRootDir пуст", diskOut("CHAIN=/\nDRRC=0\nDROOT=\nDFPATH=/\n", big), ProvUnknown, "каталог данных"},
		{"демон лежит — цепочка с пометкой", diskOut("CHAIN=/var/lib/docker\nDRRC=1\nDROOT=Cannot connect to the Docker daemon at unix:///var/run/docker.sock.\nDFPATH=/var/lib/docker\n", big), ProvOK, "остановлен"},
		{"нет прав на docker info", diskOut("CHAIN=/var/lib/docker\nDRRC=1\nDROOT=permission denied while trying to connect\nDFPATH=/var/lib/docker\n", big), ProvUnknown, "прочитать не удалось"},
		{"путь не напечатан", diskOut("", big), ProvUnknown, "определить не удалось"},
	}
	for _, c := range cases {
		got := classifyDisk(parseProbe(c.out, nil))
		if got.State != c.want || !strings.Contains(got.Reason, c.in) {
			t.Errorf("%s: %v (%s), ждали %v и «%s»", c.name, got.State, got.Reason, c.want, c.in)
		}
	}
}

// Доезд M1: Docker работает, DockerRootDir на малом разделе → «нельзя».
func TestProvisionCheckDiskDockerRootArrives(t *testing.T) {
	f := healthyFake()
	f.out[ProvDiskTag] = diskOut("CHAIN=/var/lib/docker\nDRRC=0\nDROOT=/srv/docker\nDFPATH=/srv/docker\n", "400000")
	r := NewSessionWithRunner(f, &ServerCreds{User: "root"}).ProvisionCheck()
	it := itemByPrefix(t, r, "свободное место")
	if it.State != ProvBad || !strings.Contains(it.Reason, "/srv/docker") {
		t.Fatalf("DockerRootDir мал: %v %s", it.State, it.Reason)
	}
}

// Доезд M1, не root: docker info «permission denied» → повтор через sudo -n.
func TestProvisionCheckDiskSudoRetry(t *testing.T) {
	f := healthyFake()
	f.out[ProvDiskTag] = diskOut("CHAIN=/var/lib/docker\nDRRC=1\nDROOT=permission denied\nDFPATH=/var/lib/docker\n", "36000000")
	sf := &diskSudoFake{provFake: f, sudoOut: diskOut("CHAIN=/var/lib/docker\nDRRC=0\nDROOT=/srv/docker\nDFPATH=/srv/docker\n", "36000000")}
	r := NewSessionWithRunner(sf, &ServerCreds{User: "ubuntu"}).ProvisionCheck()
	if it := itemByPrefix(t, r, "свободное место"); it.State != ProvOK || !strings.Contains(it.Reason, "/srv/docker") {
		t.Fatalf("после sudo: %v %s", it.State, it.Reason)
	}
}

type diskSudoFake struct {
	*provFake
	sudoOut string
}

func (f *diskSudoFake) Run(cmd string, in []byte) (string, error) {
	if strings.HasPrefix(cmd, "sudo -n ") && strings.Contains(cmd, ProvDiskTag) {
		return f.sudoOut, nil
	}
	return f.provFake.Run(cmd, in)
}

// N6: занятый порт найден, а соседняя запись не разобрана — «нельзя» с
// пометкой «список неполный», а не «не удалось».
func TestProvPortIncompleteKeepsBusy(t *testing.T) {
	d := parseProbe("DOCKER=yes\nSRVRC=0\nSRV=27.1\nEND\n", nil)
	c := parseProbe("RC=0\nN=caddy|0.0.0.0:443->443/tcp, 0.0.0.0:abc->1/tcp\nEND\n", nil)
	pub := publishedPorts(d, c)
	ss := parseProbe(okPorts, nil)
	got := classifyPort(ss, pub, "XRay", "tcp", ProvXRayPort)
	if got.State != ProvBad || !strings.Contains(got.Reason, "неполный") {
		t.Fatalf("занятый при неполном списке: %v %s", got.State, got.Reason)
	}
	// Тот же неполный список и свободный порт — «не удалось», не «свободен».
	if got := classifyPort(ss, pub, "AWG", "udp", ProvAWGPort); got.State != ProvUnknown {
		t.Fatalf("свободный при неполном списке: %v %s", got.State, got.Reason)
	}
}
