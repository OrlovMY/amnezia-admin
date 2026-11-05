package core

// Аудит-2 AU, L2: демон Docker остановлен, data-root перенесён в
// /etc/docker/daemon.json — мерить его, а не цепочку по умолчанию.

import (
	"strings"
	"testing"
)

const stoppedDisk = "CHAIN=/var/lib/docker\nDRRC=1\nDROOT=Cannot connect to the Docker daemon at unix:///var/run/docker.sock.\n"

func atOut(path, avail string) probe {
	return parseProbe("DFPATH="+path+"\nDFRC=0\nDF=/dev/y 41152736 3000000 "+avail+" 8% "+path+"\nEND\n", nil)
}

// Тест различения: файла нет / data-root задан / файл не прочитан / не
// разобран / data-root не задан / путь непригоден.
func TestProvDiskDaemonJSON(t *testing.T) {
	big := "DFPATH=/var/lib/docker\nDFRC=0\nDF=/dev/x 41152736 3000000 36000000 8% /\nEND\n"
	cases := []struct {
		name string
		out  string
		at   probe
		want ProvState
		in   string
	}{
		{"файла нет — цепочка", stoppedDisk + "DJFILE=none\n" + big, probe{}, ProvOK, "не задан"},
		{"data-root задан, мал", stoppedDisk + "DJRC=0\nDJ={\nDJ=  \"data-root\": \"/srv/docker\"\nDJ=}\n" + big, atOut("/srv", "400000"), ProvBad, "/srv/docker"},
		{"data-root задан, велик", stoppedDisk + "DJRC=0\nDJ={\"data-root\":\"/srv/docker\"}\n" + big, atOut("/srv/docker", "36000000"), ProvOK, "daemon.json"},
		{"graph (старое имя)", stoppedDisk + "DJRC=0\nDJ={\"graph\":\"/srv/docker\"}\n" + big, atOut("/srv/docker", "400000"), ProvBad, "/srv/docker"},
		{"файл не прочитан", stoppedDisk + "DJRC=1\nDJ=cat: /etc/docker/daemon.json: Permission denied\n" + big, probe{}, ProvUnknown, "прочитать не удалось"},
		{"файл не разобран", stoppedDisk + "DJRC=0\nDJ={data-root:\n" + big, probe{}, ProvUnknown, "не разобран"},
		{"data-root не задан", stoppedDisk + "DJRC=0\nDJ={\"log-level\":\"warn\"}\n" + big, probe{}, ProvOK, "не задан"},
		{"путь непригоден", stoppedDisk + "DJRC=0\nDJ={\"data-root\":\"/srv/$(x)\"}\n" + big, probe{}, ProvUnknown, "путь не разобран"},
		{"путь задан, df не выполнен", stoppedDisk + "DJRC=0\nDJ={\"data-root\":\"/srv/docker\"}\n" + big, parseProbe("", errEmpty), ProvUnknown, "измерить не удалось"},
	}
	for _, c := range cases {
		got := classifyDisk(parseProbe(c.out, nil), c.at)
		if got.State != c.want || !strings.Contains(got.Reason, c.in) {
			t.Errorf("%s: %v (%s), ждали %v и «%s»", c.name, got.State, got.Reason, c.want, c.in)
		}
	}
}

var errEmpty = errString("обрыв")

type errString string

func (e errString) Error() string { return string(e) }

// Тест доезда: демон лежит, data-root в daemon.json → вторая проба df этого
// каталога выполняется боевым путём, мал → «нельзя».
func TestProvisionCheckDaemonJSONArrives(t *testing.T) {
	f := healthyFake()
	f.out[ProvDiskTag] = stoppedDisk + "DJRC=0\nDJ={\"data-root\":\"/srv/docker\"}\nDFPATH=/var/lib/docker\nDFRC=0\nDF=/dev/x 41152736 3000000 36000000 8% /\nEND\n"
	f.out[ProvDiskAtTag] = "DFPATH=/srv\nDFRC=0\nDF=/dev/y 1000000 900000 300000 90% /srv\nEND\n"
	r := NewSessionWithRunner(f, &ServerCreds{User: "root"}).ProvisionCheck()
	it := itemByPrefix(t, r, "свободное место")
	if it.State != ProvBad || !strings.Contains(it.Reason, "/srv/docker") {
		t.Fatalf("data-root мал: %v %s", it.State, it.Reason)
	}
	ran := false
	for _, c := range f.cmds {
		if c == provCmd(provDiskAtScript("/srv/docker")) {
			ran = true
		}
	}
	if !ran {
		t.Fatalf("проба data-root не выполнялась: %q", f.cmds)
	}
	// Та же картина, daemon.json не прочитан — «не удалось», не «годится».
	f.out[ProvDiskTag] = stoppedDisk + "DJRC=1\nDJ=Permission denied\nDFPATH=/var/lib/docker\nDFRC=0\nDF=/dev/x 41152736 3000000 36000000 8% /\nEND\n"
	r = NewSessionWithRunner(f, &ServerCreds{User: "root"}).ProvisionCheck()
	if it := itemByPrefix(t, r, "свободное место"); it.State != ProvUnknown {
		t.Fatalf("daemon.json не прочитан: %v %s", it.State, it.Reason)
	}
}

func TestProvDiskAtScriptChain(t *testing.T) {
	s := provDiskAtScript("/srv/docker/x")
	for _, want := range []string{"if [ -d /srv/docker/x ]", "elif [ -d /srv/docker ]", "elif [ -d /srv ]", "p=/;"} {
		if !strings.Contains(s, want) {
			t.Errorf("нет %q в %s", want, s)
		}
	}
}
