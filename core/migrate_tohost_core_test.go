package core

import (
	"strings"
	"testing"
)

// R1 (ревью PR #69): subnet_address — адрес СЕТИ, а не адрес хоста
// интерфейса. Боевой awg0.conf несёт адрес хоста (10.8.1.1/24).
func TestAdminKeySubnetIsNetworkAddress(t *testing.T) {
	conf := strings.Replace(awg2Conf, "Address = 10.8.1.0/24", "Address = 10.8.1.1/24", 1)
	p, err := ProtocolParamsFromServer("amnezia-awg2", []byte(conf))
	if err != nil {
		t.Fatal(err)
	}
	if p["subnet_address"] != "10.8.1.0" || p["subnet_cidr"] != "24" {
		t.Fatalf("subnet_address=%v subnet_cidr=%v, ждали 10.8.1.0 и 24", p["subnet_address"], p["subnet_cidr"])
	}
	// Без маски сеть не вычислить — поля нет (обязательное → отказ), а не
	// адрес хоста под видом сети.
	conf = strings.Replace(awg2Conf, "Address = 10.8.1.0/24", "Address = 10.8.1.1", 1)
	if _, err := ProtocolParamsFromServer("amnezia-awg2", []byte(conf)); err == nil || !strings.Contains(err.Error(), "subnet_address") {
		t.Fatalf("адрес без маски: %v", err)
	}
}

// Порты предпроверки — из копии: XRay — tcp, остальные — udp, NotIncluded
// пропущен, нечитаемый порт — «узнать не удалось», а не умолчание.
func TestProvisionPortsFromBackup(t *testing.T) {
	b := instBackup()
	ports, bad := ProvisionPortsFromBackup(b)
	if len(bad) != 0 || len(ports) != 2 {
		t.Fatalf("ports=%v bad=%v", ports, bad)
	}
	if ports[0].Port != 51820 || ports[0].Proto != "udp" || ports[1].Port != 443 || ports[1].Proto != "tcp" {
		t.Fatalf("ports=%v", ports)
	}
	b.Containers[0].Port = "abc"
	_, bad = ProvisionPortsFromBackup(b)
	if len(bad) != 1 || bad[0].State != ProvUnknown {
		t.Fatalf("нечитаемый порт: %v", bad)
	}
	if _, bad = ProvisionPortsFromBackup(nil); len(bad) != 1 || bad[0].State != ProvUnknown {
		t.Fatalf("нет копии: %v", bad)
	}
}

// Доезд: ProvisionCheckFor проверяет порт КОПИИ (51820), а не умолчание
// (55424): занятый 51820 — «не годится», занятый 55424 — не мешает.
func TestProvisionCheckForUsesBackupPorts(t *testing.T) {
	healthy := healthyFake
	b := &Backup{Containers: []BackupContainer{{Name: "amnezia-awg2", Status: CtrSaved, Port: "51820"}}}
	f := healthy()
	f.out[ProvPortsTag] = "SSRC=0\nL=tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\nL=udp UNCONN 0 0 0.0.0.0:51820 0.0.0.0:*\nEND\n"
	if v := NewSessionWithRunner(f, &ServerCreds{Host: "h", Port: "22", User: "root"}).ProvisionCheckFor(b).Verdict(); v != ProvVerdictNo {
		t.Fatalf("занят порт копии: %v", v)
	}
	f = healthy()
	f.out[ProvPortsTag] = "SSRC=0\nL=tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\nL=udp UNCONN 0 0 0.0.0.0:55424 0.0.0.0:*\nEND\n"
	r := NewSessionWithRunner(f, &ServerCreds{Host: "h", Port: "22", User: "root"}).ProvisionCheckFor(b)
	for _, it := range r.Items {
		if strings.Contains(it.What, "55424") || (strings.Contains(it.What, "51820") && !strings.Contains(it.What, "из копии")) {
			t.Fatalf("пункт порта не из копии: %v", it)
		}
		if strings.Contains(it.What, "51820") && it.State != ProvOK {
			t.Fatalf("порт копии свободен, а пункт %v", it)
		}
	}
}
