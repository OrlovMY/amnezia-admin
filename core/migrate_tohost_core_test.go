package core

import (
	"encoding/json"
	"errors"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"amnezia-admin/internal/fakesrv"
)

// H2 (ревью PR #70): отказ входа по паролю из ключа — измеренное «не
// годится» (ErrAdminKeyAuthRejected), отличное и от «совпало», и от «сеть».
// Доезд — настоящий SSH-сервер (fakesrv), а не присваивание ошибки.
func TestVerifyAdminKeyAuthRejectedVsNetwork(t *testing.T) {
	srv, _ := newFakeSSHServer(t, "127.0.0.1:0")
	host, port, _ := strings.Cut(srv.Addr(), ":")
	kh := filepath.Join(t.TempDir(), "known_hosts")
	sess, err := ConnectWithHostKey(&ServerCreds{Host: host, Port: port, User: fakeSSHUser, Password: fakeSSHPassword},
		HostKeyPolicy{KnownHostsPath: kh, Prompt: func(string, string) bool { return true }})
	if err != nil {
		t.Fatal(err)
	}
	fp := sess.HostKeyFingerprint
	sess.Close()
	p, _ := strconv.Atoi(port)
	mk := func(pw string, port int) (AdminKey, AdminKeyInput) {
		in := AdminKeyInput{Host: host, Port: port, User: fakeSSHUser, Password: NewSecret([]byte(pw)), PasswordConsent: true}
		k, err := BuildAdminKey(in)
		if err != nil {
			t.Fatal(err)
		}
		return k, in
	}
	k, in := mk(fakeSSHPassword, p)
	if err := VerifyAdminKey(k, in, fp, kh); err != nil {
		t.Fatalf("верный пароль: %v", err)
	}
	k, in = mk("wrong-password", p)
	if err := VerifyAdminKey(k, in, fp, kh); !errors.Is(err, ErrAdminKeyAuthRejected) {
		t.Fatalf("неверный пароль: %v, ждали ErrAdminKeyAuthRejected", err)
	}
	// сеть: закрытый порт — НЕ «отказ входа»
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	_, cport, _ := strings.Cut(ln.Addr().String(), ":")
	ln.Close()
	cp, _ := strconv.Atoi(cport)
	k, in = mk(fakeSSHPassword, cp)
	if err := VerifyAdminKey(k, in, fp, kh); err == nil || errors.Is(err, ErrAdminKeyAuthRejected) || errors.Is(err, ErrAdminKeyMismatch) {
		t.Fatalf("сеть: %v — ждали «проверить не удалось»", err)
	}
}

// Ревью PR #70-2 M1: пустой список клиентов XRay допустим ТОЛЬКО при
// корректной в остальном форме — строгий разбор, не «запасной».
func TestProtocolParamsXRayEmptyClientsStrict(t *testing.T) {
	empty := strings.Replace(xraySrcJSON("443"), `{"id":"`+fkUUID+`","flow":"xtls-rprx-vision"}`, "", 1)
	if !strings.Contains(empty, `"clients":[]`) {
		t.Fatalf("образец не с пустым списком: %s", empty)
	}
	p, err := ProtocolParamsFromServer("amnezia-xray", []byte(empty))
	if err != nil || p["port"] != "443" || p["site"] != "www.example.com" {
		t.Fatalf("пустой список корректной формы: %v %v", p, err)
	}
	bad := strings.Replace(empty, `"decryption":"none"`, `"decryption":"none","fallbacks":[]`, 1)
	if _, err := ProtocolParamsFromServer("amnezia-xray", []byte(bad)); !errors.Is(err, ErrAdminKeyNoProtocolParams) {
		t.Fatalf("пустой список + неизвестное поле: %v", err)
	}
	bad = strings.Replace(empty, `"security":"reality"`, `"security":"tls"`, 1)
	if _, err := ProtocolParamsFromServer("amnezia-xray", []byte(bad)); !errors.Is(err, ErrAdminKeyNoProtocolParams) {
		t.Fatalf("пустой список + не reality: %v", err)
	}
	// Обычный разбор (перенос) пустой список по-прежнему не принимает.
	if _, err := parseXRayServer([]byte(empty)); err == nil {
		t.Fatal("parseXRayServer принял пустой список клиентов")
	}
}

// AdminKeyContainersFromServer на поддельном сервере: параметры с сервера
// (подсеть — адрес сети), XRay без клиентов — оговорка, нет контейнера —
// ошибка с именем.
func TestAdminKeyContainersFromServer(t *testing.T) {
	f := fakesrv.NewAWG2()
	s := NewSessionWithRunner(f, &ServerCreds{Host: "h", Port: "22", User: "root"})
	cs, notes, err := s.AdminKeyContainersFromServer([]string{"amnezia-awg2"})
	if err != nil || len(cs) != 1 || len(notes) != 0 {
		t.Fatalf("cs=%v notes=%v err=%v", cs, notes, err)
	}
	if cs[0].Protocol["subnet_address"] != "10.8.1.0" || cs[0].Protocol["port"] != "51820" || cs[0].Protocol["S3"] != "15" {
		t.Fatalf("параметры: %v", cs[0].Protocol)
	}
	if _, _, err := s.AdminKeyContainersFromServer([]string{"amnezia-xray"}); err == nil || !strings.Contains(err.Error(), "amnezia-xray") {
		t.Fatalf("нет контейнера: %v", err)
	}
	x := fakesrv.NewXRay("master")
	sx := NewSessionWithRunner(x, &ServerCreds{Host: "h", Port: "22", User: "root"})
	if _, notes, err := sx.AdminKeyContainersFromServer([]string{"amnezia-xray"}); err != nil || len(notes) != 0 {
		t.Fatalf("XRay с клиентами: notes=%v err=%v", notes, err)
	}
	raw, _ := x.File(fakesrv.XRayDir + "/server.json")
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	m["inbounds"].([]any)[0].(map[string]any)["settings"].(map[string]any)["clients"] = []any{}
	empty, _ := json.Marshal(m)
	x.SetFile(fakesrv.XRayDir+"/server.json", empty)
	cs, notes, err = sx.AdminKeyContainersFromServer([]string{"amnezia-xray"})
	if err != nil || len(cs) != 1 || len(notes) != 1 || notes[0] != XRayNoClientsNote {
		t.Fatalf("XRay без клиентов: cs=%v notes=%v err=%v", cs, notes, err)
	}
}

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
