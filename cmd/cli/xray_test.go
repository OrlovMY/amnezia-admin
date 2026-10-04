package main

// AL-01: XRay в CLI через полный run() и настоящий SSH (fakesrv.ListenSSH).

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"amnezia-admin/core"
	"amnezia-admin/internal/fakesrv"
)

var reUUIDFull = regexp.MustCompile(`[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)

func setupXRayRun(t *testing.T) (key, kh string, exec *fakesrv.Server) {
	t.Helper()
	t.Cleanup(core.SetXRayWaits(0, 0))
	const user, password = "root", "fakepw-xray-test"
	hostKey, err := fakesrv.NewHostKey()
	if err != nil {
		t.Fatal(err)
	}
	exec = fakesrv.NewXRay("master")
	srv, err := fakesrv.ListenSSH("127.0.0.1:0", user, password, hostKey, exec)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { srv.Close() })
	key = buildTestVpnKey(t, srv.Addr(), user, password)
	kh = filepath.Join(t.TempDir(), "known_hosts")
	var out, errOut bytes.Buffer
	if code := run([]string{"list", "-key", key, "-hostkey", srv.Fingerprint()}, strings.NewReader(""), &out, &errOut, kh); code != 0 {
		t.Fatalf("list: %d %s", code, errOut.String())
	}
	return key, kh, exec
}

func xrayWrites(exec *fakesrv.Server) int {
	n := 0
	for _, c := range exec.Commands() {
		if strings.Contains(c, "flock") || strings.HasPrefix(c, "docker restart") || strings.Contains(c, "/backup") {
			n++
		}
	}
	return n
}

func xrayIDOf(t *testing.T, exec *fakesrv.Server, name string) string {
	t.Helper()
	b, _ := exec.File("/opt/amnezia/xray/clientsTable")
	var list []core.ClientEntry
	if err := json.Unmarshal(b, &list); err != nil {
		t.Fatal(err)
	}
	for _, c := range list {
		if c.Name() == name {
			return c.ClientID
		}
	}
	return ""
}

// TestXRayCLIList — список: «—» и пояснение вместо трафика, служебная
// строка, отпечатки вместо UUID.
func TestXRayCLIList(t *testing.T) {
	key, kh, _ := setupXRayRun(t)
	var out, errOut bytes.Buffer
	if code := run([]string{"list", "-key", key}, strings.NewReader(""), &out, &errOut, kh); code != 0 {
		t.Fatalf("%d %s", code, errOut.String())
	}
	s := out.String()
	for _, want := range []string{"Alice", "Bob", core.XRayServiceName, core.XRayStatsNote, "включён"} {
		if !strings.Contains(s, want) {
			t.Errorf("нет %q в\n%s", want, s)
		}
	}
	if reUUIDFull.MatchString(s) || strings.Contains(s, "0 B") || strings.Contains(s, "не подключался") {
		t.Errorf("UUID или ложный ноль в списке:\n%s", s)
	}
}

// TestXRayCLIRefuseWithoutYes — без терминала и без -yes каждое действие с
// перезапуском — отказ, код 2, ни одной команды записи и перезапуска; в
// выводе — предупреждение. Включение (у WG без вопроса) у XRay тоже
// спрашивает: оно перезапускает XRay.
func TestXRayCLIRefuseWithoutYes(t *testing.T) {
	for _, args := range [][]string{
		{"add", "-name", "Carol"},
		{"del", "-name", "Alice"},
		{"rekey", "-name", "Alice"},
		{"toggle", "-name", "Alice"},
	} {
		t.Run(args[0], func(t *testing.T) {
			key, kh, exec := setupXRayRun(t)
			before := xrayWrites(exec)
			var out, errOut bytes.Buffer
			code := run(append(args, "-key", key), strings.NewReader("y\n"), &out, &errOut, kh)
			if code != 2 || xrayWrites(exec) != before || exec.XRayRestarts() != 0 {
				t.Fatalf("код %d, записей %d→%d, перезапусков %d; %s", code, before, xrayWrites(exec), exec.XRayRestarts(), errOut.String())
			}
			if !strings.Contains(out.String(), "XRay будет перезапущен") || !strings.Contains(out.String(), "узнать нельзя") {
				t.Errorf("нет предупреждения:\n%s", out.String())
			}
			if reUUIDFull.MatchString(out.String() + errOut.String()) {
				t.Errorf("UUID в выводе:\n%s", out.String())
			}
		})
	}
	// включение отключённого — тоже вопрос
	key, kh, exec := setupXRayRun(t)
	var out, errOut bytes.Buffer
	if code := run([]string{"toggle", "-key", key, "-name", "Bob", "-yes"}, strings.NewReader(""), &out, &errOut, kh); code != 0 {
		t.Fatalf("отключение -yes: %d %s", code, errOut.String())
	}
	n := exec.XRayRestarts()
	out.Reset()
	if code := run([]string{"toggle", "-key", key, "-name", "Bob"}, strings.NewReader(""), &out, &errOut, kh); code != 2 || exec.XRayRestarts() != n {
		t.Fatalf("включение без -yes: код %d, перезапусков %d→%d", code, n, exec.XRayRestarts())
	}
}

// TestXRayCLIYes — -yes печатает предупреждение и выполняет; add — 1
// перезапуск и файл .json; del — карточка с отпечатком и «неизвестно»;
// rename — без предупреждения и без перезапуска.
func TestXRayCLIYes(t *testing.T) {
	key, kh, exec := setupXRayRun(t)
	var out, errOut bytes.Buffer
	if code := run([]string{"add", "-key", key, "-name", "Carol", "-yes"}, strings.NewReader(""), &out, &errOut, kh); code != 0 {
		t.Fatalf("add: %d %s", code, errOut.String())
	}
	if exec.XRayRestarts() != 1 || !strings.Contains(out.String(), "XRay будет перезапущен") || !strings.Contains(out.String(), "Carol.json") {
		t.Fatalf("add: перезапусков %d\n%s", exec.XRayRestarts(), out.String())
	}
	if reUUIDFull.MatchString(out.String()) {
		t.Errorf("UUID в выводе add:\n%s", out.String())
	}

	out.Reset()
	alice := xrayIDOf(t, exec, "Alice")
	if code := run([]string{"del", "-key", key, "-name", "Alice", "-yes"}, strings.NewReader(""), &out, &errOut, kh); code != 0 {
		t.Fatalf("del: %d %s", code, errOut.String())
	}
	s := out.String()
	if exec.XRayRestarts() != 2 || !strings.Contains(s, core.UUIDPrint(alice)) || strings.Contains(s, alice) ||
		!strings.Contains(s, "неизвестно (XRay не отдаёт статистику)") || !strings.Contains(s, "XRay будет перезапущен") {
		t.Fatalf("del:\n%s", s)
	}

	out.Reset()
	if code := run([]string{"rename", "-key", key, "-name", "Bob", "-newname", "Боб"}, strings.NewReader(""), &out, &errOut, kh); code != 0 {
		t.Fatalf("rename: %d %s", code, errOut.String())
	}
	if exec.XRayRestarts() != 2 || strings.Contains(out.String(), "перезапущен") {
		t.Fatalf("rename перезапускает или предупреждает:\n%s", out.String())
	}
}

// TestXRayCLIShowConfig — конфиг существующего клиента: без -print UUID не
// печатается; с -print — ссылка vless://.
func TestXRayCLIShowConfig(t *testing.T) {
	key, kh, exec := setupXRayRun(t)
	var out, errOut bytes.Buffer
	if code := run([]string{"show-config", "-key", key, "-name", "Bob"}, strings.NewReader(""), &out, &errOut, kh); code != 0 {
		t.Fatalf("%d %s", code, errOut.String())
	}
	if reUUIDFull.MatchString(out.String()) || !strings.Contains(out.String(), "Bob.json") {
		t.Fatalf("без -print:\n%s", out.String())
	}
	out.Reset()
	if code := run([]string{"show-config", "-key", key, "-name", "Bob", "-print"}, strings.NewReader(""), &out, &errOut, kh); code != 0 {
		t.Fatalf("%d %s", code, errOut.String())
	}
	if !strings.Contains(out.String(), "vless://"+xrayIDOf(t, exec, "Bob")+"@") || exec.XRayRestarts() != 0 {
		t.Fatalf("-print:\n%s", out.String())
	}
}
