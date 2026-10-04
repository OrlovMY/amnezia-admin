package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"amnezia-admin/internal/fakesrv"
)

func cliRun(t *testing.T, kh string, stdin string, args ...string) (int, string, string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code := run(args, strings.NewReader(stdin), &out, &errOut, kh)
	return code, out.String(), errOut.String()
}

func serverPriv(t *testing.T, exec *fakesrv.Server) string {
	t.Helper()
	wg, _ := exec.File("/opt/amnezia/awg/wg0.conf")
	for _, l := range strings.Split(string(wg), "\n") {
		if strings.HasPrefix(l, "PrivateKey = ") {
			return strings.TrimPrefix(l, "PrivateKey = ")
		}
	}
	t.Fatal("нет PrivateKey")
	return ""
}

func flocks(exec *fakesrv.Server) int {
	n := 0
	for _, c := range exec.Commands() {
		if strings.Contains(c, "flock -w") {
			n++
		}
	}
	return n
}

// TestCLIBackupWarnsBeforeWrite — предупреждение SEC-01 «файл НЕ
// зашифрован» напечатано ДО строки о записи; файл 0600; секретов в выводе
// нет; код 0.
func TestCLIBackupWarnsBeforeWrite(t *testing.T) {
	key, kh, exec := setupFakeSSHForRunWithExec(t)
	p := filepath.Join(t.TempDir(), "c.aabk")
	code, out, errOut := cliRun(t, kh, "", "backup", "-key", key, "-o", p)
	if code != 0 {
		t.Fatalf("код %d: %s", code, errOut)
	}
	w := strings.Index(out, "НЕ ЗАШИФРОВАН")
	r := strings.Index(out, "Копия записана: ")
	if w < 0 || r < 0 || w > r {
		t.Fatalf("предупреждение не до записи (%d, %d):\n%s", w, r, out)
	}
	for _, part := range []string{"секретный ключ", "общие секреты", "ключ маскировки", "Windows", "смените ключ сервера"} {
		if !strings.Contains(out[w:r], part) {
			t.Errorf("в предупреждении нет «%s»", part)
		}
	}
	if strings.Contains(out+errOut, serverPriv(t, exec)) {
		t.Error("приватный ключ сервера в выводе")
	}
	fi, err := os.Stat(p)
	if err != nil || (runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600) {
		t.Errorf("файл копии: %v %v", fi, err)
	}
	code, out, _ = cliRun(t, kh, "", "backup-info", p)
	if code != 0 || !strings.Contains(out, "amnezia-awg") || strings.Contains(out, serverPriv(t, exec)) {
		t.Errorf("backup-info: %d\n%s", code, out)
	}
}

// TestCLIBackupIncomplete — не прочитан файл — код 3 (не 0 и не 1),
// «НЕПОЛНАЯ»; тест доезда через fakesrv.
func TestCLIBackupIncomplete(t *testing.T) {
	key, kh, exec := setupFakeSSHForRunWithExec(t)
	exec.FailRead = map[string]error{"/opt/amnezia/awg/clientsTable": errors.New("cat: Input/output error")}
	p := filepath.Join(t.TempDir(), "c.aabk")
	code, out, _ := cliRun(t, kh, "", "backup", "-key", key, "-o", p)
	if code != exitBackupIncomplete || !strings.Contains(out, "НЕПОЛНАЯ") {
		t.Fatalf("код %d:\n%s", code, out)
	}
}

// TestCLIBackupInfoCorrupt — повреждённый файл: «копия не прочитана», код 1.
func TestCLIBackupInfoCorrupt(t *testing.T) {
	p := filepath.Join(t.TempDir(), "bad.aabk")
	os.WriteFile(p, []byte("AABK 1\nlayer none\nsha256 00\n\n{}"), 0o600)
	code, _, errOut := cliRun(t, "", "", "backup-info", p)
	if code != 1 || !strings.Contains(errOut, "копия не прочитана") {
		t.Fatalf("код %d: %s", code, errOut)
	}
}

// TestCLIRestore — предпросмотр без записи; -apply без терминала и -yes —
// код 2, без записи; расхождение порта — код 4; -apply -yes — данные
// старого сервера на новом, автокопия в каталоге данных.
func TestCLIRestore(t *testing.T) {
	keyA, khA, srcExec := setupFakeSSHForRunWithExec(t)
	srcExec.SetFile("/opt/amnezia/awg/wireguard_psk.key", []byte("OLD-PSK\n"))
	p := filepath.Join(t.TempDir(), "c.aabk")
	if code, _, e := cliRun(t, khA, "", "backup", "-key", keyA, "-o", p); code != 0 {
		t.Fatalf("backup: %d %s", code, e)
	}
	keyB, khB, tgt := setupFakeSSHForRunWithExec(t)
	tgt.SetFile("/opt/amnezia/awg/wireguard_psk.key", []byte("NEW-PSK\n"))

	code, out, e := cliRun(t, khB, "", "restore", "-key", keyB, "-file", p)
	if code != 0 || !strings.Contains(out, "предпросмотр") || !strings.Contains(out, "УДАЛЕНЫ клиенты нового сервера") || flocks(tgt) != 0 {
		t.Fatalf("предпросмотр: %d %s\n%s", code, e, out)
	}
	// QA-01 р2 Н3: без терминала, -apply без -yes — код 2 и ни одной записи,
	// даже если на stdin «согласие» (вопрос без терминала не задаётся).
	if code, _, _ := cliRun(t, khB, "y\ny\n", "restore", "-key", keyB, "-file", p, "-apply"); code != 2 || flocks(tgt) != 0 {
		t.Fatalf("-apply без -yes: код %d, записей %d", code, flocks(tgt))
	}
	wg, _ := tgt.File("/opt/amnezia/awg/wg0.conf")
	tgt.SetFile("/opt/amnezia/awg/wg0.conf", []byte(strings.Replace(string(wg), "ListenPort = 51820", "ListenPort = 40000", 1)))
	code, out, _ = cliRun(t, khB, "", "restore", "-key", keyB, "-file", p, "-apply", "-yes")
	if code != exitRestoreStopped || !strings.Contains(out, "ОСТАНОВЛЕН") || !strings.Contains(out, "  1. amnezia-awg, порт:") || flocks(tgt) != 0 {
		t.Fatalf("порт другой (расхождения списком): код %d\n%s", code, out)
	}
	tgt.SetFile("/opt/amnezia/awg/wg0.conf", wg)
	code, out, e = cliRun(t, khB, "", "restore", "-key", keyB, "-file", p, "-apply", "-yes")
	if rm := strings.Index(out, "Будут УДАЛЕНЫ клиенты нового сервера"); rm < 0 || rm > strings.Index(out, "Копия: формат") {
		t.Errorf("раздел удаляемых не первым:\n%s", out)
	}
	if code != 0 || !strings.Contains(out, "amnezia-awg: восстановлен") {
		t.Fatalf("восстановление: %d %s\n%s", code, e, out)
	}
	for _, n := range []string{"wg0.conf", "clientsTable", "wireguard_psk.key"} {
		a, _ := srcExec.File("/opt/amnezia/awg/" + n)
		b, _ := tgt.File("/opt/amnezia/awg/" + n)
		if !bytes.Equal(a, b) {
			t.Errorf("%s на новом не равен старому", n)
		}
	}
	for _, part := range []string{"Автокопия нового сервера до замены: ", "Удалить сервер из приложения", "не этой программой"} {
		if !strings.Contains(out, part) {
			t.Errorf("в итоге нет «%s»", part)
		}
	}
	if strings.Contains(out, serverPriv(t, srcExec)) {
		t.Error("приватный ключ сервера в выводе")
	}
	dir, err := userBackupsDir()
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := filepath.Glob(filepath.Join(dir, "*.aabk")); len(got) == 0 {
		t.Errorf("автокопии нет в %s", dir)
	}
}

// TestCLIBackupSummaryNotIncluded — наблюдение AU-LOGIC: при «не входит»
// итог не говорит «все протоколы сохранены».
func TestCLIBackupSummaryNotIncluded(t *testing.T) {
	key, kh, exec := setupFakeSSHForRunWithExec(t)
	exec.Names = append(exec.Names, "amnezia-openvpn")
	p := filepath.Join(t.TempDir(), "c.aabk")
	_, out, _ := cliRun(t, kh, "", "backup", "-key", key, "-o", p)
	if strings.Contains(out, "Все протоколы сервера сохранены") || !strings.Contains(out, "Не входят в копию: amnezia-openvpn") {
		t.Errorf("итог:\n%s", out)
	}
}

// TestBackupCLIErrorsMasked — SEC-01 р2: в backup.go ни одна ошибка не
// печатается напрямую — только через backupErr (errText → MaskText).
// Подсадка «fmt.Fprintln(errOut, err)» роняет сторож.
func TestBackupCLIErrorsMasked(t *testing.T) {
	src, err := os.ReadFile("backup.go")
	if err != nil {
		t.Fatal(err)
	}
	re := regexp.MustCompile(`fmt\.Fprint\w*\([^\n]*\berr\b`)
	n := 0
	for i, l := range strings.Split(string(src), "\n") {
		if strings.Contains(l, "fmt.Fprint") {
			n++
		}
		if re.MatchString(l) && !strings.Contains(l, "errText(") {
			t.Errorf("backup.go:%d: ошибка печатается в обход backupErr: %s", i+1, strings.TrimSpace(l))
		}
	}
	if n < 5 {
		t.Fatalf("сторож ничего не видит: строк вывода %d", n)
	}
	var b bytes.Buffer
	backupErr(&b, "x: ", errors.New("клиент 3f1c2a9e-1b2c-4d5e-8f90-0123456789ab утёк"))
	if strings.Contains(b.String(), "3f1c2a9e-1b2c") {
		t.Errorf("backupErr не маскирует: %s", b.String())
	}
}
