package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"amnezia-admin/core"
)

// TestPasswordFileOpenWarning — SEC-01 Н-5: на Linux/macOS файл пароля,
// доступный группе или прочим, — предупреждение (не отказ); 0600 — без
// предупреждения. На Windows права так не выражаются — не проверяется.
func TestPasswordFileOpenWarning(t *testing.T) {
	openMode := os.FileMode(0o600) | os.FileMode(0o600)>>3 // доступ группе
	if runtime.GOOS == "windows" {
		if passwordFileOpen(openMode) {
			t.Error("на Windows по правам предупреждать нечем")
		}
		t.Skip("Windows: права файла не выражают доступ группе/прочим")
	}
	var buf bytes.Buffer
	oldOut, oldMode := passwordWarnOut, fileModeOf
	passwordWarnOut = &buf
	t.Cleanup(func() { passwordWarnOut, fileModeOf = oldOut, oldMode })
	p := writePwFile(t, cliTestPassword)
	fileModeOf = func(string) (os.FileMode, error) { return openMode, nil }
	if pw, err := readPasswordFile(p); err != nil || string(pw.Bytes()) != cliTestPassword {
		t.Fatalf("чтение: %v", err)
	}
	if !strings.Contains(buf.String(), "доступен группе") {
		t.Errorf("нет предупреждения для открытого файла: %q", buf.String())
	}
	buf.Reset()
	fileModeOf = oldMode // настоящий файл 0600
	readPasswordFile(p)
	if buf.Len() != 0 {
		t.Errorf("предупреждение для 0600: %q", buf.String())
	}
}

// TestCLIAutoCopyInheritsLayer — автокопия перед восстановлением наследует
// режим копии-источника: из зашифрованной — тем же паролем (без него не
// открывается); из незашифрованной — без пароля и с предупреждением в
// итоге. Подмена «автокопия всегда без пароля» роняет тест.
func TestCLIAutoCopyInheritsLayer(t *testing.T) {
	lightArgon(t)
	keyA, khA, srcExec := setupFakeSSHForRunWithExec(t)
	srcExec.SetFile("/opt/amnezia/awg/wireguard_psk.key", []byte("OLD-PSK\n"))
	good := writePwFile(t, cliTestPassword)
	enc := filepath.Join(t.TempDir(), "enc.aabk")
	plain := filepath.Join(t.TempDir(), "plain.aabk")
	cliRun(t, khA, "", "backup", "-key", keyA, "-o", enc, "-password-file", good)
	cliRun(t, khA, "", "backup", "-key", keyA, "-o", plain, "-no-password")
	auto := func(out string) string {
		for _, l := range strings.Split(out, "\n") {
			if i := strings.Index(l, "Автокопия нового сервера до замены: "); i >= 0 {
				return strings.TrimSpace(l[i+len("Автокопия нового сервера до замены: "):])
			}
		}
		t.Fatalf("нет пути автокопии:\n%s", out)
		return ""
	}

	keyB, khB, tgt := setupFakeSSHForRunWithExec(t)
	tgt.SetFile("/opt/amnezia/awg/wireguard_psk.key", []byte("NEW-PSK\n"))
	code, out, e := cliRun(t, khB, "", "restore", "-key", keyB, "-file", enc, "-password-file", good, "-apply", "-yes")
	if code != 0 {
		t.Fatalf("restore из зашифрованной: %d %s\n%s", code, e, out)
	}
	ap := auto(out)
	if l, _ := core.BackupLayerOf(ap); l != core.PasswordLayerName {
		t.Fatalf("автокопия из зашифрованной — слой %q", l)
	}
	if _, err := core.ReadBackupFile(ap, core.PasswordLayer{Password: core.NewSecret([]byte(cliTestPassword))}); err != nil {
		t.Errorf("автокопия не открывается паролем источника: %v", err)
	}
	if _, err := core.ReadBackupFile(ap, core.PlainLayer{}); !errors.Is(err, core.ErrBackupNotRead) {
		t.Errorf("автокопия открылась без пароля: %v", err)
	}
	if strings.Contains(out, core.AutoCopyUnencryptedNote) {
		t.Error("у зашифрованной автокопии предупреждение «НЕ зашифрована»")
	}

	keyC, khC, tgt2 := setupFakeSSHForRunWithExec(t)
	tgt2.SetFile("/opt/amnezia/awg/wireguard_psk.key", []byte("NEW-PSK\n"))
	code, out, e = cliRun(t, khC, "", "restore", "-key", keyC, "-file", plain, "-apply", "-yes")
	if code != 0 || !strings.Contains(out, core.AutoCopyUnencryptedNote) {
		t.Fatalf("restore из незашифрованной: %d %s\n%s", code, e, out)
	}
	if l, _ := core.BackupLayerOf(auto(out)); l != "none" {
		t.Errorf("автокопия из незашифрованной — слой %q", l)
	}
}
