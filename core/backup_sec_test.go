package core

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"amnezia-admin/internal/fakesrv"
)

// allVerbs — все глаголы fmt, которыми можно напечатать значение (SEC-01:
// %d/%c/%U у []byte выдают байты, если Format у Secret не перехватывает).
var allVerbs = []string{"%v", "%+v", "%#v", "%T", "%s", "%q", "%x", "%X", "%d", "%c", "%U", "%b", "%o", "%O",
	"%e", "%E", "%f", "%F", "%g", "%G", "%p", "%t", "%8.3v", "%-20s", "% x", "%#x"}

// leakForms — представления байтов секрета без маскировки, которых не должно
// быть в выводе: при каждом глаголе (как напечатал бы его голый []byte) и
// сами байты.
func leakForms(secret []byte) []string {
	forms := []string{string(secret)}
	for _, v := range allVerbs {
		if v == "%T" || v == "%p" {
			continue
		}
		f := fmt.Sprintf(v, secret)
		if len(f) >= 16 {
			forms = append(forms, f[1:len(f)-1]) // без скобок/кавычек по краям
		}
	}
	return forms
}

// TestSecretAllVerbs — Secret, *Backup, BackupFile, срез, map, interface и
// значение panic: ни один глагол не выдаёт секрет. Подмена «удалить
// Format» роняет тест (%d/%c/%U).
func TestSecretAllVerbs(t *testing.T) {
	srv := fakesrv.New()
	wg, _ := srv.File("/opt/amnezia/awg/wg0.conf")
	b, _ := backupSession(t, srv).CollectBackup("t", backupNow, okResolver)
	f := fileOfB(ctrOf(t, b, "amnezia-awg"), "wg0.conf")
	sec := f.Data
	if sec.Len() < 50 {
		t.Fatalf("тест ничего не значит: %d байт", sec.Len())
	}
	values := map[string]any{
		"Secret": sec, "*Secret": &sec, "*Backup": b, "Backup": *b, "BackupFile": f,
		"[]Secret": []Secret{sec}, "map": map[string]Secret{"k": sec}, "any": any(sec),
	}
	forms := leakForms(wg)
	for name, v := range values {
		for _, verb := range allVerbs {
			out := fmt.Sprintf(verb, v)
			for _, lf := range forms {
				if strings.Contains(out, lf) {
					t.Fatalf("%s %s выдал секрет: %.80s", name, verb, out)
				}
			}
		}
	}
	// значение panic
	func() {
		defer func() {
			r := recover()
			out := fmt.Sprint(r)
			for _, lf := range forms {
				if strings.Contains(out, lf) {
					t.Fatalf("значение panic выдало секрет: %.80s", out)
				}
			}
		}()
		panic(sec)
	}()
}

// TestWriteBackupFileNoReplace — SEC-01: имя появилось между записью
// временного файла и созданием итогового → отказ, чужой файл цел;
// временный файл — с суффиксом .aabk и удалён.
func TestWriteBackupFileNoReplace(t *testing.T) {
	b, _ := backupSession(t, fakesrv.New()).CollectBackup("t", backupNow, okResolver)
	dir := t.TempDir()
	p := filepath.Join(dir, "x.aabk")
	var tmpSeen []string
	beforeBackupLink = func() {
		tmpSeen, _ = filepath.Glob(filepath.Join(dir, ".x.aabk.tmp-*.aabk"))
		if err := os.WriteFile(p, []byte("ЧУЖОЙ"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { beforeBackupLink = nil })
	err := WriteBackupFile(p, b, PlainLayer{})
	if err == nil || !strings.Contains(err.Error(), "уже есть") {
		t.Fatalf("ждали отказ «уже есть», получили %v", err)
	}
	if got, _ := os.ReadFile(p); string(got) != "ЧУЖОЙ" {
		t.Errorf("чужой файл изменён: %q", got)
	}
	if len(tmpSeen) != 1 {
		t.Errorf("временный файл с суффиксом .aabk не найден: %v", tmpSeen)
	}
	if left, _ := filepath.Glob(filepath.Join(dir, ".*tmp-*")); len(left) != 0 {
		t.Errorf("временный файл не удалён: %v", left)
	}
}
