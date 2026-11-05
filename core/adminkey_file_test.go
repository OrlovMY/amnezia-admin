package core

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// TestWriteAdminKeyFile — ключ пишется целиком (Reveal) в новый файл 0600;
// существующий файл не перезаписывается и ключа в ошибке нет; пустой ключ
// не пишется; имя файла — безопасное.
// Подмены: O_TRUNC вместо O_EXCL; права 0644; ключ в тексте ошибки — роняют.
func TestWriteAdminKeyFile(t *testing.T) {
	key, err := BuildAdminKey(adminInputT(t, adminKeyPw, 22))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	name := AdminKeyFileName("a b/c:1.example", time.Date(2026, 11, 6, 7, 8, 9, 0, time.UTC))
	if name != "admin-a_b_c_1.example-20261106-070809.vpn.txt" {
		t.Errorf("имя %q", name)
	}
	p := filepath.Join(dir, name)
	abs, err := WriteAdminKeyFile(p, key)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(abs)
	if string(raw) != key.Reveal()+"\n" {
		t.Error("в файле не ключ целиком")
	}
	if runtime.GOOS != "windows" {
		if st, _ := os.Stat(abs); st.Mode().Perm() != 0o600 {
			t.Errorf("права %v", st.Mode().Perm())
		}
	}
	_, err = WriteAdminKeyFile(p, key)
	if err == nil || !strings.Contains(err.Error(), "уже есть") || strings.Contains(err.Error(), adminKeyPw) || strings.Contains(err.Error(), "vpn://") {
		t.Errorf("повторная запись: %v", err)
	}
	if raw2, _ := os.ReadFile(abs); string(raw2) != string(raw) {
		t.Error("существующий файл изменён")
	}
	if _, err := WriteAdminKeyFile(filepath.Join(dir, "empty"), AdminKey{}); err == nil {
		t.Error("пустой ключ записан")
	}
}
