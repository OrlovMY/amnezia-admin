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

// H1/M1: имена устройств Windows и хвостовые точки — отказ на всех ОС,
// файл не создаётся; путь вне каталога или путь устройства — отказ;
// не обычный файл — отказ. В устройство тест не пишет.
// Подмены: убрать проверку имени / adminKeyTargetErr / adminKeyRegularErr → падает.
func TestWriteAdminKeyFileReserved(t *testing.T) {
	key, err := BuildAdminKey(adminInputT(t, adminKeyPw, 22))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	for _, n := range []string{"NUL", "nul.txt", "Con", "PRN.vpn", "aux", "COM0", "com9", "LPT5.txt", "COM²", "LPT¹", "CONIN$", "NUL .txt", "k.", "k2. .", "k "} {
		if _, err := WriteAdminKeyFile(filepath.Join(dir, n), key); err == nil {
			t.Errorf("имя %q принято", n)
		} else if strings.Contains(err.Error(), adminKeyPw) {
			t.Error("пароль в ошибке")
		}
	}
	if ents, _ := os.ReadDir(dir); len(ents) != 0 {
		t.Errorf("создано файлов: %d", len(ents))
	}
	// проверка имени — сама по себе, без опоры на Abs (на Windows хвостовую
	// точку срезает GetFullPathName, и отказ дал бы второй слой)
	for _, n := range []string{"NUL", "nul.txt", "COM¹", "k.", "k2. .", "k "} {
		if AdminKeyFileNameErr(n) == nil {
			t.Errorf("AdminKeyFileNameErr(%q) = nil", n)
		}
	}
	for _, ok := range []string{"nullable.txt", "con1", "COM10", "my.nul"} {
		if err := AdminKeyFileNameErr(ok); err != nil {
			t.Errorf("обычное имя %q отклонено: %v", ok, err)
		}
	}
	p := filepath.Join(dir, "k.txt")
	abs, _ := filepath.Abs(p)
	if err := adminKeyTargetErr(p, abs); err != nil {
		t.Errorf("обычный путь отклонён: %v", err)
	}
	for _, bad := range []string{`\\.\NUL`, `\\?\` + abs, filepath.Join(filepath.Dir(filepath.Dir(abs)), "k.txt"), filepath.Join(filepath.Dir(abs), "other.txt")} {
		if err := adminKeyTargetErr(p, bad); err == nil {
			t.Errorf("путь %q принят", bad)
		}
	}
	if err := adminKeyRegularErr(fakeFI{os.ModeDevice | os.ModeCharDevice}); err == nil {
		t.Error("устройство принято за файл")
	}
	if err := adminKeyRegularErr(fakeFI{0}); err != nil {
		t.Error("обычный файл отклонён")
	}
}

type fakeFI struct{ m os.FileMode }

func (f fakeFI) Name() string       { return "x" }
func (f fakeFI) Size() int64        { return 0 }
func (f fakeFI) Mode() os.FileMode  { return f.m }
func (f fakeFI) ModTime() time.Time { return time.Time{} }
func (f fakeFI) IsDir() bool        { return false }
func (f fakeFI) Sys() any           { return nil }
