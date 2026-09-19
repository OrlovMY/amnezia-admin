package main

// Права файлов, создаваемых GUI (PR-A4, пункт 2): crash.log и ui.json
// обязаны быть недоступны другим пользователям машины.
//
// ЧЕСТНО О WINDOWS. POSIX-биты на Windows не применяются: разграничение там
// задаётся ACL, а Go из режима файла использует только флаг «только для
// чтения». os.Stat там вернёт 0666 и на 0600, и на 0644 — то есть этот тест
// на Windows не отличает починенный код от сломанного. Зелёная галочка в
// таком случае была бы враньём, поэтому на Windows тест ПРОПУСКАЕТСЯ с
// причиной, а место 0644 удерживает структурный сторож
// internal/permguard (он платформы не касается, потому что читает исходники).

import (
	"os"
	"runtime"
	"testing"
)

func skipIfNoPosixPerms(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("права файлов на Windows задаются ACL, а не POSIX-битами: os.Stat вернёт 0666 и для 0600, и для 0644 — проверять здесь нечего; место 0644 держит сторож internal/permguard")
	}
}

func assertOwnerOnly(t *testing.T, path string) {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	if perm := fi.Mode().Perm(); perm&0o077 != 0 {
		t.Fatalf("права %s = %#o, want без доступа группе и остальным (0600)", path, perm)
	}
}

func TestCrashLogIsOwnerOnly(t *testing.T) {
	skipIfNoPosixPerms(t)
	dir := t.TempDir()
	if err := writeCrashLog(dir, "panic: тест\n"); err != nil {
		t.Fatalf("writeCrashLog: %v", err)
	}
	assertOwnerOnly(t, dir+"/crash.log")
}

func TestUIStateIsOwnerOnly(t *testing.T) {
	skipIfNoPosixPerms(t)
	dir := t.TempDir()
	saveSortStateTo(dir, sortStateJSON{Primary: "name", PrimaryDir: "asc"})
	assertOwnerOnly(t, uiStatePathIn(dir))
}
