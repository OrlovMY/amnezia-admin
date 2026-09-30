package main

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

// TestInsideTempDirShortName — КАНАРЕЙКА сравнения путей (ревью QA-01, п.6):
// тот же каталог, записанный короткой формой 8.3 (как %TEMP% бывает на
// раннере: C:\Users\RUNNER~1\…), обязан считаться лежащим во временном
// каталоге, а соседний каталог вне его — нет.
func TestInsideTempDirShortName(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "Очень длинное имя каталога")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	p, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]uint16, 1024)
	n, err := windows.GetShortPathName(p, &buf[0], uint32(len(buf)))
	if err != nil || n == 0 {
		t.Skipf("короткие имена на этом томе выключены: %v", err)
	}
	short := windows.UTF16ToString(buf[:n])
	if !insideTempDir(short) {
		t.Errorf("короткая форма %q не распознана как лежащая во временном каталоге", short)
	}
	if !insideTempDir(filepath.Join(short, "ещё-не-создан")) {
		t.Errorf("несуществующий хвост под короткой формой не распознан")
	}
	if insideTempDir(filepath.Dir(canonPath(os.TempDir()))) {
		t.Errorf("родитель временного каталога ошибочно считается лежащим внутри него")
	}
}
