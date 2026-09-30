package testpath

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestInsideTempDir — таблица из ревью QA долгов (раунд 2). От ответа
// зависит, удалит ли тест (os.RemoveAll в Cleanup) каталог рядом с
// бинарником: ложное «внутри» стоило бы настоящих данных. Случаи одной ОС
// на других не молчат — пропускаются с названной причиной.
func TestInsideTempDir(t *testing.T) {
	tmp := os.TempDir()
	sub, err := os.MkdirTemp("", "testpath")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(sub) })
	outside, err := os.Getwd() // каталог пакета — не во временном
	if err != nil {
		t.Fatal(err)
	}
	if InsideTempDir(outside) {
		t.Fatalf("проверка ПЕРЕСТАЛА ЧТО-ЛИБО ЗНАЧИТЬ: каталог пакета %s лежит во временном", outside)
	}

	cases := []struct {
		name string
		os   string // "" — любая ОС
		path func(t *testing.T) string
		want bool
	}{
		{"сам TempDir", "", func(*testing.T) string { return tmp }, false},
		{"подкаталог TempDir (есть)", "", func(*testing.T) string { return sub }, true},
		{"подкаталог TempDir (ещё нет)", "", func(*testing.T) string { return filepath.Join(sub, "нет", "глубже") }, true},
		{"TempDir/..", "", func(*testing.T) string { return filepath.Join(tmp, "..") }, false},
		{"TempDir/sub/../..", "", func(*testing.T) string { return filepath.Join(sub, "..", "..") }, false},
		{"сосед с общим префиксом", "", func(*testing.T) string {
			return filepath.Clean(tmp) + "x" + string(filepath.Separator) + "y"
		}, false},
		{"ссылка в TempDir на каталог в TempDir", "", func(t *testing.T) string {
			target := filepath.Join(sub, "цель")
			os.Mkdir(target, 0o700)
			return symlinkOrSkip(t, target, filepath.Join(sub, "ссылка-внутрь"))
		}, true},
		{"ссылка в TempDir на каталог ВНЕ TempDir", "", func(t *testing.T) string {
			return symlinkOrSkip(t, outside, filepath.Join(sub, "ссылка-наружу"))
		}, false},
		{"другой диск", "windows", func(*testing.T) string {
			vol := strings.ToUpper(filepath.VolumeName(tmp))
			other := "Z:"
			if vol == "Z:" {
				other = "Y:"
			}
			return other + `\` + strings.TrimPrefix(filepath.Clean(tmp), filepath.VolumeName(tmp)) + `\x`
		}, false},
		{"регистр не влияет", "windows", func(*testing.T) string { return strings.ToUpper(sub) }, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if c.os != "" && runtime.GOOS != c.os {
				t.Skipf("случай только для %s (здесь %s)", c.os, runtime.GOOS)
			}
			p := c.path(t)
			if got := InsideTempDir(p); got != c.want {
				t.Fatalf("InsideTempDir(%q) = %v, ожидалось %v (TempDir %q)", p, got, c.want, tmp)
			}
		})
	}
}

// symlinkOrSkip создаёт ссылку; где ОС не даёт (Windows без режима
// разработчика), случай пропускается ВСЛУХ.
func symlinkOrSkip(t *testing.T, target, link string) string {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("символьную ссылку создать нельзя (%v) — случай не проверен", err)
	}
	return link
}
