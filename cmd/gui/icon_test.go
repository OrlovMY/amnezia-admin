package main

import (
	"bytes"
	"image/png"
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

// Значок встроен, непуст и это именно знак из assets/ (а не устаревшая
// копия): байты совпадают с assets/logo-256.png, картинка 256×256.
func TestAppIconMatchesAsset(t *testing.T) {
	if len(appIconPNG) == 0 || len(appIcon.Content()) == 0 {
		t.Fatal("значок приложения пуст")
	}
	img, err := png.Decode(bytes.NewReader(appIconPNG))
	if err != nil {
		t.Fatalf("значок не PNG: %v", err)
	}
	if b := img.Bounds(); b.Dx() != 256 || b.Dy() != 256 {
		t.Fatalf("размер значка %v, ожидался 256×256", b)
	}
	want, err := os.ReadFile(filepath.Join("..", "..", "assets", "logo-256.png"))
	if err != nil {
		t.Fatalf("нет assets/logo-256.png: %v", err)
	}
	if !bytes.Equal(appIconPNG, want) {
		t.Fatal("cmd/gui/icon.png разошёлся с assets/logo-256.png — скопируйте заново")
	}
}

// Значок действительно ставится приложению: строка в main() есть и не
// закомментирована. Без неё окно получает значок Fyne по умолчанию.
func TestAppIconIsSet(t *testing.T) {
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`(?m)^\s*a\.SetIcon\(appIcon\)\s*$`).Match(src) {
		t.Fatal("в main.go нет a.SetIcon(appIcon) — окно останется со значком Fyne")
	}
}

// Значок .exe: ресурс для windows/amd64 лежит в пакете (go build берёт
// *_windows_amd64.syso сам) и несёт все кадры текущего assets/logo.ico.
func TestWindowsResourceCarriesIcon(t *testing.T) {
	syso, err := os.ReadFile("rsrc_windows_amd64.syso")
	if err != nil {
		t.Fatalf("нет ресурса значка exe: %v", err)
	}
	for _, n := range []string{"16", "32", "48", "256"} {
		frame, err := os.ReadFile(filepath.Join("..", "..", "assets", "logo-"+n+".png"))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Contains(syso, frame) {
			t.Errorf("в rsrc_windows_amd64.syso нет кадра %s px из assets — пересоберите .syso", n)
		}
	}
}
