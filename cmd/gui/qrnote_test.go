package main

// Третье состояние: текстовый QR влез, а QR AmneziaVPN не построен — это
// сказано вслух (приложение назовёт сервер «Сервер N»), а не молча
// подменено текстовым QR. XRay — не потеря (метка ссылки), пометки нет.

import (
	"strings"
	"testing"

	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/test"
)

func TestQRNoteWhenAmneziaFormatFails(t *testing.T) {
	a := test.NewApp()
	t.Cleanup(a.Quit)
	noEndpoint := "[Interface]\nPrivateKey = не-настоящий\nAddress = 10.8.1.5/32\n"
	for _, c := range []struct {
		name, container string
		wantNote        bool
	}{
		{"AmneziaWG, нет Endpoint", "amnezia-awg", true},
		{"XRay", "amnezia-xray", false},
		{"контейнер неизвестен", "", true},
	} {
		t.Run(c.name, func(t *testing.T) {
			o, note := qrObjectNote("x", noEndpoint, c.container)
			if _, ok := o.(*canvas.Image); !ok {
				t.Fatalf("ждали текстовый QR, получили %T", o)
			}
			if got := note != ""; got != c.wantNote {
				t.Fatalf("пометка %q, ждали есть=%v", note, c.wantNote)
			}
			why := "в конфиге нет"
			if c.container == "" {
				why = "Протокол сервера не выбран"
			}
			if c.wantNote && (!strings.Contains(note, "Сервер N") || !strings.Contains(note, why) || strings.Contains(note, "PrivateKey =")) {
				t.Fatalf("пометка без причины или с содержимым: %q", note)
			}
		})
	}
}
