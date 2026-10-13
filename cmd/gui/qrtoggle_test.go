package main

// Конфиг влезает в текстовый QR, контейнер известен: по умолчанию — QR
// формата AmneziaVPN (только в нём приложение получает заголовок сервера —
// адрес выдачи; из текстового .conf оно берёт «Сервер N»,
// importController.cpp:643). «Текстовый QR» — для AmneziaWG/WireGuard.

import (
	"strings"
	"testing"

	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/test"

	"amnezia-admin/core"
)

func TestQRAmneziaDefaultWithTextToggle(t *testing.T) {
	a := test.NewApp()
	t.Cleanup(a.Quit)
	nu := seriesNewUser()
	var lines []string
	for _, l := range strings.Split(nu.Config, "\n") {
		if !strings.HasPrefix(l, "I1") && !strings.HasPrefix(l, "I2") {
			lines = append(lines, l)
		}
	}
	small := strings.Join(lines, "\n")
	if _, err := core.QRPNG(small, 256); err != nil {
		t.Fatalf("проверка ничего не значит: %v", err)
	}
	s, ok := qrObject(nu.Name, small, nu.Container).(*qrSeries)
	if !ok || s.alt == nil || s.altMode || !s.altBtn.Visible() {
		t.Fatal("ждали QR AmneziaVPN по умолчанию с кнопкой «Текстовый QR»")
	}
	series := s.img.Resource.Content()
	test.Tap(s.altBtn)
	if string(s.img.Resource.Content()) != string(s.alt) || s.altBtn.Text != qrSeriesButton || s.prev.Visible() {
		t.Fatal("«Текстовый QR» не показал текстовый QR")
	}
	test.Tap(s.altBtn)
	if string(s.img.Resource.Content()) != string(series) || s.altBtn.Text != qrTextButton {
		t.Fatal("«QR для AmneziaVPN» не вернул серию")
	}
	// Контейнер неизвестен — прежний текстовый QR, без переключателя.
	if _, ok := qrObject(nu.Name, small, "").(*canvas.Image); !ok {
		t.Fatal("без контейнера ждали текстовый QR")
	}
}
