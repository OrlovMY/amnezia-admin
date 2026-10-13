package main

// Серия QR формата AmneziaVPN в «Конфиг готов» и «Показать QR»: конфиг
// AmneziaWG 2 не влезает в текстовый QR — показываются коды по одному,
// «QR i из N», «Назад»/«Далее», подпись «Сканируйте в приложении
// AmneziaVPN». Подмена «серии нет» (контейнер не передан) роняет тест:
// на месте QR — надпись «Не удалось построить QR-код».
// Живым сканом приложения НЕ проверено.

import (
	"encoding/base64"
	"encoding/hex"
	"math/rand"
	"strconv"
	"strings"
	"testing"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/test"
	"fyne.io/fyne/v2/widget"

	"amnezia-admin/core"
)

// seriesNewUser — клиент AWG2, чей .conf не влезает в один QR: I1 из
// случайных байтов (zlib их не сожмёт) — три куска серии. Ключи не настоящие.
func seriesNewUser() *core.NewUser {
	r := rand.New(rand.NewSource(1984))
	key := func() string {
		b := make([]byte, 32)
		r.Read(b)
		return base64.StdEncoding.EncodeToString(b)
	}
	i1 := make([]byte, 1000)
	r.Read(i1)
	conf := "[Interface]\nPrivateKey = " + key() + "\nAddress = 10.8.1.5/32\nDNS = 1.1.1.1, 1.0.0.1\n" +
		"Jc = 4\nJmin = 10\nJmax = 50\nS1 = 20\nS2 = 30\nS3 = 15\nS4 = 10\nH1 = 1-100\nH2 = 200-300\nH3 = 400-500\nH4 = 600-700\n" +
		"I1 = <b 0x" + hex.EncodeToString(i1) + ">\nI2 = <b 0x" + hex.EncodeToString(i1[:300]) + ">\n" +
		"\n[Peer]\nPublicKey = " + key() + "\nPresharedKey = " + key() + "\nAllowedIPs = 0.0.0.0/0, ::/0\n" +
		"Endpoint = 203.0.113.10:51820\nPersistentKeepalive = 25\n"
	return &core.NewUser{Name: "Телефон Анны", IP: "10.8.1.5", Config: conf, Container: "amnezia-awg2"}
}

// findSeries — видимая серия QR в дереве окна.
func findSeries(root fyne.CanvasObject) *qrSeries {
	var found *qrSeries
	var walk func(o fyne.CanvasObject)
	walk = func(o fyne.CanvasObject) {
		if found != nil || o == nil || !o.Visible() {
			return
		}
		if s, ok := o.(*qrSeries); ok {
			found = s
			return
		}
		switch x := o.(type) {
		case *fyne.Container:
			for _, k := range x.Objects {
				walk(k)
			}
		case *container.Scroll:
			walk(x.Content)
		case fyne.Widget:
			for _, k := range test.WidgetRenderer(x).Objects() {
				walk(k)
			}
		}
	}
	walk(root)
	return found
}

func TestQRSeriesInConfigDialog(t *testing.T) {
	nu := seriesNewUser()
	if _, err := core.QRPNG(nu.Config, 256); err == nil {
		t.Fatalf("проверка ничего не значит: конфиг %d байт влез в один QR", len(nu.Config))
	}
	u := osmotrUI(t, osmotrThemes[0].v)
	u.win.Resize(fyne.NewSize(1229, 620))
	u.showConfigDialog(nu, "создан")
	pop := topPopup(t, u.win.Canvas())
	osmotrFrame(pop, nil)
	s := findSeries(pop)
	if s == nil {
		t.Fatal("серии QR в окне нет")
	}
	n := len(s.pngs)
	if n < 2 {
		t.Fatalf("проверка ничего не значит: кусков %d", n)
	}
	if qrErrLabel(pop) != nil {
		t.Error("рядом с серией — надпись «не удалось построить»")
	}
	hint := false
	walkLabels(pop, func(l *widget.Label) {
		if strings.Contains(l.Text, "AmneziaVPN") && strings.Contains(l.Text, "порядок любой") {
			hint = true
		}
	})
	if !hint {
		t.Error("нет подсказки, что серию читает только AmneziaVPN")
	}
	seen := map[string]bool{}
	for i := 0; i < n; i++ {
		if want := "QR " + strconv.Itoa(i+1) + " из " + strconv.Itoa(n) + " · " + qrSeriesCaption; s.pos.Text != want {
			t.Fatalf("подпись %q, ждали %q", s.pos.Text, want)
		}
		if s.prev.Disabled() != (i == 0) || s.next.Disabled() != (i == n-1) {
			t.Fatalf("QR %d: Назад выкл=%v, Далее выкл=%v", i+1, s.prev.Disabled(), s.next.Disabled())
		}
		res := s.img.Resource
		if res == nil || !strings.HasSuffix(res.Name(), "-qr.png") || seen[string(res.Content())] {
			t.Fatalf("QR %d: картинка не новая", i+1)
		}
		seen[string(res.Content())] = true
		test.Tap(s.next)
	}
	test.Tap(s.next) // за краем — ничего
	test.Tap(s.prev)
	if s.idx != n-2 {
		t.Fatalf("Назад: idx %d, ждали %d", s.idx, n-2)
	}
}

// «Показать QR» по сохранённому конфигу: контейнер — текущий протокол.
func TestQRSeriesSavedConfig(t *testing.T) {
	nu := seriesNewUser()
	o := qrObject(nu.Name, nu.Config, nu.Container)
	if _, ok := o.(*qrSeries); !ok {
		t.Fatalf("на месте QR %T, ждали серию", o)
	}
	// Третье состояние: контейнер неизвестен — честная надпись, не пустота.
	if l, ok := qrObject(nu.Name, nu.Config, "").(*widget.Label); !ok || !strings.HasPrefix(l.Text, "Не удалось построить QR-код") {
		t.Fatalf("без контейнера ждали надпись, получили %T", l)
	}
	// Серию не построить (XRay) — надпись называет обе причины.
	l, ok := qrObject(nu.Name, nu.Config, "amnezia-xray").(*widget.Label)
	if !ok || !strings.Contains(l.Text, "слишком большой") || !strings.Contains(l.Text, "серия QR AmneziaVPN не построена") ||
		strings.Contains(l.Text, "PrivateKey") {
		t.Fatalf("надпись: %v", l)
	}
}

func walkLabels(root fyne.CanvasObject, f func(*widget.Label)) {
	var walk func(o fyne.CanvasObject)
	walk = func(o fyne.CanvasObject) {
		if o == nil || !o.Visible() {
			return
		}
		if l, ok := o.(*widget.Label); ok {
			f(l)
		}
		switch x := o.(type) {
		case *fyne.Container:
			for _, k := range x.Objects {
				walk(k)
			}
		case *container.Scroll:
			walk(x.Content)
		case fyne.Widget:
			for _, k := range test.WidgetRenderer(x).Objects() {
				walk(k)
			}
		}
	}
	walk(root)
}
