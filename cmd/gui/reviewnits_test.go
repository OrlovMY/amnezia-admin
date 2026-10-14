package main

// Незаблокирующие замечания прошлых ревью (fix/review-nits):
//  1. боковая раскладка серии QR — подпись ровно один раз;
//  2. протокол неизвестен (u.cur == nil) — сказано, что приложение назовёт
//     сервер «Сервер N»;
//  3. режим «Текстовый QR» — под осмотром видимости на четырёх окнах.

import (
	"fmt"
	"strings"
	"testing"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/test"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"amnezia-admin/core"
)

// qrCaptionTexts — подписи «что сканировать»; вместе они видны ровно один
// раз. Подпись входит в строку целиком («QR 1 из 3 · Сканируйте…»); прежняя
// подпись одного кода в боковой раскладке «QR формата AmneziaVPN» — только
// строкой целиком (этими словами начинается и подсказка под кодом).
var qrCaptionTexts = []string{qrSeriesCaption, qrTextCaption}

const qrOldOneCaption = "QR формата AmneziaVPN"

func countCaptions(root fyne.CanvasObject) (n int, seen []string) {
	walkLabels(root, func(l *widget.Label) {
		for _, c := range qrCaptionTexts {
			if strings.Contains(l.Text, c) || l.Text == qrOldOneCaption {
				n++
				seen = append(seen, l.Text)
				break
			}
		}
	})
	return
}

// TestQRSeriesCaptionOnce — ТЕСТ РАЗЛИЧЕНИЯ: в любой раскладке и режиме
// подпись видна ровно один раз. Прежде в боковой раскладке pos и caption
// говорили одно и то же (текстовый QR) или почти одно (один код).
func TestQRSeriesCaptionOnce(t *testing.T) {
	a := test.NewApp()
	t.Cleanup(a.Quit)
	nu := seriesNewUser()
	many, err := core.AmneziaQRSeries(nu.Config, nu.Container)
	if err != nil || len(many) < 2 {
		t.Fatalf("серия: %d кодов, %v", len(many), err)
	}
	alt, err := core.QRPNG("[Interface]\nAddress = 10.8.1.5/32\n", 256)
	if err != nil {
		t.Fatal(err)
	}
	for _, side := range []bool{false, true} {
		for _, c := range []struct {
			name string
			pngs [][]byte
			text bool
		}{
			{"серия", many, false},
			{"один код", many[:1], false},
			{"текстовый QR", many, true},
			{"текстовый QR, один код", many[:1], true},
		} {
			t.Run(fmt.Sprintf("боковая=%v/%s", side, c.name), func(t *testing.T) {
				s := newQRSeries("x", c.pngs)
				s.setAlt(alt)
				if side {
					s.setSide(widget.NewLabel("строка честности"))
				}
				if c.text {
					test.Tap(s.altBtn)
				}
				if n, seen := countCaptions(s); n != 1 {
					t.Fatalf("подпись видна %d раз: %q", n, seen)
				}
			})
		}
	}
}

// TestAWG2TextQRCaptionOnceInDialog — ТЕСТ ДОЕЗДА п.1: боевое окно «Конфиг
// готов» AmneziaWG 2 (setSide из showConfigDialog), до и после «Текстовый QR».
func TestAWG2TextQRCaptionOnceInDialog(t *testing.T) {
	u := osmotrUI(t, theme.VariantLight)
	s := textQRScene(t, u, true, fyne.NewSize(1229, 620))
	if n, seen := countCaptions(s.root); n != 1 {
		t.Fatalf("при открытии подпись видна %d раз: %q", n, seen)
	}
	test.Tap(findButton(t, s.root, qrTextButton))
	if n, seen := countCaptions(s.root); n != 1 {
		t.Fatalf("после «Текстовый QR» подпись видна %d раз: %q", n, seen)
	}
}

// TestSavedQRNoContainerSaysServerN — ТЕСТ ДОЕЗДА п.2: «Показать QR» при
// u.cur == nil (протокол не выбран) → showSavedConfig → showFoundConfig →
// qrObjectNote(…, "") — текстовый QR, и в окне сказано про «Сервер N».
// Прежде пометка была пуста: QR показан молча.
func TestSavedQRNoContainerSaysServerN(t *testing.T) {
	u, _, _ := savedFixture(t)
	row := rowOf(t, u, "Carol")
	u.cur = nil
	u.showSavedConfig(row, false)
	waitGUIGoroutines(t)
	txt := popupText(t, u)
	if !strings.Contains(txt, qrNoContainerNote) {
		t.Fatalf("протокол неизвестен, а про «Сервер N» не сказано:\n%s", txt)
	}
	if strings.Contains(txt, "PrivateKey =") {
		t.Fatal("в окне содержимое конфига")
	}
}

// TestTextQRFullyVisible — осмотр режима «Текстовый QR»: после нажатия
// QR виден целиком (256, не срезан прокруткой или рамкой), кнопка
// переключения и кнопки действия — целиком внутри окна, на четырёх окнах.
func TestTextQRFullyVisible(t *testing.T) {
	forms := []string{"конфиг готов, AmneziaWG 2", "конфиг готов, AmneziaWG", "(м) конфигурация: найден, ключ сервера сверен"}
	sizes := []fyne.Size{{Width: 857, Height: 517}, {Width: 972, Height: 517}, {Width: 1229, Height: 620}, {Width: 1229, Height: 900}}
	for _, form := range forms {
		for _, size := range sizes {
			for _, th := range osmotrThemes {
				t.Run(fmt.Sprintf("%s/%.0fx%.0f/%s", form, size.Width, size.Height, th.name), func(t *testing.T) {
					u := osmotrUI(t, th.v)
					var s osmotrScene
					switch form {
					case "конфиг готов, AmneziaWG 2":
						s = textQRScene(t, u, true, size)
					case "конфиг готов, AmneziaWG":
						s = textQRScene(t, u, false, size)
					default:
						s = formByName(t, form).open(t, u, func() { u.win.Resize(size) })
					}
					pop, ok := s.root.(*widget.PopUp)
					if !ok {
						t.Fatalf("проверка ничего не значит: корень %T", s.root)
					}
					test.Tap(findButton(t, pop, qrTextButton))
					osmotrFrame(pop, nil)
					qs := textQRSeries(pop)
					if qs == nil {
						t.Fatal("проверка ничего не значит: текстовый QR не показан")
					}
					v, full, where, found := qrVisibleHeight(pop)
					if !found {
						t.Fatal("проверка ничего не значит: QR в окне нет")
					}
					t.Logf("текстовый QR: видно %.1f из %.1f (%s)", v, full, where)
					if full < 256 || v < full-0.5 {
						t.Errorf("текстовый QR срезан: видно %.1f из %.1f (%s)", v, full, where)
					}
					dr := fyne.CurrentApp().Driver()
					ip, is := dr.AbsolutePositionForObject(qs.img), qs.img.Size()
					if ip.X < 0 || ip.Y < 0 || ip.X+is.Width > size.Width+0.5 || ip.Y+is.Height > size.Height+0.5 {
						t.Errorf("текстовый QR за краем окна: %v %v в окне %v", ip, is, size)
					}
					for _, text := range []string{qrSeriesButton, "Сохранить ещё в…", "Скопировать путь", "Закрыть"} {
						b := findButton(t, pop, text)
						p, bs := dr.AbsolutePositionForObject(b), b.Size()
						if p.X < 0 || p.Y < 0 || p.X+bs.Width > size.Width+0.5 || p.Y+bs.Height > size.Height+0.5 ||
							bs.Height < b.MinSize().Height-0.5 || bs.Width < b.MinSize().Width-0.5 {
							t.Errorf("кнопка %q не видна целиком: %v %v в окне %v", text, p, bs, size)
						}
						if p.X < ip.X+is.Width && ip.X < p.X+bs.Width && p.Y < ip.Y+is.Height && ip.Y < p.Y+bs.Height {
							t.Errorf("кнопка %q накрывает текстовый QR: кнопка %v %v, QR %v %v", text, p, bs, ip, is)
						}
					}
				})
			}
		}
	}
}

// textQRSeries — серия, показывающая текстовый QR (ресурс *-text-qr.png); nil — нет.
func textQRSeries(root fyne.CanvasObject) *qrSeries {
	var found *qrSeries
	var walk func(o fyne.CanvasObject)
	walk = func(o fyne.CanvasObject) {
		if o == nil || !o.Visible() || found != nil {
			return
		}
		if s, ok := o.(*qrSeries); ok && s.img.Resource != nil && strings.HasSuffix(s.img.Resource.Name(), "-text-qr.png") {
			found = s
			return
		}
		for _, k := range childrenOf(o) {
			walk(k)
		}
	}
	walk(root)
	return found
}

// textQRScene — «Конфиг готов» с конфигом, который влезает в текстовый QR,
// при известном контейнере: серия AmneziaVPN по умолчанию и кнопка
// «Текстовый QR». awg2 — со строкой честности (боковая раскладка setSide).
func textQRScene(t *testing.T, u *ui, awg2 bool, size fyne.Size) osmotrScene {
	t.Helper()
	osmotrMain(u)
	u.win.Resize(size)
	nu := seriesNewUser()
	var lines []string
	for _, l := range strings.Split(nu.Config, "\n") {
		if !strings.HasPrefix(l, "I1") && !strings.HasPrefix(l, "I2") {
			lines = append(lines, l)
		}
	}
	nu.Config = strings.Join(lines, "\n")
	nu.Container = "amnezia-awg"
	if awg2 {
		nu.Container = "amnezia-awg2"
		nu.Note = core.AWG2ConfigNote
	}
	u.showConfigDialog(nu, "создан")
	c := u.win.Canvas()
	pop := topPopup(t, c)
	return osmotrScene{root: pop, canvas: c, mins: osmotrFrame(pop, nil)}
}
