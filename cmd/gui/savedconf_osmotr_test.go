package main

// Прибор: меню строки (4 пункта) и три состояния окна «Конфигурация клиента»
// (задача владельца 01.10.2026). Конфиг для «найден» — с настоящей парой
// ключей (публичный вычислен из приватного), в каталоге с худшим путём
// (модель macOS), как у «Конфиг готов, сохранён».

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/widget"
	"golang.org/x/crypto/curve25519"

	"amnezia-admin/core"
	"amnezia-admin/internal/fakesrv"
	"amnezia-admin/internal/guiview"
)

// osmotrPriv — постоянный тестовый приватный ключ (32 байта), не настоящий.
var osmotrPriv = base64.StdEncoding.EncodeToString([]byte("osmotr-test-private-key-32-bytes"))

func osmotrPub(t *testing.T) string {
	t.Helper()
	priv, _ := base64.StdEncoding.DecodeString(osmotrPriv)
	pub, err := curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(pub)
}

func openSavedConfig(state string) func(t *testing.T, u *ui, sized func()) osmotrScene {
	return func(t *testing.T, u *ui, sized func()) osmotrScene {
		osmotrMain(u)
		u.canManage = true
		u.cur = &u.containers[0]
		u.clients[1].ClientID = osmotrPub(t)
		sized()
		configDirEnv(t)
		dir, err := core.UserConfigsDir()
		if err != nil {
			t.Fatal(err)
		}
		switch state {
		case "найден, ключ сервера не сверен", "найден, чужой сервер", "найден, ключ сервера сверен":
			srvPub := "SRV="
			if state != "найден, ключ сервера не сверен" {
				// сервер — fakesrv, где этот клиент есть (PSK и адрес как в
				// файле), а [Peer] PublicKey файла — НЕ ключ этого сервера
				srv := fakesrv.New()
				wg, _ := srv.File("/opt/amnezia/awg/wg0.conf")
				srv.SetFile("/opt/amnezia/awg/wg0.conf", append(wg, []byte("\n[Peer]\nPublicKey = "+osmotrPub(t)+"\nPresharedKey = PSK=\nAllowedIPs = 10.8.1.5/32\n")...))
				u.sess = core.NewSessionWithRunner(srv, &core.ServerCreds{Host: "203.0.113.10", User: "root", Password: "x"})
				if state == "найден, ключ сервера сверен" {
					srvPub = pubOfWg(t, string(wg)) // главный путь: ключ сервера совпал — QR сам
				}
			}
			conf := "[Interface]\nPrivateKey = " + osmotrPriv + "\nAddress = 10.8.1.5/32\nDNS = 1.1.1.1\n\n[Peer]\nPublicKey = " + srvPub + "\nPresharedKey = PSK=\nAllowedIPs = 0.0.0.0/0\nEndpoint = 203.0.113.10:51820\n"
			if err := os.MkdirAll(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "Телефон Анны.conf"), []byte(conf), 0o600); err != nil {
				t.Fatal(err)
			}
		case "не прочитано":
			if err := os.MkdirAll(filepath.Dir(dir), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(dir, []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		u.showSavedConfig(1, false)
		waitGUIGoroutines(t)
		// сцена обязана быть той, что названа (иначе прибор мерил бы другое)
		want := map[string]string{
			"найден, чужой сервер":           guiview.SavedServerKeyDiffers,
			"найден, ключ сервера не сверен": guiview.SavedShowQRUnverified,
			"найден, ключ сервера сверен":    "Ключ сервера (PublicKey) совпадает с ключом этого сервера.",
		}[state]
		if txt := popupText(t, u); want != "" && !strings.Contains(txt, want) {
			t.Fatalf("сцена %q ничего не значит: в окне нет %q: %s", state, want, txt)
		}
		return scenePopup(t, u)
	}
}

func openRowMenu(t *testing.T, u *ui, sized func()) osmotrScene {
	osmotrMain(u)
	sized()
	c := u.win.Canvas()
	widget.ShowPopUpMenuAtPosition(u.cellMenu(widget.TableCellID{Row: 1, Col: 1}), c, fyne.NewPos(300, 200))
	top := c.Overlays().Top()
	return osmotrScene{root: top, canvas: c, mins: osmotrFrame(top, nil)}
}

func init() {
	osmotrForms = append(osmotrForms,
		osmotrForm{name: "(м) меню строки", open: openRowMenu,
			// Прибор мерит меню как одну прокрутку и внутрь не идёт; подписи
			// пунктов на отрисованном меню проверяет TestSecondaryTapShowsMenu.
			inventory: []string{"прокрутка:"}},
		osmotrForm{name: "(м) конфигурация: найден, ключ сервера не сверен", open: openSavedConfig("найден, ключ сервера не сверен"), width: 472,
			inventory: []string{"подпись:Конфигурация «Телефон Анны»", "прокрутка:", "кнопка:Сохранить ещё в…", "кнопка:Скопировать путь", "кнопка:Закрыть"}},
		osmotrForm{name: "(м) конфигурация: найден, ключ сервера сверен", open: openSavedConfig("найден, ключ сервера сверен"), width: 472,
			inventory: []string{"подпись:Конфигурация «Телефон Анны»", "изображение:", "прокрутка:", "кнопка:Сохранить ещё в…", "кнопка:Скопировать путь", "кнопка:Закрыть"}},
		osmotrForm{name: "(м) конфигурация: найден, чужой сервер", open: openSavedConfig("найден, чужой сервер"), width: 472,
			inventory: []string{"подпись:Конфигурация «Телефон Анны»", "прокрутка:", "кнопка:Сохранить ещё в…", "кнопка:Скопировать путь", "кнопка:Закрыть"}},
		osmotrForm{name: "(м) конфигурация: не найден", open: openSavedConfig("не найден"), width: 472,
			inventory: []string{"подпись:Конфигурация «Телефон Анны»", "подпись:" + firstLine(wantSavedNotFound), "кнопка:Перевыпустить — старый перестанет работать…", "кнопка:Закрыть"}},
		osmotrForm{name: "(м) конфигурация: не прочитано", open: openSavedConfig("не прочитано"), width: 472,
			inventory: []string{"подпись:Конфигурация «Телефон Анны»", "подпись:" + firstLine(wantUnreadablePrefix), "кнопка:Закрыть"}},
	)
}

// pubOfWg — публичный ключ сервера по PrivateKey [Interface] wg0.conf.
func pubOfWg(t *testing.T, wg string) string {
	t.Helper()
	i := strings.Index(wg, "PrivateKey = ")
	if i < 0 {
		t.Fatal("в wg0.conf нет PrivateKey")
	}
	line := wg[i+len("PrivateKey = "):]
	if j := strings.IndexByte(line, '\n'); j >= 0 {
		line = line[:j]
	}
	priv, err := base64.StdEncoding.DecodeString(strings.TrimSpace(line))
	if err != nil {
		t.Fatal(err)
	}
	pub, err := curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(pub)
}
