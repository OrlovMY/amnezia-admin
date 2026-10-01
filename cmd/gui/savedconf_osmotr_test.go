package main

// Прибор: меню строки (4 пункта) и три состояния окна «Конфигурация клиента»
// (задача владельца 01.10.2026). Конфиг для «найден» — с настоящей парой
// ключей (публичный вычислен из приватного), в каталоге с худшим путём
// (модель macOS), как у «Конфиг готов, сохранён».

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/widget"
	"golang.org/x/crypto/curve25519"

	"amnezia-admin/core"
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
		case "найден":
			conf := "[Interface]\nPrivateKey = " + osmotrPriv + "\nAddress = 10.8.1.5/32\nDNS = 1.1.1.1\n\n[Peer]\nPublicKey = SRV=\nPresharedKey = PSK=\nAllowedIPs = 0.0.0.0/0\nEndpoint = 203.0.113.10:51820\n"
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
		osmotrForm{name: "(м) конфигурация: найден", open: openSavedConfig("найден"), width: 472,
			inventory: []string{"подпись:Конфигурация «Телефон Анны»", "прокрутка:", "кнопка:Сохранить ещё в…", "кнопка:Скопировать путь", "кнопка:Закрыть"}},
		osmotrForm{name: "(м) конфигурация: не сохранялся", open: openSavedConfig("не сохранялся"), width: 472,
			inventory: []string{"подпись:Конфигурация «Телефон Анны»", "подпись:" + firstLine(wantSavedNotFound), "кнопка:Перевыпустить…", "кнопка:Закрыть"}},
		osmotrForm{name: "(м) конфигурация: не прочитано", open: openSavedConfig("не прочитано"), width: 472,
			inventory: []string{"подпись:Конфигурация «Телефон Анны»", "подпись:" + firstLine(wantUnreadablePrefix), "кнопка:Закрыть"}},
	)
}
