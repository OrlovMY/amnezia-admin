package main

import (
	"errors"
	"testing"

	"amnezia-admin/internal/guiview"
)

// Осмотр формы (verify-in-ui) для видимой добавки A1б: экран подключения,
// когда каталог сохранённых ключей не читается. Отдельным файлом от
// a1b_test.go: тот прогоняется поверх продуктового кода f0febbd (доказательство
// падения), а guiview.VaultListUnreadable там ещё нет.

// invVaultUnreadable — опись добавки к экрану подключения (прибор сверяет
// первые 40 знаков подписи).
var invVaultUnreadable = []string{"подпись:" + firstLine(guiview.VaultListUnreadable(errors.New("x")))}

// openConnectVaultUnreadable — сцена прибора осмотра: экран подключения,
// по пути каталога хранилищ лежит файл.
func openConnectVaultUnreadable(t *testing.T, u *ui, sized func()) osmotrScene {
	vaultPathIsAFile(t)
	u.showConnectScreen("")
	sized()
	c := u.win.Canvas()
	mins := osmotrFrame(c.Content(), nil)
	firstEntry(c.Content()).SetText("vpn://кириллицаВКлюче")
	return osmotrScene{root: c.Content(), canvas: c, mins: mins}
}
