package main

import (
	_ "embed"

	"fyne.io/fyne/v2"
)

// icon.png — копия assets/logo-256.png (go:embed не выходит за каталог
// пакета). Совпадение байт стережёт TestAppIconMatchesAsset.
//
//go:embed icon.png
var appIconPNG []byte

// appIcon — значок окна и приложения (панель задач, Alt+Tab). Значок
// самого .exe в проводнике даёт rsrc_windows_amd64.syso.
var appIcon = fyne.NewStaticResource("amnezia-admin.png", appIconPNG)
