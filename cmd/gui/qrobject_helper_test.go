package main

import "fyne.io/fyne/v2"

// qrObject — объект QR без пометки (для тестов, где пометка не проверяется).
func qrObject(name, config, containerName string) fyne.CanvasObject {
	o, _ := qrObjectNote(name, config, containerName)
	return o
}
