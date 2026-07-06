//go:build !windows

package main

import "os"

// enableVT — на Linux/macOS терминалы поддерживают ANSI нативно, никакой
// Windows-специфичной настройки консоли (кодовая страница, VT-режим) не
// требуется. Уважаем только общепринятую переменную NO_COLOR.
func enableVT() bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	return true
}
