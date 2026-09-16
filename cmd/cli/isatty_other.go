//go:build !windows

package main

import (
	"os"

	"golang.org/x/term"
)

// stdinIsTTY — см. isatty_windows.go. На Linux/macOS term.IsTerminal делает
// ioctl(TCGETS) на дескрипторе — тоже не путает /dev/null (character
// special, но не терминал) с реальным терминалом, в отличие от проверки
// только os.ModeCharDevice.
func stdinIsTTY() bool {
	return term.IsTerminal(int(os.Stdin.Fd()))
}
