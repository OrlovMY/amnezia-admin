package core

import (
	"strings"
	"testing"
)

// TestMaskTextVpnKey — ключ vpn:// (весь конфиг сервера) скрывается целиком в
// любом месте текста; уже скрытый и пустой «vpn://» не меняются.
// Подмена: убрать reVpnKey из maskFreeText — роняет.
func TestMaskTextVpnKey(t *testing.T) {
	const k1 = "vpn://AAAAeJyrVkrLz1eyUspIzcnJVyrPL8pJUbJSSkvMKU0FAMeODck"
	const k2 = "vpn://eyJob3N0TmFtZSI6IjEuMi4zLjQiLCJwYXNzd29yZCI6InNlY3JldCJ9_-+/="
	h := "vpn://" + hiddenPlaceholder
	cases := []struct{ name, in, want string }{
		{"в начале", k1 + " не принят", h + " не принят"},
		{"в середине фразы", "ошибка разбора " + k1 + ", повторите", "ошибка разбора " + h + ", повторите"},
		{"в конце строки", "dial: " + k1, "dial: " + h},
		{"два ключа", k1 + " и " + k2, h + " и " + h},
		{"в кавычках", `key="` + k1 + `"`, `key="` + h + `"`},
		{"уже скрыт", "ключ " + h, "ключ " + h},
		{"пустой vpn://", "vpn:// пуст", "vpn:// пуст"},
		{"нет ключа", "connection refused", "connection refused"},
	}
	for _, c := range cases {
		got := MaskText(c.in)
		if got != c.want {
			t.Errorf("%s: %q, ждали %q", c.name, got, c.want)
		}
		if strings.Contains(got, "AAAAeJyr") || strings.Contains(got, "eyJob3N0") {
			t.Errorf("%s: кусок ключа остался: %q", c.name, got)
		}
	}
}
