package main

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"
)

// L1 (ревью PR #75): при входе ключами ПК сначала сказано, что пароль
// придётся ввести, и только потом спрошено согласие.
func TestAdminKeyKeysLoginSaysPasswordBeforeConsent(t *testing.T) {
	e := newAKEnv(t)
	e.keyAuth = true
	out := filepath.Join(t.TempDir(), "k.txt")
	var so, se bytes.Buffer
	code := runAdminKey(context.Background(), strings.NewReader("y\n"), &so, &se, true, adminKeyOpts{host: akHost, port: "22", user: "root", out: out})
	s := so.String()
	i, j := strings.Index(s, "его придётся ввести"), strings.Index(s, "Положить пароль в ключ")
	if code != 0 || i < 0 || j < 0 || i > j {
		t.Fatalf("код %d, порядок %d/%d:\n%s", code, i, j, s+se.String())
	}
	akNoLeak(t, s+se.String(), akPw)
}
