package core

import (
	"strings"
	"testing"

	"amnezia-admin/internal/fakesrv"
)

// TestMigrateSameServerCloneText — тест различения: «один сервер» и «ключ
// хоста равен, адреса разные» — разные исходы и разные тексты; текст про
// клон не утверждает «один и тот же сервер» и даёт совет сменить ключи хоста.
func TestMigrateSameServerCloneText(t *testing.T) {
	mk := func(host string) *Session {
		s := NewSessionWithRunner(fakesrv.New(), &ServerCreds{Host: host, Port: "22"})
		s.HostKeyFingerprint = "SHA256:x"
		return s
	}
	vSame, tSame := SameServer(mk(migSrcHost), mk(migSrcHost), okResolver)
	vClone, tClone := SameServer(mk(migSrcHost), mk(migDstHost), okResolver)
	if vSame != SameYes || vClone != SameUnknown || tSame == tClone {
		t.Fatalf("исходы/тексты не различаются: %v %q / %v %q", vSame, tSame, vClone, tClone)
	}
	if !strings.Contains(tClone, "клон") || !strings.Contains(tClone, "dpkg-reconfigure openssh-server") || strings.Contains(tClone, "один и тот же сервер") {
		t.Errorf("текст про клон: %s", tClone)
	}
}
