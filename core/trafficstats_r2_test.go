package core

import (
	"strings"
	"testing"
)

// TestStatsReadAsRoot — Н2 ревью 1: данные сборщика 0600 (umask 077),
// поэтому и чтение, и состояние идут от root: напрямую под root, через
// sudo -n под другим пользователем.
func TestStatsReadAsRoot(t *testing.T) {
	if !strings.Contains(StatsCollectorScript(), "\numask 077\n") {
		t.Error("сборщик пишет данные не с umask 077")
	}
	for user, want := range map[string]string{"root": "sh -s", "admin": "sudo -n sh -s"} {
		f := &fakeStatsRunner{files: map[string]string{}}
		s := NewSessionWithRunner(f, &ServerCreds{Host: "h", User: user})
		if _, err := s.ReadTraffic(); err != nil {
			t.Fatal(err)
		}
		s.StatsStatus()
		if len(f.cmds) != 2 || f.cmds[0] != want || f.cmds[1] != want {
			t.Errorf("%s: команды %q, ждали %q", user, f.cmds, want)
		}
	}
}
