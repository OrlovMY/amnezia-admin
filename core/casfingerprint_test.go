package core

import (
	"strings"
	"testing"
)

// TestCASFingerprintTracksTemplate — отпечаток детерминирован и меняется при
// изменении шаблона внешней команды (любой формы) и скрипта.
func TestCASFingerprintTracksTemplate(t *testing.T) {
	s1, c1, u1 := CASFingerprint()
	s2, c2, u2 := CASFingerprint()
	if s1 != s2 || c1 != c2 || u1 != u2 {
		t.Fatal("отпечаток не детерминирован")
	}
	if s1 == c1 || c1 == u1 || s1 == u1 {
		t.Fatalf("суммы совпали — формы не различаются: %s %s %s", s1, c1, u1)
	}
	for _, x := range []string{s1, c1, u1} {
		if len(x) != 64 || strings.Trim(x, "0123456789abcdef") != "" {
			t.Errorf("не sha256 в hex: %q", x)
		}
	}
	// изменение шаблона (любой формы) и скрипта меняет сумму
	changed := func(label, container, dir, file, wantWg, wantTbl string, sudo bool) (string, error) {
		c, err := casWriteCommand(label, container, dir, file, wantWg, wantTbl, sudo)
		return strings.Replace(c, "-w 15", "-w 16", 1), err
	}
	s3, c3, u3 := casFingerprintWith(changed, CASWriteScript)
	if s3 != s1 || c3 == c1 || u3 == u1 {
		t.Errorf("изменение шаблона команды не изменило отпечаток (или изменило скрипт)")
	}
	if s4, _, _ := casFingerprintWith(casWriteCommand, CASWriteScript+" "); s4 == s1 {
		t.Errorf("изменение скрипта не изменило отпечаток")
	}
	// реальный построитель и CASWriteCommand/Sudo дают одно и то же
	cmd, _ := CASWriteCommand(CASLabelApply, casFPContainer, casFPDir, casFPFile, casFPSum, CASAbsent)
	if !strings.Contains(cmd, "-w 15") {
		t.Fatalf("тест ничего не значит: в шаблоне нет «-w 15»: %.80s", cmd)
	}
}
