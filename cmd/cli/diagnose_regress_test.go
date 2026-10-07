package main

// Регресс diagnose (05.10, Ubuntu 26.04): файл намеренно не использует
// нового API — он компилируется и на 25e2377 и там ПАДАЕТ поведением
// («неизвестная команда», код 1), а не компиляцией.

import (
	"bytes"
	"strings"
	"testing"
)

// TestRunDiagnoseRegress — исправный сервер: код 0, по контейнеру оба
// исхода «нет», «Проблем не найдено», без предложения исправлять.
func TestRunDiagnoseRegress(t *testing.T) {
	key, kh, _ := setupFakeSSHForRunWithExec(t)
	var o, e bytes.Buffer
	code := run([]string{"diagnose", "-key", key}, strings.NewReader(""), &o, &e, kh)
	out := stripANSI(o.String())
	if code != 0 {
		t.Fatalf("code=%d stderr=%s", code, e.String())
	}
	for _, want := range []string{"amnezia-awg — AppArmor: нет", "amnezia-awg — iptables: нет", "Проблем не найдено"} {
		if !strings.Contains(out, want) {
			t.Errorf("нет %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "Чтобы исправить") {
		t.Errorf("исправный сервер, а предложено исправление:\n%s", out)
	}
}
