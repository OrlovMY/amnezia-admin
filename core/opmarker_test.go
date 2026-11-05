package core

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestOpMarkerThreeStates — нет маркера (nil, nil) / есть (читается, текст
// про «итог неизвестен» с адресом и шагом) / не прочитан (ошибка, не «нет»).
// Подмена: ошибка разбора → (nil, nil) — роняет.
func TestOpMarkerThreeStates(t *testing.T) {
	p := filepath.Join(t.TempDir(), "m.json")
	old := OpMarkerPath
	OpMarkerPath = func() (string, error) { return p, nil }
	t.Cleanup(func() { OpMarkerPath = old })
	if m, err := ReadOpMarker(); m != nil || err != nil {
		t.Fatalf("нет маркера: %v %v", m, err)
	}
	if err := WriteOpMarker(OpMarker{Target: "198.51.100.9", Started: time.Now(), Step: "установка", Installed: []string{"amnezia-awg"}}); err != nil {
		t.Fatal(err)
	}
	m, err := ReadOpMarker()
	if err != nil || m == nil || m.Target != "198.51.100.9" {
		t.Fatalf("маркер: %v %v", m, err)
	}
	if txt := m.Text(); !strings.Contains(txt, "198.51.100.9") || !strings.Contains(txt, "«установка»") || !strings.Contains(txt, "итог неизвестен") {
		t.Errorf("текст: %s", txt)
	}
	if err := ClearOpMarker(); err != nil {
		t.Fatal(err)
	}
	if m, err := ReadOpMarker(); m != nil || err != nil {
		t.Fatalf("после снятия: %v %v", m, err)
	}
	if err := ClearOpMarker(); err != nil {
		t.Errorf("снятие отсутствующего: %v", err)
	}
	if err := os.WriteFile(p, []byte("{не json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if m, err := ReadOpMarker(); err == nil || m != nil {
		t.Errorf("повреждённый маркер выдан за «нет маркера»: %v %v", m, err)
	}
}

// TestKeepAwakeStops — запрет сна снимается; на ОС без поддержки — ok=false.
func TestKeepAwakeStops(t *testing.T) {
	stop, ok := KeepAwake()
	if ok != KeepAwakeSupported {
		t.Errorf("ok=%v при поддержке %v", ok, KeepAwakeSupported)
	}
	stop()
	stop() // повторный вызов безопасен
}
