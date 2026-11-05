package core

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestBeginOpMarker — нет маркера → пишется; есть → ErrOpMarkerPending,
// прежний не тронут; повреждён → ErrOpMarkerPending; записать нельзя →
// ErrOpMarkerNotWritten. Подмена: писать поверх прежнего — роняет.
func TestBeginOpMarker(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "m.json")
	old := OpMarkerPath
	OpMarkerPath = func() (string, error) { return p, nil }
	t.Cleanup(func() { OpMarkerPath = old })
	first := OpMarker{Target: "198.51.100.9", Started: time.Date(2026, 11, 6, 10, 0, 0, 0, time.Local), Step: "установка"}
	if err := BeginOpMarker(first); err != nil {
		t.Fatalf("нет маркера: %v", err)
	}
	err := BeginOpMarker(OpMarker{Target: "203.0.113.5", Started: time.Now()})
	if !errors.Is(err, ErrOpMarkerPending) || !strings.Contains(err.Error(), "198.51.100.9") || !strings.Contains(err.Error(), "06.11.2026 10:00") || !strings.Contains(err.Error(), p) {
		t.Fatalf("есть маркер: %v", err)
	}
	if m, _ := ReadOpMarker(); m == nil || m.Target != "198.51.100.9" {
		t.Fatalf("прежний маркер перезаписан: %v", m)
	}
	if err := os.WriteFile(p, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := BeginOpMarker(first); !errors.Is(err, ErrOpMarkerPending) {
		t.Errorf("повреждённый маркер: %v", err)
	}
	// временный файл маркера занят каталогом: записать нельзя (на всех ОС)
	p2 := filepath.Join(dir, "m2.json")
	if err := os.Mkdir(p2+".tmp", 0o700); err != nil {
		t.Fatal(err)
	}
	OpMarkerPath = func() (string, error) { return p2, nil }
	if err := BeginOpMarker(first); !errors.Is(err, ErrOpMarkerNotWritten) || errors.Is(err, ErrOpMarkerPending) {
		t.Errorf("не записан: %v", err)
	}
}
