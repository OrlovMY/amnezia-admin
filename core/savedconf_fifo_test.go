//go:build unix

package core

import (
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestSavedConfigFIFO — R2: FIFO с именем *.conf не читается (иначе чтение
// повисло бы) и даёт «не прочитано», а не «не найден».
func TestSavedConfigFIFO(t *testing.T) {
	_, pub, err := genKey()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := syscall.Mkfifo(filepath.Join(dir, "труба.conf"), 0o600); err != nil {
		t.Fatalf("mkfifo: %v", err)
	}
	done := make(chan SavedConfig, 1)
	go func() { done <- FindSavedConfig(dir, nil, pub) }()
	select {
	case got := <-done:
		if got.State != SavedUnreadable || !strings.Contains(got.Why, "не обычный файл") {
			t.Errorf("FIFO: %v — %s", got.State, got.Why)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("поиск повис на FIFO")
	}
}
