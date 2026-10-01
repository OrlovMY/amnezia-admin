package core

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestSavedConfigTooBig — R2: файл больше 64 КБ не читается целиком: он
// «не прочитан», а не молча пропущен; свой конфиг рядом всё равно найден.
func TestSavedConfigTooBig(t *testing.T) {
	priv, pub, err := genKey()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	big := strings.Repeat("#", maxSavedConf+1)
	os.WriteFile(filepath.Join(dir, "огромный.conf"), []byte(big), 0o600)
	got := FindSavedConfig(dir, nil, pub)
	if got.State != SavedUnreadable || !strings.Contains(got.Why, "больше 64 КБ") {
		t.Errorf("большой файл: %v — %s", got.State, got.Why)
	}
	os.WriteFile(filepath.Join(dir, "свой.conf"), []byte(confWithKey(t, priv, "P", "10.8.1.5/32")), 0o600)
	if got := FindSavedConfig(dir, nil, pub); got.State != SavedFound {
		t.Errorf("свой конфиг рядом с большим не найден: %v", got.State)
	}
}
