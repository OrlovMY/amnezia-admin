package main

import (
	"fmt"
	"testing"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"

	"amnezia-admin/core"
)

// activeScroll — у верхнего окна есть прокрутка, содержимое которой выше
// видимой области (прокрутка нужна).
func activeScroll(t *testing.T, u *ui) (bool, string) {
	t.Helper()
	pop := topPopup(t, u.win.Canvas())
	osmotrFrame(pop, nil)
	active, info := false, ""
	walkObjects(pop, func(o fyne.CanvasObject) {
		if s, ok := o.(*container.Scroll); ok && s.Visible() {
			need, have := s.Content.MinSize().Height, s.Size().Height
			info += " прокрутка: нужно " + ftoa(need) + ", видно " + ftoa(have)
			if need > have+0.5 {
				active = true
			}
		}
	})
	return active, info
}

func ftoa(f float32) string { return fmt.Sprintf("%.0f", f) }

// TestStartWindowsFitWithoutScroll — отзыв владельца на 32d66c4: на окне
// программы 1229×620 стартовые окна копии (выбор, сохранение в обоих
// режимах, восстановление типичного плана) — без активной прокрутки.
// Подмена «жёсткий маленький размер» роняет тест.
func TestStartWindowsFitWithoutScroll(t *testing.T) {
	u, _, _, p := guiMigration(t, "198.51.100.9") // адрес другой — с галкой, самый длинный типичный
	u.win.Resize(fyne.NewSize(1229, 620))
	forms := []struct {
		name string
		open func()
	}{
		{"выбор «Копия…»", func() { u.backupMenu() }},
		{"сохранение без пароля", func() { u.backupDialog().mode.SetSelected(backupNoPassword) }},
		{"сохранение с паролем", func() { u.backupDialog().mode.SetSelected(backupWithPassword) }},
		{"восстановление", func() {
			b, compat, rp, planErr, err := u.restorePrepare(p)
			if err != nil {
				t.Fatal(err)
			}
			u.restoreWindow(b, compat, rp, planErr)
		}},
		{"пароль копии", func() { u.passwordPrompt(func(core.Secret) {}) }},
	}
	for _, f := range forms {
		f.open()
		if active, info := activeScroll(t, u); active {
			t.Errorf("%s: на 1229×620 активна прокрутка (%s)", f.name, info)
		}
		for u.win.Canvas().Overlays().Top() != nil {
			u.win.Canvas().Overlays().Remove(u.win.Canvas().Overlays().Top())
		}
	}
}
