package main

import (
	"testing"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/driver/desktop"
)

// TestCopyHintRestoresStatus — AU-UX р3 Р3-1: подсказка значка копирования
// не стирает строку состояния. Наведение → уход возвращает прежний текст;
// если строку во время наведения сменили — новое не затирается старым.
// Подмена «не возвращать» (MouseOut без onHover(false)) роняет первый случай.
func TestCopyHintRestoresStatus(t *testing.T) {
	const reason = "XRay — только просмотр: причина"
	ev := &desktop.MouseEvent{}
	t.Run("возврат", func(t *testing.T) {
		u := serverLabelScreen(t, "203.0.113.10", fyne.NewSize(972, 517))
		u.status.SetText(reason)
		u.serverCopy.MouseIn(ev)
		if u.status.Text != serverCopyHint {
			t.Fatalf("нет подсказки при наведении: %q", u.status.Text)
		}
		u.serverCopy.MouseOut()
		if u.status.Text != reason {
			t.Errorf("после ухода строка состояния %q, ожидалось %q", u.status.Text, reason)
		}
	})
	t.Run("смена во время наведения", func(t *testing.T) {
		u := serverLabelScreen(t, "203.0.113.10", fyne.NewSize(972, 517))
		u.status.SetText(reason)
		u.serverCopy.MouseIn(ev)
		const fresh = "Обновлено: 3 клиента"
		u.status.SetText(fresh)
		u.serverCopy.MouseOut()
		if u.status.Text != fresh {
			t.Errorf("новый текст затёрт: %q, ожидалось %q", u.status.Text, fresh)
		}
	})
}
