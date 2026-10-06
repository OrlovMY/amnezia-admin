package main

import (
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
)

// markSelect — список протоколов, в раскрытом виде которого текущий пункт
// отмечен галочкой (fyne.MenuItem.Checked). Встроенный widget.Select строит
// выпадающее меню из пунктов без Checked, и текущий протокол в нём ничем не
// выделен (отзыв владельца). Закрытый вид, ширина, OnChanged, Enable/Disable —
// от widget.Select без изменений; заменён только показ раскрытого меню.
type markSelect struct {
	widget.Select
	popUp *widget.PopUpMenu
}

func newMarkSelect(options []string, changed func(string)) *markSelect {
	s := &markSelect{}
	s.Options = options
	s.OnChanged = changed
	s.PlaceHolder = "(Select one)" // как у widget.NewSelect
	s.ExtendBaseWidget(s)
	return s
}

// menuItems — пункты раскрытого меню; Checked ровно у выбранного.
func (s *markSelect) menuItems() []*fyne.MenuItem {
	sel := s.SelectedIndex()
	items := make([]*fyne.MenuItem, len(s.Options))
	for i := range s.Options {
		i := i
		items[i] = fyne.NewMenuItem(s.Options[i], func() {
			s.popUp = nil
			s.SetSelectedIndex(i)
		})
		items[i].Checked = i == sel
	}
	return items
}

func (s *markSelect) showPopUp() {
	c := fyne.CurrentApp().Driver().CanvasForObject(s)
	if c == nil {
		return
	}
	menu := fyne.NewMenu("", s.menuItems()...)
	pop := widget.NewPopUpMenu(menu, c)
	pos := fyne.CurrentApp().Driver().AbsolutePositionForObject(s)
	pop.ShowAtPosition(pos.Add(fyne.NewPos(0, s.Size().Height-theme.InputBorderSize())))
	pop.Resize(fyne.NewSize(s.Size().Width, pop.MinSize().Height))
	pop.OnDismiss = func() {
		pop.Hide()
		if s.popUp == pop {
			s.popUp = nil
		}
	}
	s.popUp = pop
}

// Tapped — как у widget.Select (фокус, раскрытие), но со своим меню.
func (s *markSelect) Tapped(*fyne.PointEvent) {
	if s.Disabled() {
		return
	}
	if c := fyne.CurrentApp().Driver().CanvasForObject(s); c != nil && !fyne.CurrentDevice().IsMobile() {
		c.Focus(s)
	}
	s.Refresh()
	s.showPopUp()
}

// TypedKey — пробел и стрелки вверх/вниз раскрывают отмеченное меню;
// остальное (влево/вправо) — как у widget.Select.
func (s *markSelect) TypedKey(e *fyne.KeyEvent) {
	switch e.Name {
	case fyne.KeySpace, fyne.KeyUp, fyne.KeyDown:
		s.showPopUp()
	default:
		s.Select.TypedKey(e)
	}
}

func (s *markSelect) Hide() {
	if s.popUp != nil {
		s.popUp.Hide()
		s.popUp = nil
	}
	s.Select.Hide()
}
