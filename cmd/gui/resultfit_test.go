package main

import (
	"errors"
	"fmt"
	"image/color"
	"testing"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"amnezia-admin/core"
)

// bigFontTheme — тема по умолчанию с текстом крупнее в scale раз: модель
// метрик шрифта macOS (CI PR #72 упал только там — у кнопки итога копии
// низ 519 при окне 517).
type bigFontTheme struct{ scale float32 }

func (b bigFontTheme) Color(n fyne.ThemeColorName, v fyne.ThemeVariant) color.Color {
	return theme.DefaultTheme().Color(n, v)
}
func (b bigFontTheme) Font(s fyne.TextStyle) fyne.Resource     { return theme.DefaultTheme().Font(s) }
func (b bigFontTheme) Icon(n fyne.ThemeIconName) fyne.Resource { return theme.DefaultTheme().Icon(n) }
func (b bigFontTheme) Size(n fyne.ThemeSizeName) float32 {
	s := theme.DefaultTheme().Size(n)
	if n == theme.SizeNameText || n == theme.SizeNameSubHeadingText || n == theme.SizeNameHeadingText || n == theme.SizeNameCaptionText {
		return s * b.scale
	}
	return s
}

// resultFitMargin — запас от края окна программы до любой кнопки окна.
const resultFitMargin = 8

// TestResultWindowsFitBigFont — окна этого PR с кнопками «Копировать» и
// действиями итога при 972×517 и шрифте крупнее на 15%: каждая видимая
// кнопка целиком в окне с запасом ≥ 8 т. Запасы — числами в журнал.
func TestResultWindowsFitBigFont(t *testing.T) {
	for _, scale := range []float32{1, 1.15} {
		t.Run(fmt.Sprintf("шрифт×%.2f", scale), func(t *testing.T) {
			u, _, _, _ := guiMigration(t, "198.51.100.9")
			fyne.CurrentApp().Settings().SetTheme(bigFontTheme{scale: scale})
			u.win.Resize(fyne.NewSize(972, 517))
			var outs []core.RestoreOutcome
			for i := 0; i < 25; i++ {
				outs = append(outs, core.RestoreOutcome{Container: fmt.Sprintf("amnezia-awg-%d", i), State: core.RestoreDone, Checked: core.RestoreCheckedWG})
			}
			forms := []struct {
				name string
				open func()
			}{
				{"итог копии", func() {
					dir, _ := core.UserBackupsDir()
					path, b, err := u.runBackupTo(dir, time.Now(), core.PlainLayer{})
					u.backupResult(path, b, err)
				}},
				{"итог восстановления", func() { u.restoreResult("/tmp/a.aabk", outs, nil) }},
				{"итог переноса", func() { u.migrateResult("/tmp/a.aabk", false, outs, nil) }},
				{"итог переноса, ошибка", func() { u.migrateResult("", false, nil, errors.New("обрыв связи")) }},
				{"сообщение", func() {
					u.showInfo("Недоступно", "Создание пользователей для XRay не поддерживается.")
				}},
			}
			for _, f := range forms {
				f.open()
				pop := topPopup(t, u.win.Canvas())
				osmotrFrame(pop, nil)
				win := u.win.Canvas().Size()
				minGap := float32(1e9)
				n := 0
				walkObjects(pop, func(o fyne.CanvasObject) {
					b, ok := o.(*widget.Button)
					if !ok || !o.Visible() {
						return
					}
					n++
					p, s := absPos(o), o.Size()
					for _, g := range []float32{p.X, p.Y, win.Width - (p.X + s.Width), win.Height - (p.Y + s.Height)} {
						if g < minGap {
							minGap = g
						}
					}
					if p.Y+s.Height > win.Height-resultFitMargin || p.X+s.Width > win.Width-resultFitMargin || p.X < resultFitMargin || p.Y < resultFitMargin {
						t.Errorf("%s: кнопка %q %v %v ближе %d т. к краю окна %v", f.name, b.Text, p, s, resultFitMargin, win)
					}
				})
				t.Logf("%s: кнопок %d, наименьший запас до края окна %.1f т.", f.name, n, minGap)
				if n == 0 {
					t.Errorf("%s: кнопок нет — проверка ничего не значит", f.name)
				}
				pop.Hide()
			}
		})
	}
}
