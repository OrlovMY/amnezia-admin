package main

// ПРОВЕРКА ПО БОЕВОМУ ПРАВИЛУ ПОПАДАНИЯ МЫШИ.
//
// ЗАЧЕМ ОТДЕЛЬНЫЙ ФАЙЛ. Регресс «не выделяется строка» (живая приёмка,
// 23.09) прожил слитым в main, потому что наша проверка левого клика жила
// по ТЕСТОВОМУ правилу, а не по боевому. Два драйвера Fyne ищут цель клика
// ПО РАЗНЫМ ПРЕДИКАТАМ:
//
//   - бой (fyne.io/fyne/v2@v2.7.4/internal/driver/glfw/window.go:460-468,
//     функция window.processMouseClicked) ищет самый вложенный объект,
//     реализующий ЛЮБОЙ из пяти интерфейсов: fyne.Tappable,
//     fyne.SecondaryTappable, fyne.DoubleTappable, fyne.Focusable,
//     desktop.Mouseable (плюс fyne.Draggable, но только когда уже начато
//     протаскивание);
//   - тест (fyne.io/fyne/v2@v2.7.4/test/test.go:153-157, TapCanvas →
//     findTappable) ищет объект, реализующий ТОЛЬКО fyne.Tappable.
//
// Ячейка таблицы, реализующая один лишь TappedSecondary, для БОЯ —
// полноценная цель мыши и съедает левый клик, а для test.TapCanvas —
// невидимка: он проходит её насквозь и находит widget.Table. Поэтому
// TestLeftClickReallySelectsRow был зелёным на сломанной программе.
//
// ЧТО ДЕЛАЕТ ЭТОТ ФАЙЛ. Повторяет БОЕВОЙ предикат у себя (импортировать
// fyne.io/fyne/v2/internal/driver нельзя: внутренний пакет чужого модуля) и
// ищет цель левого клика тем же способом, что боевой драйвер. Раз предикат
// СПИСАН, а не импортирован, он обязан устареть молча — от этого
// TestBootPredicateSourceUnchanged и TestFyneVersionPinned ниже.

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/driver/desktop"
)

// pinnedFyneVersion — версия Fyne, с которой СПИСАН боевой предикат.
// Меняется только вместе с перепроверкой window.go.
const pinnedFyneVersion = "v2.7.4"

// bootPredicateSource — дословный текст боевого предиката из
// internal/driver/glfw/window.go. Сторож ищет его в исходнике Fyne: если
// Fyne переписал правило попадания, наша копия больше ничего не доказывает.
const bootPredicateSource = "case fyne.Tappable, fyne.SecondaryTappable, fyne.DoubleTappable, fyne.Focusable, desktop.Mouseable:"

// bootPredicateFile — файл Fyne, откуда списан предикат.
const bootPredicateFile = "internal/driver/glfw/window.go"

// matchesBootPredicate — СПИСАННЫЙ боевой предикат. Draggable сознательно
// не включён: в бою он участвует только при уже начатом протаскивании, а мы
// проверяем одиночный клик.
func matchesBootPredicate(o fyne.CanvasObject) bool {
	switch o.(type) {
	case fyne.Tappable, fyne.SecondaryTappable, fyne.DoubleTappable, fyne.Focusable, desktop.Mouseable:
		return true
	}
	return false
}

// findByBootPredicate повторяет driver.FindObjectAtPositionMatching: обходит
// дерево сверху вниз и оставляет ПОСЛЕДНИЙ (то есть самый вложенный)
// видимый объект, который накрывает точку и проходит предикат.
func findByBootPredicate(root fyne.CanvasObject, at fyne.Position) fyne.CanvasObject {
	var found fyne.CanvasObject
	walkObjects(root, func(o fyne.CanvasObject) {
		if !o.Visible() {
			return
		}
		pos := fyne.CurrentApp().Driver().AbsolutePositionForObject(o)
		size := o.Size()
		if at.X < pos.X || at.Y < pos.Y {
			return
		}
		if at.X >= pos.X+size.Width || at.Y >= pos.Y+size.Height {
			return
		}
		if matchesBootPredicate(o) {
			found = o
		}
	})
	return found
}

// deliverPrimaryClick отдаёт объекту левый клик ровно теми способами,
// которыми это делает боевой драйвер для найденной им цели: сначала
// desktop.Mouseable (MouseDown/MouseUp), затем fyne.Tappable (Tapped).
// Возвращает false, если объект не умеет НИ ОДНОГО из них — это и есть
// перехват мыши: цель найдена, а обработать клик нечем.
func deliverPrimaryClick(o fyne.CanvasObject, ev *fyne.PointEvent) bool {
	handled := false
	if m, ok := o.(desktop.Mouseable); ok {
		me := &desktop.MouseEvent{Button: desktop.MouseButtonPrimary}
		me.Position = ev.Position
		me.AbsolutePosition = ev.AbsolutePosition
		m.MouseDown(me)
		m.MouseUp(me)
		handled = true
	}
	if tp, ok := o.(fyne.Tappable); ok {
		tp.Tapped(ev)
		handled = true
	}
	return handled
}

// cellCenter находит на экране ячейку с именем клиента и возвращает её саму
// и абсолютную координату центра.
func cellCenter(t *testing.T, u *ui, text string) (fyne.CanvasObject, fyne.Position) {
	t.Helper()
	u.win.Resize(fyne.NewSize(1200, 400))
	u.table.Refresh()

	var cell fyne.CanvasObject
	walkObjects(u.win.Canvas().Content(), func(o fyne.CanvasObject) {
		if c, ok := o.(*tableCell); ok && c.Text == text {
			cell = c
		}
	})
	if cell == nil {
		t.Fatalf("проверка ПЕРЕСТАЛА ЧТО-ЛИБО ЗНАЧИТЬ: на экране нет ячейки с текстом %q", text)
	}
	pos := fyne.CurrentApp().Driver().AbsolutePositionForObject(cell)
	if cell.Size().Width <= 0 || cell.Size().Height <= 0 {
		t.Fatalf("проверка ПЕРЕСТАЛА ЧТО-ЛИБО ЗНАЧИТЬ: ячейка %q нулевого размера", text)
	}
	return cell, fyne.NewPos(pos.X+cell.Size().Width/2, pos.Y+cell.Size().Height/2)
}

// TestPrimaryClickSelectsRowByBootRule — ГЛАВНАЯ проверка регресса.
// Цель левого клика ищется БОЕВЫМ правилом (не test.TapCanvas), и от
// найденной цели требуется, чтобы строка выбралась. Ячейка, реализующая
// только TappedSecondary, здесь краснеет: целью она становится, а обработать
// левый клик ей нечем — выбор строки теряется, и вместе с ним удаление,
// переименование и включение.
func TestPrimaryClickSelectsRowByBootRule(t *testing.T) {
	u := testUI(t)
	cell, center := cellCenter(t, u, "Ноутбук")

	target := findByBootPredicate(u.win.Canvas().Content(), center)
	if target == nil {
		t.Fatal("под центром ячейки боевое правило не нашло НИ ОДНОГО объекта мыши — " +
			"проверка перестала что-либо значить")
	}

	u.selectedRow = -1
	ev := &fyne.PointEvent{AbsolutePosition: center}
	pos := fyne.CurrentApp().Driver().AbsolutePositionForObject(target)
	ev.Position = fyne.NewPos(center.X-pos.X, center.Y-pos.Y)

	if !deliverPrimaryClick(target, ev) {
		t.Fatalf("боевое правило отдаёт левый клик объекту %T, а обработать левый клик "+
			"он не умеет: клик пропадает, строка не выделяется. Ячейка таблицы — %T",
			target, cell)
	}
	if u.selectedRow != 0 {
		t.Errorf("боевая цель левого клика — %T; после клика u.selectedRow = %d, ожидалось 0: "+
			"выбор строки до таблицы не доходит, а от него зависят удаление, "+
			"переименование и включение", target, u.selectedRow)
	}
}

// TestBootRuleTargetIsTheCellItself — сторож на саму проверку выше: она
// обязана мерить ЯЧЕЙКУ, а не проходить её насквозь, как test.TapCanvas.
// Если боевое правило вдруг находит под курсором не ячейку, значит либо
// ячейка перестала быть целью мыши (тогда мерить нечего), либо обход
// сломан, — и главный тест зеленеет по ложной причине.
func TestBootRuleTargetIsTheCellItself(t *testing.T) {
	u := testUI(t)
	cell, center := cellCenter(t, u, "Ноутбук")
	target := findByBootPredicate(u.win.Canvas().Content(), center)
	if target != cell {
		t.Fatalf("боевое правило под центром ячейки нашло %T, а не саму ячейку %T — "+
			"TestPrimaryClickSelectsRowByBootRule больше не проверяет перехват мыши", target, cell)
	}
}

// TestTestTapCanvasIsBlindToTheCell — предъявляет РАЗЛИЧИЕ двух правил
// дословно: тестовый искатель (только fyne.Tappable у test.TapCanvas)
// нашёл бы под тем же курсором ДРУГОЙ объект, если бы ячейка не была
// Tappable. Проверка держит причину слепоты прежнего теста явной: пока
// ячейка Tappable, оба правила сходятся; разойдутся — главный тест
// покраснеет, а этот назовёт, почему старый способ этого не заметил бы.
func TestTestTapCanvasIsBlindToTheCell(t *testing.T) {
	u := testUI(t)
	cell, center := cellCenter(t, u, "Ноутбук")

	var tappable fyne.CanvasObject
	walkObjects(u.win.Canvas().Content(), func(o fyne.CanvasObject) {
		if !o.Visible() {
			return
		}
		if _, ok := o.(fyne.Tappable); !ok {
			return
		}
		pos := fyne.CurrentApp().Driver().AbsolutePositionForObject(o)
		size := o.Size()
		if center.X < pos.X || center.Y < pos.Y {
			return
		}
		if center.X >= pos.X+size.Width || center.Y >= pos.Y+size.Height {
			return
		}
		tappable = o
	})
	boot := findByBootPredicate(u.win.Canvas().Content(), center)
	if tappable == boot {
		return // правила сошлись — ячейка умеет левый клик
	}
	t.Errorf("тестовое правило (только fyne.Tappable) нашло %T, боевое — %T: "+
		"test.TapCanvas проходит ячейку %T насквозь и потому НЕ доказывает, "+
		"что левый клик доходит до таблицы", tappable, boot, cell)
}

// fyneModuleDir возвращает каталог модуля Fyne. Не нашли — ПАДЕНИЕ, а не
// пропуск: сторож, который молча не запустился, выглядит как сторож,
// которому нечего сказать (CLAUDE.md).
func fyneModuleDir(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("go", "list", "-m", "-f", "{{.Dir}}", "fyne.io/fyne/v2").Output()
	if err != nil {
		t.Fatalf("не удалось найти каталог модуля fyne.io/fyne/v2 (%v) — "+
			"сторож боевого предиката не выполнялся", err)
	}
	dir := strings.TrimSpace(string(out))
	if dir == "" {
		t.Fatal("каталог модуля fyne.io/fyne/v2 пуст — сторож боевого предиката не выполнялся")
	}
	return dir
}

// TestFyneVersionPinned — версия Fyne в go.mod та же, с которой списан
// предикат. Обновили Fyne — перечитайте window.go и обновите константы.
func TestFyneVersionPinned(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "go.mod"))
	if err != nil {
		t.Fatalf("не прочитан go.mod: %v", err)
	}
	want := "fyne.io/fyne/v2 " + pinnedFyneVersion
	if !strings.Contains(string(data), want) {
		t.Fatalf("в go.mod нет %q: боевой предикат в этом файле списан с Fyne %s, "+
			"после смены версии его надо перечитать в %s",
			want, pinnedFyneVersion, bootPredicateFile)
	}
}

// TestBootPredicateSourceUnchanged — дословный текст боевого предиката всё
// ещё стоит в исходнике Fyne. Это и есть сторож на списанную копию: Fyne
// переписал правило — наша копия врёт, и прогон обязан упасть.
func TestBootPredicateSourceUnchanged(t *testing.T) {
	path := filepath.Join(fyneModuleDir(t), filepath.FromSlash(bootPredicateFile))
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("не прочитан исходник Fyne %s: %v — сторож не выполнялся", path, err)
	}
	src := string(data)
	if !strings.Contains(src, "func (w *window) processMouseClicked(") {
		t.Fatalf("в %s нет processMouseClicked: правило попадания мыши в Fyne переехало, "+
			"проверки этого файла больше ничего не доказывают", bootPredicateFile)
	}
	if !strings.Contains(src, bootPredicateSource) {
		t.Fatalf("в %s нет дословной строки\n\t%s\nБоевое правило попадания мыши изменилось — "+
			"matchesBootPredicate в этом файле больше не повторяет бой",
			bootPredicateFile, bootPredicateSource)
	}
}
