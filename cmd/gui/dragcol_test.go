package main

// ШИРИНА КОЛОНКИ, КОТОРАЯ ТЯНЕТСЯ МЫШЬЮ (живая приёмка владельцем
// 23.09.2026: «ширина колонки не тянется»).
//
// ПОЧЕМУ ПРОВЕРКА ИДЁТ ПО БОЕВОМУ ПРАВИЛУ. Тот же урок, что в
// hittest_test.go: test.TapCanvas ищет цель только среди fyne.Tappable, а
// боевой драйвер — по пяти интерфейсам, и протаскивание границы собрано из
// событий, которые приходят РАЗНЫМ объектам (наведение — таблице как
// desktop.Hoverable, нажатие — ближайшему объекту мыши, само движение —
// ближайшему fyne.Draggable). Проверка, которая била бы по таблице напрямую,
// зеленела бы на сломанной программе: именно так и жила поломка.
//
// ЧЕГО ЭТИ ТЕСТЫ НЕ ДОКАЗЫВАЮТ. Они не воспроизводят порог начала
// протаскивания (dragMoveThreshold) и работу курсора-стрелки: это внутри
// драйвера glfw, окна здесь нет. Проверяется цепочка «наведение → нажатие →
// движение → отпускание» в том порядке и теми объектами, которыми её
// проводит боевой драйвер.

import (
	"testing"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/driver/desktop"

	"amnezia-admin/core"
)

// headerColumnWidth — ширина, которую ПОЛУЧИЛА НА ЭКРАНЕ колонка с этим
// заголовком. Меряется по настоящему объекту подписи, а не по нашему же
// списку ширин: иначе ожидание бралось бы из подменяемого места.
func headerColumnWidth(t *testing.T, u *ui, header string) float32 {
	t.Helper()
	var w float32 = -1
	walkObjects(u.win.Canvas().Content(), func(o fyne.CanvasObject) {
		if l, ok := o.(*tappableLabel); ok && l.Text == header {
			w = l.Size().Width
		}
	})
	if w < 0 {
		t.Fatalf("проверка ПЕРЕСТАЛА ЧТО-ЛИБО ЗНАЧИТЬ: на экране нет заголовка %q", header)
	}
	return w
}

// dragTestUI — таблица на экране достаточного размера, ширины проставлены.
func dragTestUI(t *testing.T) *ui {
	t.Helper()
	u := testUI(t)
	u.win.Resize(fyne.NewSize(1200, 400))
	u.table.Refresh()
	return u
}

// tableOrigin — абсолютная позиция таблицы; от неё считаются все точки ниже.
func tableOrigin(u *ui) fyne.Position {
	return fyne.CurrentApp().Driver().AbsolutePositionForObject(u.table)
}

// hoverAt проводит курсор в точку ТЕМ ЖЕ способом, что боевой драйвер:
// событие движения получает ближайший desktop.Hoverable под точкой
// (glfw/window.go, processMouseMoved), а не тот, кому удобно тесту.
func hoverAt(t *testing.T, u *ui, at fyne.Position) {
	t.Helper()
	var hovered fyne.CanvasObject
	walkObjects(u.win.Canvas().Content(), func(o fyne.CanvasObject) {
		if !o.Visible() {
			return
		}
		if _, ok := o.(desktop.Hoverable); !ok {
			return
		}
		pos := fyne.CurrentApp().Driver().AbsolutePositionForObject(o)
		size := o.Size()
		if at.X < pos.X || at.Y < pos.Y || at.X >= pos.X+size.Width || at.Y >= pos.Y+size.Height {
			return
		}
		hovered = o
	})
	h, ok := hovered.(desktop.Hoverable)
	if !ok {
		t.Fatalf("проверка ПЕРЕСТАЛА ЧТО-ЛИБО ЗНАЧИТЬ: под точкой %v нет ни одного "+
			"объекта, получающего движение мыши", at)
	}
	pos := fyne.CurrentApp().Driver().AbsolutePositionForObject(hovered)
	h.MouseMoved(&desktop.MouseEvent{PointEvent: fyne.PointEvent{
		AbsolutePosition: at,
		Position:         fyne.NewPos(at.X-pos.X, at.Y-pos.Y),
	}})
}

// mouseEventFor — событие кнопки для объекта, с Position относительно него
// самого, как его строит боевой драйвер.
func mouseEventFor(o fyne.CanvasObject, at fyne.Position) *desktop.MouseEvent {
	pos := fyne.CurrentApp().Driver().AbsolutePositionForObject(o)
	return &desktop.MouseEvent{
		Button: desktop.MouseButtonPrimary,
		PointEvent: fyne.PointEvent{
			AbsolutePosition: at,
			Position:         fyne.NewPos(at.X-pos.X, at.Y-pos.Y),
		},
	}
}

// pressAt нажимает кнопку в точке по боевому правилу и возвращает объект,
// которому нажатие досталось. Если этот объект не desktop.Mouseable, нажатие
// в бою ПРОПАДАЕТ — это и есть перехват мыши, и pressAt возвращает его
// вторым значением как «не обработано».
func pressAt(t *testing.T, u *ui, at fyne.Position) (fyne.CanvasObject, bool) {
	t.Helper()
	target := findByBootPredicate(u.win.Canvas().Content(), at)
	if target == nil {
		t.Fatalf("проверка ПЕРЕСТАЛА ЧТО-ЛИБО ЗНАЧИТЬ: под точкой %v боевое правило "+
			"не нашло ни одного объекта мыши", at)
	}
	m, ok := target.(desktop.Mouseable)
	if !ok {
		return target, false
	}
	m.MouseDown(mouseEventFor(target, at))
	return target, true
}

// releaseAt отпускает кнопку там же и тем же способом.
func releaseAt(t *testing.T, u *ui, at fyne.Position) {
	t.Helper()
	target := findByBootPredicate(u.win.Canvas().Content(), at)
	if m, ok := target.(desktop.Mouseable); ok {
		m.MouseUp(mouseEventFor(target, at))
	}
}

// dragTo двигает мышь с нажатой кнопкой: событие движения в бою получает
// ближайший fyne.Draggable, то есть сама таблица.
func dragTo(t *testing.T, u *ui, from, to fyne.Position) {
	t.Helper()
	origin := tableOrigin(u)
	u.table.Dragged(&fyne.DragEvent{
		PointEvent: fyne.PointEvent{
			AbsolutePosition: to,
			Position:         fyne.NewPos(to.X-origin.X, to.Y-origin.Y),
		},
		Dragged: fyne.NewDelta(to.X-from.X, to.Y-from.Y),
	})
	u.table.Refresh()
}

// Границы колонок в системе координат таблицы. Сняты замером раскладки
// заголовка (подпись «#» занимает 16..56 точек, «Имя» начинается с 60):
// тянущаяся полоса — это ЩЕЛЬ между подписями.
const (
	headerY       = 10  // внутри строки заголовка
	boundaryNumX  = 58  // граница между «#» и «Имя»
	boundaryNameX = 342 // граница между «Имя» и «Создан»
	labelNumX     = 36  // середина подписи «#», не граница
)

// TestColumnDragAfterPlainHeaderClickResizesTheGrabbedColumn — СИМПТОМ
// ВЛАДЕЛЬЦА ЦЕЛИКОМ.
//
// Человек щёлкает по строке заголовка (например, попадая в границу и не
// двигая мышью), а потом берётся тянуть ДРУГУЮ границу. До починки
// захваченная первым нажатием граница оставалась защёлкнутой навсегда:
// widget.Table возвращает dragCol в «ничего не захвачено» только в DragEnd,
// а DragEnd боевой драйвер зовёт лишь после НАЧАВШЕГОСЯ протаскивания.
// Итог: тянут границу «Имя», а меняется ширина «#», и меняется скачком —
// с 40 до 354 точек в этом самом замере. Выглядит это ровно как «ширина
// колонки не тянется».
func TestColumnDragAfterPlainHeaderClickResizesTheGrabbedColumn(t *testing.T) {
	u := dragTestUI(t)
	origin := tableOrigin(u)
	beforeNum := headerColumnWidth(t, u, "#")
	beforeName := headerColumnWidth(t, u, "Имя")

	// 1. Нажали и отпустили на границе, не протаскивая.
	first := fyne.NewPos(origin.X+boundaryNumX, origin.Y+headerY)
	hoverAt(t, u, first)
	pressAt(t, u, first)
	releaseAt(t, u, first)

	// 2. Теперь тянем ДРУГУЮ границу — между «Имя» и «Создан».
	second := fyne.NewPos(origin.X+boundaryNameX, origin.Y+headerY)
	to := fyne.NewPos(second.X+60, second.Y)
	hoverAt(t, u, second)
	pressAt(t, u, second)
	dragTo(t, u, second, to)
	releaseAt(t, u, to)

	afterNum := headerColumnWidth(t, u, "#")
	afterName := headerColumnWidth(t, u, "Имя")

	if afterNum != beforeNum {
		t.Errorf("тянули границу колонки «Имя», а изменилась ширина колонки «#»: %v → %v. "+
			"Захваченная предыдущим нажатием граница осталась защёлкнутой (dragCol), "+
			"и мышь тянет не ту колонку", beforeNum, afterNum)
	}
	if afterName <= beforeName {
		t.Errorf("ширина колонки «Имя» после протаскивания вправо на 60 точек: %v → %v — "+
			"колонка не тянется", beforeName, afterName)
	}
}

// TestHeaderLabelClearsStuckDragAfterLostRelease — ЧЕМ ПОЛЕЗЕН ПРОБРОС
// НАЖАТИЯ В ТАБЛИЦУ, и польза эта узкая (ревью QA-01).
//
// ЧЕГО ЗДЕСЬ НЕТ И ПОЧЕМУ. Прежняя редакция этого теста наводила курсор на
// границу, а нажимала по подписи заголовка — последовательность, НЕДОСТИЖИМУЮ
// в бою: переход мыши из щели на подпись обязательно вызовет
// Table.MouseMoved, и запомненная граница обнулится. Правило хит-теста тест
// соблюдал, а порядок событий — нет, и краснел он на состоянии, которого не
// бывает.
//
// ДОСТИЖИМЫЙ СЦЕНАРИЙ такой. Нажатие в щели захватывает границу. Отпускание
// обычно снимает захват (clientTable.MouseUp), но оно может уйти МИМО
// ТАБЛИЦЫ — если курсор к этому времени над кнопкой, над краем окна или вне
// его. Тогда граница остаётся захваченной. Следующий обычный клик по подписи
// заголовка — тот самый, которым сортируют, — снимает её, потому что подпись
// пробрасывает нажатие и отпускание в таблицу. Без проброса клик по подписи
// не доходил до таблицы вовсе, и захват жил дальше.
func TestHeaderLabelClearsStuckDragAfterLostRelease(t *testing.T) {
	u := dragTestUI(t)
	origin := tableOrigin(u)
	beforeNum := headerColumnWidth(t, u, "#")
	beforeName := headerColumnWidth(t, u, "Имя")

	// 1. Нажали в щели у колонки «#». Отпускание ушло мимо таблицы — его
	//    просто нет.
	first := fyne.NewPos(origin.X+boundaryNumX, origin.Y+headerY)
	hoverAt(t, u, first)
	pressAt(t, u, first)

	// 2. Обычный клик по подписи заголовка: навели, нажали, отпустили.
	label := fyne.NewPos(origin.X+labelNumX, origin.Y+headerY)
	hoverAt(t, u, label)
	target, handled := pressAt(t, u, label)
	if _, isLabel := target.(*tappableLabel); !isLabel {
		t.Fatalf("проверка ПЕРЕСТАЛА ЧТО-ЛИБО ЗНАЧИТЬ: нажатие по подписи заголовка "+
			"боевое правило отдало %T, а не подписи", target)
	}
	if !handled {
		t.Fatalf("боевое правило отдаёт нажатие подписи заголовка (%T), а обработать его "+
			"она не умеет: нажатие пропадает, до таблицы не доходит", target)
	}
	releaseAt(t, u, label)

	// 3. Теперь тянем границу колонки «Имя».
	second := fyne.NewPos(origin.X+boundaryNameX, origin.Y+headerY)
	to := fyne.NewPos(second.X+60, second.Y)
	hoverAt(t, u, second)
	pressAt(t, u, second)
	dragTo(t, u, second, to)
	releaseAt(t, u, to)

	if after := headerColumnWidth(t, u, "#"); after != beforeNum {
		t.Errorf("тянули границу колонки «Имя», а изменилась ширина «#»: %v → %v. "+
			"Клик по подписи заголовка не снял захваченную границу — нажатие до таблицы "+
			"не дошло", beforeNum, after)
	}
	if after := headerColumnWidth(t, u, "Имя"); after <= beforeName {
		t.Errorf("ширина колонки «Имя» после протаскивания: %v → %v — тянется не та колонка",
			beforeName, after)
	}
}

// TestHeaderLabelIsMouseable — СТРУКТУРНАЯ проверка, и названа так честно:
// она говорит лишь, что подпись заголовка умеет принять нажатие кнопки, а не
// что от этого что-то меняется на экране. Поведение — в тесте выше.
func TestHeaderLabelIsMouseable(t *testing.T) {
	var o fyne.CanvasObject = newTappableLabel()
	if _, ok := o.(desktop.Mouseable); !ok {
		t.Fatalf("%T не desktop.Mouseable: боевой драйвер отдаёт ей нажатие над заголовком, "+
			"и оно пропадает — до таблицы не доходит ничего", o)
	}
}

// TestHeaderClickStillSorts — СОСЕДНЯЯ ПРИЧИНА: проброс нажатия не должен
// сломать сортировку по клику и не должен сработать дважды. Клик по подписи
// «Имя» — одна смена сортировки, а не две (две вернули бы порядок обратно).
func TestHeaderClickStillSorts(t *testing.T) {
	u := dragTestUI(t)
	u.sortPrimary = core.SortNone

	var target fyne.CanvasObject
	walkObjects(u.win.Canvas().Content(), func(o fyne.CanvasObject) {
		if l, ok := o.(*tappableLabel); ok && l.Text == "Имя" {
			target = l
		}
	})
	if target == nil {
		t.Fatal("проверка ПЕРЕСТАЛА ЧТО-ЛИБО ЗНАЧИТЬ: на экране нет заголовка «Имя»")
	}
	at := fyne.CurrentApp().Driver().AbsolutePositionForObject(target)
	center := fyne.NewPos(at.X+target.Size().Width/2, at.Y+target.Size().Height/2)

	hoverAt(t, u, center)
	pressAt(t, u, center)
	releaseAt(t, u, center)
	// Тап приходит ПОСЛЕ отпускания — именно так делает боевой драйвер.
	target.(fyne.Tappable).Tapped(&fyne.PointEvent{AbsolutePosition: center})

	if u.sortPrimary != core.SortByName {
		t.Errorf("после клика по заголовку «Имя» сортировка = %v, ожидалась сортировка по имени: "+
			"проброс нажатия в таблицу сломал сортировку", u.sortPrimary)
	}
	if u.sortPrimaryDir != core.Asc {
		t.Errorf("после ОДНОГО клика по заголовку «Имя» направление сортировки %v, ожидалось "+
			"по возрастанию: похоже, клик сработал дважды", u.sortPrimaryDir)
	}
}
