package main

// ВСПЛЫВАЮЩАЯ ПОДСКАЗКА ПРО РАСКЛАДКУ.
//
// ЗАЧЕМ ЭТОТ ФАЙЛ. Живая приёмка владельца 23.09.2026, дословно: «3. Слишко.
// Может место под подсказку не надо, пускай она будет всплывающей». Место под
// подсказку было зарезервировано в потоке, и диалог пин-кода вырос с 380x280
// до 420x444 ради текста, которого в норме на экране нет.
//
// Резерв убран, подсказка всплывает над содержимым. У такого решения три
// свои беды, и каждая прибита здесь отдельно:
//
//  1. всплывашка может снова начать занимать место — тогда диалог опять
//     раздуется, а прежняя болезнь («кнопка уезжает из-под пальца») вернётся;
//  2. всплывашка может накрыть то, на что человек в этот момент смотрит или
//     нажимает, — само поле ввода и кнопку подтверждения;
//  3. всплывашка — новый объект ПОВЕРХ содержимого, и он может перехватить
//     мышь. Проверяется это БОЕВЫМ правилом попадания (hittest_test.go), а не
//     test.TapCanvas: именно на этой разнице владелец уже получил регресс с
//     левым кликом. Ради этой проверки от widget.PopUp и пришлось отказаться:
//     он реализует fyne.Tappable и растягивается на всю канву, то есть съел бы
//     первый клик по любой кнопке диалога.

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/widget"

	"amnezia-admin/core"
	"amnezia-admin/internal/kbdlayout"
)

// rect — прямоугольник объекта в абсолютных координатах канвы.
type rect struct {
	pos  fyne.Position
	size fyne.Size
}

func rectOf(o fyne.CanvasObject) rect {
	return rect{pos: fyne.CurrentApp().Driver().AbsolutePositionForObject(o), size: o.Size()}
}

func (r rect) right() float32  { return r.pos.X + r.size.Width }
func (r rect) bottom() float32 { return r.pos.Y + r.size.Height }

func (r rect) String() string {
	return fmt.Sprintf("x[%.1f..%.1f] y[%.1f..%.1f]", r.pos.X, r.right(), r.pos.Y, r.bottom())
}

// overlaps — прямоугольники пересекаются по ПЛОЩАДИ. Соприкосновение краями
// (всплывашка стоит вплотную над полем) пересечением не считается.
func (r rect) overlaps(o rect) bool {
	return r.pos.X < o.right() && o.pos.X < r.right() &&
		r.pos.Y < o.bottom() && o.pos.Y < r.bottom()
}

func (r rect) contains(o rect) bool {
	return o.pos.X >= r.pos.X && o.pos.Y >= r.pos.Y && o.right() <= r.right() && o.bottom() <= r.bottom()
}

func (r rect) center() fyne.Position {
	return fyne.NewPos(r.pos.X+r.size.Width/2, r.pos.Y+r.size.Height/2)
}

// visibleHintPopups — ВИДИМЫЕ всплывашки подсказок на экране, найденные по их
// собственной раскладке. Обход — walkVisible: выключенная подсказка спрятана,
// и боевой драйвер в неё не заходит.
func visibleHintPopups(root fyne.CanvasObject) []fyne.CanvasObject {
	var out []fyne.CanvasObject
	walkVisible(root, func(o fyne.CanvasObject) {
		c, ok := o.(*fyne.Container)
		if !ok {
			return
		}
		if _, ok := c.Layout.(*hintFloatLayout); !ok {
			return
		}
		if pop := c.Objects[1]; pop.Visible() {
			out = append(out, pop)
		}
	})
	return out
}

// onePopup — ровно одна видимая всплывашка. Ни одной — проверять нечего и
// проверка перестала что-либо значить.
func onePopupObj(t *testing.T, root fyne.CanvasObject) (fyne.CanvasObject, rect) {
	t.Helper()
	pops := visibleHintPopups(root)
	if len(pops) != 1 {
		t.Fatalf("проверка ПЕРЕСТАЛА ЧТО-ЛИБО ЗНАЧИТЬ: видимых всплывашек подсказки %d, "+
			"ожидалась ровно одна", len(pops))
	}
	r := rectOf(pops[0])
	if r.size.Width <= 0 || r.size.Height <= 0 {
		t.Fatalf("всплывашка нулевого размера (%v) — её не видно, проверка ничего не значит", r)
	}
	return pops[0], r
}

// onePopup — то же, когда нужен только прямоугольник.
func onePopup(t *testing.T, root fyne.CanvasObject) rect {
	t.Helper()
	_, r := onePopupObj(t, root)
	return r
}

// ---------- три формы под ключ ----------

// hintScene — открытая форма, в которой подсказка уже всплыла: корень для
// обхода, поле ввода, о котором подсказка, и кнопка подтверждения.
type hintScene struct {
	what    string
	root    fyne.CanvasObject
	canvas  fyne.Canvas
	field   *widget.Entry
	confirm *widget.Button
	// mayCover — ПОИМЁННЫЙ список того, что всплывашке разрешено накрыть.
	// Всё остальное видимое накрывать нельзя. Список пишется руками именно
	// затем, чтобы каждое перекрытие было чьим-то решением, а не побочным
	// следствием вёрстки: добавить сюда строку — значит согласиться, что
	// человек её в этот момент не увидит.
	mayCover []string
}

func openConnectScene(t *testing.T) hintScene {
	t.Helper()
	u := focusTestUI(t)
	u.win.Resize(fyne.NewSize(900, 700))
	u.showConnectScreen("")
	c := u.win.Canvas().Content()
	e := firstEntry(c)
	if e == nil {
		t.Fatal("проверка ПЕРЕСТАЛА ЧТО-ЛИБО ЗНАЧИТЬ: на экране подключения нет поля ввода")
	}
	e.SetText("vpn://кириллицаВКлюче")
	c.Refresh()
	return hintScene{
		what: "экран подключения", root: c, canvas: u.win.Canvas(),
		field: e, confirm: buttonByText(t, c, "Подключиться"),
		// Накрыта поясняющая подпись над полем ключа. Это единственное, что
		// там стоит, и к моменту показа подсказки человек уже вставил ключ,
		// то есть подпись прочитана и своё дело сделала.
		mayCover: []string{
			"Нужен админский ключ — внутри него SSH-доступ к серверу." +
				"\nПользовательский (share) ключ не подойдёт.",
		},
	}
}

// hintScenes — формы, где подсказка ВСПЛЫВАЕТ. Их одна: в диалоге пин-кода и
// в диалоге сохранения свободной полосы под всплывашку не нашлось, и там
// подсказка стоит в зарезервированном месте (см. комментарий к layoutHint и
// TestReservedHintFormsHaveNoPopup, который следит, чтобы этот список не
// разошёлся с кодом молча).
var hintScenes = []func(*testing.T) hintScene{openConnectScene}

// bootRoot — дерево, в котором боевой драйвер ИЩЕТ цель мыши, по правилу
// driver.FindObjectAtPositionMatching (window.go:322): если на канве есть
// оверлей, обыскивается ТОЛЬКО ВЕРХНИЙ оверлей, а до содержимого окна дело не
// доходит вовсе. Искать сразу в диалоге было бы правилом теста, а не боя:
// всплывашка, выехавшая в стек оверлеев (ровно то, что делает widget.PopUp),
// в таком поиске не участвовала бы, и перехват мыши остался бы незамеченным.
func bootRoot(c fyne.Canvas) fyne.CanvasObject {
	if top := c.Overlays().Top(); top != nil {
		return top
	}
	return c.Content()
}

// openPinDialog и openSaveDialog — формы с ЗАРЕЗЕРВИРОВАННЫМ местом под
// подсказку. Подсказка в них включена (набрано не в английской раскладке).
func openPinDialog(t *testing.T) (fyne.CanvasObject, fyne.Canvas) {
	t.Helper()
	savedHosts := core.NetworkTimeHosts
	core.NetworkTimeHosts = []string{"https://127.0.0.1:1"}
	t.Cleanup(func() { core.NetworkTimeHosts = savedHosts })

	u := focusTestUI(t)
	t.Cleanup(func() { waitGUIGoroutines(t) })
	u.win.Resize(fyne.NewSize(900, 700))
	u.showVaultPinDialog(t.TempDir()+"/нет.avlt", "Сервер 1", widget.NewButton("", nil), widget.NewLabel(""))
	over := u.win.Canvas().Overlays().List()
	if len(over) == 0 {
		t.Fatal("диалог пин-кода не открылся")
	}
	waitGUIGoroutines(t)
	d := over[len(over)-1]
	passwordEntry(t, d, 0).SetText(typedCyrillicPin)
	d.Refresh()
	return d, u.win.Canvas()
}

func openSaveDialog(t *testing.T) (fyne.CanvasObject, fyne.Canvas) {
	t.Helper()
	u := focusTestUI(t)
	u.win.Resize(fyne.NewSize(900, 700))
	u.offerSaveKey("vpn://не-настоящий", "Сервер 1", "")
	d := u.win.Canvas().Overlays().List()[0]
	passwordEntry(t, d, 0).SetText(typedCyrillicPin)
	d.Refresh()
	return d, u.win.Canvas()
}

// ---------- 2. всплывашка никого не накрывает ----------

// coverable — видимый объект формы, который всплывашка может собой закрыть, и
// имя, которым он назовётся в отчёте об ошибке.
type coverable struct {
	obj  fyne.CanvasObject
	name string
}

// coverableObjects — ВСЁ ВИДИМОЕ, что всплывашка способна закрыть: органы
// управления (по боевому предикату — поля, кнопки, галки) и подписи
// (widget.Label, canvas.Text).
//
// ПОЧЕМУ НЕ ТОЛЬКО ОРГАНЫ УПРАВЛЕНИЯ (ревью UX-01, круг 2). Первая редакция
// спрашивала про два объекта, назначенных «своими», и пропустила две беды.
// Вторая спрашивала про все органы управления — и поймала поле «Метка», но
// пропустила имя хранилища в диалоге пин-кода: это ПОДПИСЬ, а не орган
// управления. Между тем это единственное место, которое говорит, ЧЕЙ пин
// вводится, а ошибка тут стоит попытки из десяти и блокировки на пять минут.
// Поэтому правило теперь самое широкое, какое можно проверить: накрывать
// нельзя НИЧЕГО, кроме поимённо перечисленного в scene.mayCover.
//
// Внутрь подписи не спускаемся: widget.Label рисует себя вложенным RichText, и
// его куски — тот же текст. Внутрь органов управления тоже: они проверены сами.
//
// Отброшены две категории, и обе — не послабление:
//   - вырожденные (нулевой ширины или высоты): скрытая кнопка «Повторить»
//     стоит на канве нулевым прямоугольником, накрыть её нечем;
//
// Сама всплывашка и её содержимое из обхода исключены: иначе она «накрывала
// бы» собственный текст.
//
//   - те, кто накрывает ВСЮ всплывашку целиком: подложка модального диалога
//     (widget.PopUp самого dialog.NewCustom) во весь экран и контейнеры формы.
//     Это фон, а не содержимое.
func coverableObjects(root, popObj fyne.CanvasObject, pop rect) []coverable {
	var out []coverable
	labels := formLabels(root)
	walkVisibleStop(root, func(o fyne.CanvasObject) bool {
		if o == popObj {
			return true // сама всплывашка: она не то, что она накрывает
		}
		name, stop := "", false
		switch x := o.(type) {
		case *widget.Label:
			name, stop = x.Text, true
		case *widget.Button:
			name, stop = "кнопка «"+x.Text+"»", true
		case *widget.Check:
			name, stop = "галка «"+x.Text+"»", true
		case *widget.Entry:
			name, stop = "поле «"+entryName(x, labels)+"»", true
		case *canvas.Text:
			name = x.Text
		default:
			if matchesBootPredicate(o) {
				name, stop = fmt.Sprintf("%T", o), true
			}
		}
		if name == "" {
			return false
		}
		r := rectOf(o)
		if r.contains(pop) {
			// Фон или контейнер во всю форму — не содержимое. ВНУТРЬ ЗАХОДИМ:
			// подложка модального диалога (widget.PopUp самого
			// dialog.NewCustom) сама проходит боевой предикат, и остановка на
			// ней оставила бы проверку без единого объекта.
			return false
		}
		if r.size.Width <= 0 || r.size.Height <= 0 {
			return stop
		}
		out = append(out, coverable{obj: o, name: name})
		return stop
	})
	return out
}

// formLabels — подписи полей из widget.Form («Метка», «Пин-код»…): по ним
// поле называется в отчётах. Прежде имя строилось из флага Password, и два
// непарольных поля были в отчёте неразличимы (ревью QA-01).
func formLabels(root fyne.CanvasObject) map[fyne.CanvasObject]string {
	out := map[fyne.CanvasObject]string{}
	walkObjects(root, func(o fyne.CanvasObject) {
		if f, ok := o.(*widget.Form); ok {
			for _, it := range f.Items {
				out[it.Widget] = it.Text
			}
		}
	})
	return out
}

// entryName — подпись поля в форме, иначе его подсказка-заглушка, иначе
// честное «без подписи».
func entryName(e *widget.Entry, labels map[fyne.CanvasObject]string) string {
	if l := labels[e]; l != "" {
		return l
	}
	if e.PlaceHolder != "" {
		return e.PlaceHolder
	}
	return "без подписи"
}

// TestFloatingHintCoversOnlyWhatTheFormAllows — ВСПЛЫВАШКА НЕ НАКРЫВАЕТ
// НИЧЕГО, КРОМЕ ПОИМЁННО РАЗРЕШЁННОГО.
//
// По умолчанию накрывать нельзя ничего. Разрешение выписывается в форме
// (scene.mayCover) отдельной строкой на каждый объект — так перекрытие
// перестаёт быть побочным следствием вёрстки и становится чьим-то решением.
// Ровно этого не хватило первой редакции: она спрашивала про поле ввода и
// кнопку подтверждения, то есть про тех, кого мы сами назначили важными, и
// потому не заметила ни имени хранилища в диалоге пин-кода, ни поля «Метка» в
// диалоге сохранения.
func TestFloatingHintCoversOnlyWhatTheFormAllows(t *testing.T) {
	for _, open := range hintScenes {
		s := open(t)
		t.Run(s.what, func(t *testing.T) {
			popObj, pop := onePopupObj(t, s.root)
			objs := coverableObjects(s.root, popObj, pop)
			if len(objs) < 3 {
				t.Fatalf("проверка ПЕРЕСТАЛА ЧТО-ЛИБО ЗНАЧИТЬ: видимых объектов формы найдено "+
					"%d — обход не видит ни полей, ни кнопок, ни подписей", len(objs))
			}
			seenField, seenConfirm := false, false
			allowed := map[string]bool{}
			for _, a := range s.mayCover {
				allowed[a] = true
			}
			used := map[string]bool{}
			for _, c := range objs {
				if c.obj == fyne.CanvasObject(s.field) {
					seenField = true
				}
				if c.obj == fyne.CanvasObject(s.confirm) {
					seenConfirm = true
				}
				if !pop.overlaps(rectOf(c.obj)) {
					continue
				}
				if allowed[c.name] {
					used[c.name] = true
					continue
				}
				t.Errorf("всплывашка %v накрывает %q %v, а в списке разрешённого этого нет. "+
					"Либо переставь подсказку, либо впиши строку в mayCover — и тем самым "+
					"скажи вслух, что человек её в этот момент не видит",
					pop, c.name, rectOf(c.obj))
			}
			if !seenField || !seenConfirm {
				t.Errorf("проверка ПЕРЕСТАЛА ЧТО-ЛИБО ЗНАЧИТЬ: среди объектов формы нет самого "+
					"поля ввода (%v) или кнопки подтверждения (%v)", seenField, seenConfirm)
			}
			// Разрешение, которым никто не воспользовался, — это забытая
			// строка: она будет молча оправдывать будущее перекрытие.
			for _, a := range s.mayCover {
				if !used[a] {
					t.Errorf("в mayCover разрешено накрывать %q, но всплывашка этого не "+
						"накрывает — разрешение устарело и оправдает собой что угодно", a)
				}
			}
		})
	}
}

// TestFloatingHintStandsAtTheField — всплывашка стоит ВПЛОТНУЮ НАД СВОИМ
// полем и по его ширине.
//
// Сторож на проверку выше: «не накрывает» выполняется и у подсказки, уехавшей
// в угол канвы или схлопнувшейся в точку, — а такая подсказка бесполезна.
// Здесь требуется, чтобы низ всплывашки совпадал с верхом поля и чтобы по
// горизонтали она поля не покидала.
func TestFloatingHintStandsAtTheField(t *testing.T) {
	for _, open := range hintScenes {
		s := open(t)
		t.Run(s.what, func(t *testing.T) {
			pop := onePopup(t, s.root)
			field := rectOf(s.field)
			if diff := pop.bottom() - field.pos.Y; diff > 0.5 || diff < -0.5 {
				t.Errorf("низ всплывашки на %.1f точек в стороне от верха поля: всплывашка %v, "+
					"поле %v — подсказка оторвалась от того, о чём говорит", diff, pop, field)
			}
			if pop.pos.X != field.pos.X {
				t.Errorf("всплывашка начинается по X на %.1f, а поле — на %.1f",
					pop.pos.X, field.pos.X)
			}
			// Шире поля — значит вылезла за край диалога, и текст обрежет
			// краем окна: ровно та беда, от которой стерёг размер резерва.
			if pop.size.Width > field.size.Width {
				t.Errorf("всплывашка шириной %.1f шире своего поля (%.1f) — она вылезает "+
					"за край диалога, и текст обрежется", pop.size.Width, field.size.Width)
			}
		})
	}
}

// TestFloatingHintStaysOnCanvas — всплывашка целиком ВНУТРИ окна. Уехавшая за
// край была бы обрезана окном, и человек прочёл бы полфразы — ровно та беда,
// от которой стерегла проверка размера резерва.
func TestFloatingHintStaysOnCanvas(t *testing.T) {
	for _, open := range hintScenes {
		s := open(t)
		t.Run(s.what, func(t *testing.T) {
			pop := onePopup(t, s.root)
			canvasRect := rect{pos: fyne.NewPos(0, 0), size: s.canvas.Size()}
			if !canvasRect.contains(pop) {
				t.Errorf("всплывашка %v выходит за пределы окна %v — текст обрежется краем окна",
					pop, canvasRect)
			}
		})
	}
}

// ---------- 3. всплывашка не перехватывает мышь ----------

// TestFloatingHintStealsNoClicks — ни поле ввода, ни кнопка подтверждения не
// теряют мышь, пока подсказка висит.
//
// Цель клика ищется БОЕВЫМ правилом драйвера (пять интерфейсов), а не
// test.TapCanvas: всплывашка — новый объект поверх содержимого, и весь вопрос
// в том, становится ли он целью мыши. Наш слой — canvas.Rectangle и
// widget.Label, ни один из пяти интерфейсов не реализует, поэтому клик
// проходит насквозь. widget.PopUp на этом месте покраснел бы: он Tappable и
// занимает всю канву.
func TestFloatingHintStealsNoClicks(t *testing.T) {
	for _, open := range hintScenes {
		s := open(t)
		t.Run(s.what, func(t *testing.T) {
			pops := visibleHintPopups(s.root)
			if len(pops) == 0 {
				t.Fatal("проверка ПЕРЕСТАЛА ЧТО-ЛИБО ЗНАЧИТЬ: всплывашки на экране нет, " +
					"перехватывать мышь нечему")
			}
			for _, what := range []struct {
				name string
				obj  fyne.CanvasObject
			}{
				{"поле ввода", s.field},
				{"кнопка «" + s.confirm.Text + "»", s.confirm},
			} {
				at := rectOf(what.obj).center()
				target := findByBootPredicate(bootRoot(s.canvas), at)
				if target == nil {
					t.Errorf("под центром %s боевое правило не нашло ни одного объекта мыши", what.name)
					continue
				}
				if target != what.obj {
					t.Errorf("боевая цель клика в центре %s — %T, а должен быть сам объект (%T): "+
						"всплывашка подсказки перехватывает мышь", what.name, target, what.obj)
				}
			}
		})
	}
}

// ---------- 1. всплывашка не занимает места ----------

// Пределы компактности. Сняты с настоящей вёрстки ЭТОЙ ревизии (385.5 и
// 481.8) и стоят выше неё, но ЗАВЕДОМО НИЖЕ прежних (443.7 и 617.2): на базе
// 7d69bf3 оба предела красные. Стерегут они не точное значение, а возврат
// того, что мы убрали, — постоянного резерва под сообщение о неудавшемся
// переключении раскладки и второй подсказки в диалоге сохранения.
//
// Почему пределы не 330 и 430, как в первой редакции: подсказка про раскладку
// в этих двух диалогах вернулась в зарезервированное место — всплывашке там
// негде встать, не накрыв орган управления (замеры см. в комментарии к
// layoutHint в main.go). Это названная вслух цена, а не просадка втихую.
const (
	pinDialogMaxHeight  = 400 // ревизия: 385.5; на базе 7d69bf3 было 443.7
	saveDialogMaxHeight = 500 // ревизия: 481.8; на базе 7d69bf3 было 617.2
)

// TestDialogsStayCompact — ДИАЛОГИ ОСТАЛИСЬ КОМПАКТНЫМИ (претензия владельца
// «Слишко»).
func TestDialogsStayCompact(t *testing.T) {
	t.Run("диалог пин-кода", func(t *testing.T) {
		d, _ := openPinDialog(t)
		if h := d.MinSize().Height; h > pinDialogMaxHeight {
			t.Errorf("наименьшая высота диалога пин-кода %.1f при пределе %d — "+
				"диалог снова раздут местом под подсказку", h, pinDialogMaxHeight)
		}
	})
	t.Run("диалог сохранения ключа", func(t *testing.T) {
		d, _ := openSaveDialog(t)
		if h := d.MinSize().Height; h > saveDialogMaxHeight {
			t.Errorf("наименьшая высота диалога сохранения %.1f при пределе %d — "+
				"диалог снова раздут местом под подсказку", h, saveDialogMaxHeight)
		}
	})
}

// TestHintDoesNotChangeDialogHeight — появление и исчезновение подсказки НЕ
// МЕНЯЕТ высоту диалога вовсе.
//
// Это то же требование, что и у TestLayoutHintDoesNotMoveButtons, но с другой
// стороны: кнопка может не двигаться и в диалоге, который вырос вниз. Здесь
// спрашивается сам диалог. Проверка не зависит от того, всплывашка перед нами
// или резерв, — оба обязаны держать высоту.
func TestHintDoesNotChangeDialogHeight(t *testing.T) {
	savedHosts := core.NetworkTimeHosts
	core.NetworkTimeHosts = []string{"https://127.0.0.1:1"}
	t.Cleanup(func() { core.NetworkTimeHosts = savedHosts })

	u := focusTestUI(t)
	t.Cleanup(func() { waitGUIGoroutines(t) })
	u.win.Resize(fyne.NewSize(900, 700))
	u.showVaultPinDialog(t.TempDir()+"/нет.avlt", "Сервер 1", widget.NewButton("", nil), widget.NewLabel(""))
	waitGUIGoroutines(t)
	d := u.win.Canvas().Overlays().List()[0]

	before := d.MinSize()
	e := passwordEntry(t, d, 0)
	e.SetText(typedCyrillicPin)
	d.Refresh()
	if !hasText(visibleTexts(d), wantPinLayoutHint) {
		t.Fatal("проверка ПЕРЕСТАЛА ЧТО-ЛИБО ЗНАЧИТЬ: подсказка не появилась, мерить нечего")
	}
	if with := d.MinSize(); with != before {
		t.Errorf("с показанной подсказкой диалог стал %v вместо %v — подсказка занимает место "+
			"в потоке по-разному, содержимое едет", with, before)
	}
	e.SetText(typedLatinPin)
	d.Refresh()
	if after := d.MinSize(); after != before {
		t.Errorf("после исчезновения подсказки диалог стал %v вместо %v", after, before)
	}
}

// TestReservedHintFormsHaveNoPopup — СТОРОЖ НА СПИСОК hintScenes.
//
// Всплывашка разрешена только там, где доказано, что она никого не накрывает,
// а доказывает это TestFloatingHintCoversOnlyWhatTheFormAllows по списку
// hintScenes. Переведи кто-нибудь диалог пин-кода или сохранения на
// всплывашку, забыв дописать форму в список, — доказательства не будет, а
// прогон останется зелёным. Поэтому здесь прямо требуется: в этих двух формах
// всплывашек нет.
//
// ГРАНИЦА (ревью QA-01): список hintScenes этот тест НЕ читает. Он краснеет
// на всплывашке в этих двух формах, даже если форму в hintScenes добавили, —
// перевод формы на всплывашку требует правки ОБОИХ мест, и сообщение говорит
// именно это.
func TestReservedHintFormsHaveNoPopup(t *testing.T) {
	for _, c := range []struct {
		what string
		open func(*testing.T) (fyne.CanvasObject, fyne.Canvas)
	}{
		{"диалог «Введите пин-код»", openPinDialog},
		{"диалог «Сохранить ключ?»", openSaveDialog},
	} {
		t.Run(c.what, func(t *testing.T) {
			d, _ := c.open(t)
			if !hasText(visibleTexts(d), wantPinLayoutHint) {
				t.Fatal("проверка ПЕРЕСТАЛА ЧТО-ЛИБО ЗНАЧИТЬ: подсказка не показана")
			}
			if n := len(visibleHintPopups(d)); n != 0 {
				t.Errorf("в этой форме %d всплывающих подсказок, а она обязана держать подсказку "+
					"в зарезервированном месте. Если перевод на всплывашку задуман, добавь форму "+
					"в hintScenes (там проверят, что всплывашка ничего не накрывает) И убери её "+
					"из этого теста: сам он hintScenes не читает", n)
			}
		})
	}
}

// ---------- сообщение о неудавшемся переключении раскладки ----------

// TestLayoutNoticeCostsNothingWhenSilent — сообщение об отказе переключить
// раскладку ОСТАЛОСЬ В ПОТОКЕ, но в норме не стоит ни одной точки высоты.
//
// ПОЧЕМУ ОНО НЕ ВСПЛЫВАШКА. Это не отклик на ввод, а состояние сессии: оно
// верно всё время, пока диалог открыт, и его надо держать перед глазами, а не
// ронять поверх чужого текста. Двигать содержимое ему нечем и некогда: текст
// известен ДО показа диалога, подпись рождается сразу окончательной. Плата за
// это — диалог на случай отказа выше; проверка предъявляет обе половины:
// молчит — высота как без него, говорит — высота больше и текст виден.
func TestLayoutNoticeCostsNothingWhenSilent(t *testing.T) {
	savedHosts := core.NetworkTimeHosts
	core.NetworkTimeHosts = []string{"https://127.0.0.1:1"}
	t.Cleanup(func() { core.NetworkTimeHosts = savedHosts })

	measure := func(t *testing.T, err error) (fyne.Size, []string) {
		t.Helper()
		substituteForceEnglish(t, err)
		u := focusTestUI(t)
		t.Cleanup(func() { waitGUIGoroutines(t) })
		u.win.Resize(fyne.NewSize(900, 700))
		u.showVaultPinDialog(t.TempDir()+"/нет.avlt", "Сервер 1", widget.NewButton("", nil), widget.NewLabel(""))
		waitGUIGoroutines(t)
		d := u.win.Canvas().Overlays().List()[0]
		return d.MinSize(), visibleTexts(d)
	}

	var quiet fyne.Size
	t.Run("переключили", func(t *testing.T) {
		size, texts := measure(t, nil)
		quiet = size
		if hasText(texts, wantLayoutSwitchFailed) {
			t.Fatalf("раскладка переключена, а диалог сообщает об отказе: %q", texts)
		}
	})
	t.Run("отказ — сообщение видно и место под него нашлось", func(t *testing.T) {
		size, texts := measure(t, errWantedLayoutRefusal)
		if !hasText(texts, wantLayoutSwitchFailed) {
			t.Fatalf("переключить раскладку не удалось, а диалог молчит: %q", texts)
		}
		if size.Height <= quiet.Height {
			t.Errorf("диалог с сообщением об отказе высотой %.1f не выше молчащего (%.1f) — "+
				"сообщение стоит в потоке и обязано было раздвинуть диалог; если оно "+
				"умещается без этого, значит место под него всё-таки зарезервировано",
				size.Height, quiet.Height)
		}
	})
	t.Run("ОС так не умеет — высота как у молчащего", func(t *testing.T) {
		size, texts := measure(t, errUnsupportedLayout)
		if hasText(texts, wantLayoutSwitchFailed) {
			t.Fatalf("на ОС без переключения раскладки показано сообщение об отказе: %q", texts)
		}
		if size.Height != quiet.Height {
			t.Errorf("на ОС без переключения раскладки диалог высотой %.1f, а при успешном "+
				"переключении — %.1f: пустая подпись занимает место", size.Height, quiet.Height)
		}
	})
}

// Ошибки для таблицы выше. Заведены здесь, чтобы не тащить в этот файл
// импорты ради двух значений.
var (
	errWantedLayoutRefusal = errors.New("user32: отказ")
	errUnsupportedLayout   = kbdlayout.ErrUnsupported
)

// words — текст со схлопнутыми пробелами: сравнивать нарисованное с исходным
// надо по словам, потому что перенос по словам разрезает фразу на куски и
// меняет пробелы на краях.
func words(s string) string { return strings.Join(strings.Fields(s), " ") }

// TestLayoutNoticeTextFitsItsPlace — СООБЩЕНИЕ ОБ ОТКАЗЕ ВИДНО ЦЕЛИКОМ.
//
// Сторож, потерянный в первой редакции (ревью UX-01, круг 2). Пока сообщение
// стояло в зарезервированном месте, его достаточность проверялась вместе с
// подсказками; резерв убран — и проверять стало нечему, хотя обрезать текст
// по-прежнему есть чем: подпись переносится по словам, а сколько высоты ей
// даст VBox, зависит от расчёта Fyne, а не от нас.
//
// Меряется настоящей вёрсткой открытого диалога: докуда дотянулся
// НАРИСОВАННЫЙ текст подписи и сколько высоты ей отведено.
func TestLayoutNoticeTextFitsItsPlace(t *testing.T) {
	savedHosts := core.NetworkTimeHosts
	core.NetworkTimeHosts = []string{"https://127.0.0.1:1"}
	t.Cleanup(func() { core.NetworkTimeHosts = savedHosts })

	for _, c := range []struct {
		what string
		open func(*testing.T) (fyne.CanvasObject, fyne.Canvas)
	}{
		{"диалог «Введите пин-код»", openPinDialog},
		{"диалог «Сохранить ключ?»", openSaveDialog},
	} {
		t.Run(c.what, func(t *testing.T) {
			substituteForceEnglish(t, errWantedLayoutRefusal)
			d, _ := c.open(t)

			var notice *widget.Label
			walkVisible(d, func(o fyne.CanvasObject) {
				if l, ok := o.(*widget.Label); ok && l.Text == wantLayoutSwitchFailed {
					notice = l
				}
			})
			if notice == nil {
				t.Fatal("проверка ПЕРЕСТАЛА ЧТО-ЛИБО ЗНАЧИТЬ: сообщения об отказе на экране нет")
			}
			box := rectOf(notice)
			if box.size.Height <= 0 {
				t.Fatalf("подпись с сообщением об отказе нулевой высоты (%v)", box)
			}
			var bottom float32
			var drawn []string
			walkVisible(notice, func(o fyne.CanvasObject) {
				txt, ok := o.(*canvas.Text)
				if !ok || txt.Text == "" {
					return
				}
				drawn = append(drawn, txt.Text)
				if b := rectOf(txt).bottom(); b > bottom {
					bottom = b
				}
			})
			if len(drawn) == 0 {
				t.Fatal("проверка ПЕРЕСТАЛА ЧТО-ЛИБО ЗНАЧИТЬ: в подписи не нарисовано ни строки")
			}
			// Первое: нарисованное не вылезает вниз за отведённое подписи.
			if bottom > box.bottom()+0.5 {
				t.Errorf("нарисованный текст сообщения об отказе доходит до %.1f, а подписи "+
					"отведено до %.1f (%v) — сообщение обрежется по высоте", bottom, box.bottom(), box)
			}
			// Второе, и без него первого мало: нарисованы ВСЕ слова. Обрезка
			// внутри строки (Wrapping не по словам) высоту не меняет вовсе —
			// просто хвост фразы не рисуется, и человек читает «Не удалось
			// переключить раскладку на английскую» без того, что делать
			// дальше. Вертикальная проверка такого не видит.
			if got, want := words(strings.Join(drawn, " ")), words(wantLayoutSwitchFailed); got != want {
				t.Errorf("нарисовано %q, а сообщение целиком — %q: человек прочтёт полфразы "+
					"и не узнает, что раскладку надо переключить самому", got, want)
			}
		})
	}
}
