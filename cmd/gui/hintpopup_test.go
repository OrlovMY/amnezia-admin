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
	"testing"

	"fyne.io/fyne/v2"
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
func onePopup(t *testing.T, root fyne.CanvasObject) rect {
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
}

func openPinScene(t *testing.T) hintScene {
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
	e := passwordEntry(t, d, 0)
	e.SetText(typedCyrillicPin)
	d.Refresh()
	return hintScene{what: "диалог «Введите пин-код»", root: d, canvas: u.win.Canvas(), field: e, confirm: buttonByText(t, d, "Открыть")}
}

func openSaveScene(t *testing.T) hintScene {
	t.Helper()
	u := focusTestUI(t)
	u.win.Resize(fyne.NewSize(900, 700))
	u.offerSaveKey("vpn://не-настоящий", "Сервер 1", "")
	d := u.win.Canvas().Overlays().List()[0]
	e := passwordEntry(t, d, 0)
	e.SetText(typedCyrillicPin)
	d.Refresh()
	return hintScene{what: "диалог «Сохранить ключ?»", root: d, canvas: u.win.Canvas(), field: e, confirm: buttonByText(t, d, "Сохранить")}
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
	return hintScene{what: "экран подключения", root: c, canvas: u.win.Canvas(), field: e, confirm: buttonByText(t, c, "Подключиться")}
}

var hintScenes = []func(*testing.T) hintScene{openPinScene, openSaveScene, openConnectScene}

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

// ---------- 2. всплывашка никого не накрывает ----------

// TestFloatingHintCoversNeitherFieldNorButton — ВСПЛЫВАШКА НЕ НАКРЫВАЕТ НИ
// ПОЛЕ ВВОДА, НИ КНОПКУ ПОДТВЕРЖДЕНИЯ.
//
// Это и есть цена отказа от резерва: подсказка больше не раздвигает форму, но
// теперь она лежит поверх чужого места, и надо доказать, что место это —
// ничьё. Поле ввода человек в этот момент заполняет, кнопку собирается нажать.
// Сторона выбрана в коде раз и навсегда (над полем); проверка меряет
// НАСТОЯЩУЮ вёрстку всех трёх форм, поэтому переставь кто-нибудь кнопку или
// поле — она покраснеет, а не промолчит.
func TestFloatingHintCoversNeitherFieldNorButton(t *testing.T) {
	for _, open := range hintScenes {
		s := open(t)
		t.Run(s.what, func(t *testing.T) {
			pop := onePopup(t, s.root)
			field, btn := rectOf(s.field), rectOf(s.confirm)
			if field.size.Height <= 0 || btn.size.Height <= 0 {
				t.Fatalf("проверка ПЕРЕСТАЛА ЧТО-ЛИБО ЗНАЧИТЬ: поле %v или кнопка %v "+
					"не размещены на канве", field, btn)
			}
			if pop.overlaps(field) {
				t.Errorf("всплывашка %v накрывает поле ввода %v — человек печатает вслепую "+
					"в поле, которого не видит", pop, field)
			}
			if pop.overlaps(btn) {
				t.Errorf("всплывашка %v накрывает кнопку «%s» %v — человек не видит того, "+
					"что собирается нажать", pop, s.confirm.Text, btn)
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

// Пределы компактности. Числа сняты с настоящей вёрстки ЭТОЙ ревизии и стоят
// чуть выше неё: они стерегут не точное значение, а возврат резерва — любая
// подсказка, снова вставшая в поток, добавит диалогу от 35 точек высоты.
// Прежние (с резервом) высоты записаны рядом, чтобы было видно, что предел не
// подогнан под них.
const (
	pinDialogMaxHeight  = 330 // с резервом было 443.7
	saveDialogMaxHeight = 430 // с резервом было 617.2
)

// TestDialogsStayCompact — ДИАЛОГИ ОСТАЛИСЬ КОМПАКТНЫМИ (претензия владельца
// «Слишко»).
func TestDialogsStayCompact(t *testing.T) {
	t.Run("диалог пин-кода", func(t *testing.T) {
		s := openPinScene(t)
		if h := s.root.MinSize().Height; h > pinDialogMaxHeight {
			t.Errorf("наименьшая высота диалога пин-кода %.1f при пределе %d — "+
				"диалог снова раздут местом под подсказку", h, pinDialogMaxHeight)
		}
	})
	t.Run("диалог сохранения ключа", func(t *testing.T) {
		s := openSaveScene(t)
		if h := s.root.MinSize().Height; h > saveDialogMaxHeight {
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
// спрашивается сам диалог.
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
	if len(visibleHintPopups(d)) == 0 {
		t.Fatal("проверка ПЕРЕСТАЛА ЧТО-ЛИБО ЗНАЧИТЬ: подсказка не всплыла, мерить нечего")
	}
	if with := d.MinSize(); with != before {
		t.Errorf("с всплывшей подсказкой диалог стал %v вместо %v — подсказка занимает место "+
			"в потоке, содержимое едет", with, before)
	}
	e.SetText(typedLatinPin)
	d.Refresh()
	if after := d.MinSize(); after != before {
		t.Errorf("после исчезновения подсказки диалог стал %v вместо %v", after, before)
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
