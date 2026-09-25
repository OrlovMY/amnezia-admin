package main

// ОСМОТР ФОРМЫ ЦЕЛИКОМ — прибор HARD-стандарта «Осмотр страницы целиком после
// визуальной правки» (.profi, knowledge/standards/verify-in-ui.md) для GUI на
// Fyne.
//
// ЗАЧЕМ. Прибор стандарта (osmotr-probe.js) — браузерная проба, у Fyne нет ни
// DOM, ни CSS. А болезнь та же: сторожа мерят свойства ЭЛЕМЕНТОВ, а вид ФОРМЫ
// целиком не мерил никто — ревьюер UX-01 вручную нашёл всплывашку поверх имени
// сервера и поля «Метка» при зелёных сторожах. Прибор обходит ВСЁ видимое в
// форме и считает:
//
//	вылезание   — сколько точек объект выходит за окно или за рамку диалога;
//	перекрытие  — пары видимых объектов с общей площадью;
//	сжатие      — объект получил меньше своего минимального размера;
//	состав      — ЗАКРЫТАЯ опись: ровно такие объекты, не больше и не меньше;
//	ширина      — рамка диалога ровно заказанной ширины (не раздулась);
//	шкала       — различные высоты кнопок, полей, списков.
//
// ВОРОТА (ревью QA-01). Первая редакция печатала найденное в t.Log и краснела
// только на недозапуске — то есть молчала при дефектах, и QA-01 вернул
// вчерашний дефект прямо в main.go при зелёном прогоне. Теперь ЛЮБОЕ
// неразрешённое вылезание, перекрытие, сжатие, лишний или недостающий объект,
// изменившаяся ширина — t.Errorf (osmotrGate). Известные дефекты разрешены
// ПОИМЁННО (osmotrKnown, «ИЗВЕСТНЫЙ ДЕФЕКТ …»), и разрешение, которое ничего
// не покрыло, тоже роняет прогон: починили дефект — убери разрешение, иначе
// оно повиснет оправданием следующего.
//
// КАНАРЕЙКИ проверяют ВОРОТА, а не функцию замера: дефект подсаживается в
// разметку формы, собранной боевым кодом main.go, и та же osmotrGate, что у
// TestOsmotrForms, обязана выдать ошибку.
//
// СНИМКИ. При заданной переменной окружения OSMOTR_DIR прибор пишет туда PNG
// каждой формы. В репозиторий снимки не кладутся.

import (
	"errors"
	"fmt"
	"image/color"
	"image/png"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/test"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"amnezia-admin/core"
)

// osmotrWalk — обход прибора. Боевой (в скрытое не заходит, как
// driver.WalkVisibleObjectTree); подменяется только канарейкой.
var osmotrWalk = walkVisibleStop

// variantTheme — встроенная тема Fyne (ТА ЖЕ, что app.New() даёт в бою:
// размеры, шрифты), с принудительным вариантом светлый/тёмный.
//
// ПОЧЕМУ НЕ ТЕМА ТЕСТОВОГО ДРАЙВЕРА. test.NewApp() ставит test.Theme(), у
// которой ДРУГИЕ размеры: полоса прокрутки 16 вместо 12, рамка поля 2 вместо
// 1, скругление 4 вместо 5, заголовок 23.8 вместо 24.
type variantTheme struct {
	fyne.Theme
	v fyne.ThemeVariant
}

func (t variantTheme) Color(n fyne.ThemeColorName, _ fyne.ThemeVariant) color.Color {
	return t.Theme.Color(n, t.v)
}

// osmotrAtom — то, что человек видит как одно целое.
type osmotrAtom struct {
	kind, name string
	obj        fyne.CanvasObject
	r          rect
}

func (a osmotrAtom) key() string { return a.kind + ":" + a.name }

type osmotrReport struct {
	form, size, theme string
	bounds            rect
	boundsWhat        string

	atoms      []osmotrAtom
	backdrops  int // подложки (canvas.Rectangle) — не атомы, названы числом
	degenerate int // нулевого размера и без текста — невидимы
	zeroSized  []string
	accent     int // кнопок акцентной важности (HighImportance)
	settled    int // объектов, сдвинутых кадром (osmotrFrame) после показа

	overflow  []string
	overflowT float32
	overlaps  []string
	allowed   []string // перекрытия, разрешённые формой по замыслу
	overlapA  float32
	squeezed  []string

	counts  map[string]int
	heights map[string][]float32

	missing []string // из описи не найдено
	extra   []string // найдено сверх описи
	shot    string
}

// valid — обход нашёл ровно опись. Иначе выдача НЕДЕЙСТВИТЕЛЬНА целиком:
// недостача — обход не дошёл (или объект пропал), излишек — на форме
// появилось то, чего никто не решал.
func (r *osmotrReport) valid() bool { return len(r.missing) == 0 && len(r.extra) == 0 }

// osmotrClassify — чем объект является для осмотра. stop — внутрь не идём.
func osmotrClassify(o fyne.CanvasObject, labels map[fyne.CanvasObject]string) (kind, name string, stop bool) {
	switch x := o.(type) {
	case *widget.Label:
		return "подпись", firstLine(x.Text), true
	case *widget.Button:
		return "кнопка", x.Text, true
	case *widget.Entry:
		if x.MultiLine {
			return "поле многострочное", entryName(x, labels), true
		}
		return "поле", entryName(x, labels), true
	case *widget.Check:
		return "галка", firstLine(x.Text), true
	case *widget.Select:
		return "список", x.PlaceHolder, true
	case *widget.Table:
		return "таблица", "", true
	case *clientTable:
		// Внутрь таблицы не идём: она прокручивается в обе стороны, и её
		// ячейки законно уходят за край видимой области. Вылезание и
		// перекрытие ВНУТРИ таблицы прибор не мерит — названная граница
		// (пункт 1 стандарта: «внутри прокручиваемого родителя не мерится по
		// построению; смотрит снимок»).
		return "таблица", "", true
	case *widget.TextGrid:
		return "текстовая сетка", "", true
	case *widget.Hyperlink:
		return "ссылка", x.Text, true
	case *widget.Icon:
		return "значок", "", true
	case *canvas.Text:
		return "текст", firstLine(x.Text), true
	case *canvas.Image:
		return "изображение", "", true
	}
	return "", "", false
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i] + "…"
	}
	if r := []rune(s); len(r) > 40 {
		s = string(r[:40]) + "…"
	}
	return s
}

// hintPopups — всплывашки подсказки: осмотр считает каждую одним атомом.
func hintPopups(root fyne.CanvasObject) map[fyne.CanvasObject]bool {
	out := map[fyne.CanvasObject]bool{}
	walkObjects(root, func(o fyne.CanvasObject) {
		if c, ok := o.(*fyne.Container); ok {
			if _, ok := c.Layout.(*hintFloatLayout); ok && len(c.Objects) > 1 {
				out[c.Objects[1]] = true
			}
		}
	})
	return out
}

// ---------- кадр: пересчёт раскладки по правилу боевого драйвера ----------

// osmotrFrame — ОДИН КАДР боевого драйвера: common.Canvas.EnsureMinSize
// (fyne internal/driver/common/canvas.go:84), повторённый по правилу.
//
// Обход снизу вверх; у кого минимальный размер изменился с прошлого кадра, у
// того родитель перекладывается (updateLayout), и изменение идёт выше; у
// корня изменение перекладывает сам корень. Кто минимум НЕ изменил — того
// кадр не трогает, как и в бою: устаревшая при неизменном минимуме вёрстка
// так и остаётся на снимке и в замере.
//
// Первый кадр (mins == nil) видит всех впервые — в бою тоже: у узла кэша
// минимум нулевой, и первый кадр перекладывает всё. Поэтому формы зовут кадр
// в МОМЕНТ ПОКАЗА, до изменений, которые в бою приходят позже (ввод, ответ
// сервера), а замер зовёт второй — только по изменившемуся.
//
// Прежняя редакция (ревью QA-01) перекладывала ВСЁ перед каждым замером и
// тем маскировала бы класс «вёрстка устарела, а минимум не изменился».
func osmotrFrame(root fyne.CanvasObject, mins map[fyne.CanvasObject]fyne.Size) map[fyne.CanvasObject]fyne.Size {
	if mins == nil {
		mins = map[fyne.CanvasObject]fyne.Size{}
	}
	var visit func(o fyne.CanvasObject) bool
	visit = func(o fyne.CanvasObject) bool {
		if o == nil || !o.Visible() {
			return false
		}
		var kids []fyne.CanvasObject
		switch x := o.(type) {
		case *fyne.Container:
			kids = x.Objects
		case fyne.Widget:
			kids = test.WidgetRenderer(x).Objects()
		}
		childChanged := false
		for _, c := range kids {
			if visit(c) {
				childChanged = true
			}
		}
		if childChanged {
			osmotrRelayout(o)
		}
		m := o.MinSize()
		old, seen := mins[o]
		mins[o] = m
		return !seen || old != m
	}
	if visit(root) {
		osmotrRelayout(root)
	}
	return mins
}

func osmotrRelayout(o fyne.CanvasObject) {
	switch x := o.(type) {
	case *fyne.Container:
		if x.Layout != nil {
			x.Layout.Layout(x.Objects, x.Size())
		}
	case fyne.Widget:
		test.WidgetRenderer(x).Layout(x.Size())
	}
}

func atomRects(root fyne.CanvasObject) map[fyne.CanvasObject]rect {
	out := map[fyne.CanvasObject]rect{}
	walkVisible(root, func(o fyne.CanvasObject) { out[o] = rectOf(o) })
	return out
}

// ---------- сцена и замер ----------

// osmotrScene — открытая форма, готовая к осмотру.
type osmotrScene struct {
	root   fyne.CanvasObject
	canvas fyne.Canvas
	// mins — кэш минимумов после кадра показа (osmotrFrame). nil — кадра
	// показа не было, и первый кадр случится при замере.
	mins map[fyne.CanvasObject]fyne.Size
}

func osmotrProbe(form, size, themeName string, s osmotrScene, mayOverlap []string) *osmotrReport {
	before := atomRects(s.root)
	osmotrFrame(s.root, s.mins)
	// Сначала отрисовка, потом замер: мерим нарисованное.
	img := s.canvas.Capture()
	rep := &osmotrReport{form: form, size: size, theme: themeName,
		counts: map[string]int{}, heights: map[string][]float32{}}
	if pop, ok := s.root.(*widget.PopUp); ok {
		// Рамка диалога — прямоугольник содержимого всплывающего окна: его
		// заливает фон диалога, и он виден на снимке. Подложку рендерера
		// PopUp не берём: она отстаёт, когда диалог вырос после показа.
		rep.bounds, rep.boundsWhat = rectOf(pop.Content), "рамка диалога"
	} else {
		rep.bounds, rep.boundsWhat = rect{size: s.canvas.Size()}, "окно"
	}
	for o, r := range atomRects(s.root) {
		if b, ok := before[o]; ok && b != r {
			rep.settled++
		}
	}

	pops := hintPopups(s.root)
	labels := formLabels(s.root)
	osmotrWalk(s.root, func(o fyne.CanvasObject) bool {
		var kind, name string
		stop := false
		if pops[o] {
			kind, name, stop = "всплывашка", "подсказка про раскладку", true
		} else {
			kind, name, stop = osmotrClassify(o, labels)
		}
		if kind == "" {
			if _, ok := o.(*canvas.Rectangle); ok {
				rep.backdrops++
			}
			return false
		}
		r := rectOf(o)
		if r.size.Width <= 0 || r.size.Height <= 0 {
			// НУЛЕВОЙ РАЗМЕР — НЕ ЗНАЧИТ НЕВИДИМ: заголовок диалога Fyne 2.7.4
			// раскладка не размещает (dialog/base.go), а текст рисуется.
			if name != "" && (kind == "подпись" || kind == "текст") {
				r.size = o.MinSize()
				rep.zeroSized = append(rep.zeroSized, kind+" «"+name+"»")
			} else {
				rep.degenerate++
				return stop
			}
		}
		rep.atoms = append(rep.atoms, osmotrAtom{kind: kind, name: name, obj: o, r: r})
		return stop
	})

	allowed := map[string]bool{}
	for _, p := range mayOverlap {
		a, b, _ := strings.Cut(p, "|")
		allowed[a+"|"+b], allowed[b+"|"+a] = true, true
	}

	const eps = 0.5
	for i, a := range rep.atoms {
		rep.counts[a.kind]++
		switch a.kind {
		case "кнопка", "поле", "список":
			rep.heights[a.kind] = append(rep.heights[a.kind], a.r.size.Height)
		}
		if b, ok := a.obj.(*widget.Button); ok && b.Importance == widget.HighImportance {
			rep.accent++
		}
		// вылезание
		b := rep.bounds
		var parts []string
		var worst float32
		for _, d := range []struct {
			side string
			v    float32
		}{
			{"слева", b.pos.X - a.r.pos.X}, {"сверху", b.pos.Y - a.r.pos.Y},
			{"справа", a.r.right() - b.right()}, {"снизу", a.r.bottom() - b.bottom()},
		} {
			if d.v > eps {
				parts = append(parts, fmt.Sprintf("%s %.1f", d.side, d.v))
				if d.v > worst {
					worst = d.v
				}
			}
		}
		if len(parts) > 0 {
			rep.overflow = append(rep.overflow, fmt.Sprintf("%s «%s»: %s", a.kind, a.name, strings.Join(parts, ", ")))
			rep.overflowT += worst
		}
		// сжатие
		if m := a.obj.MinSize(); m.Width > a.r.size.Width+eps || m.Height > a.r.size.Height+eps {
			rep.squeezed = append(rep.squeezed, fmt.Sprintf("%s «%s»: мин %.0fx%.0f, дано %.0fx%.0f",
				a.kind, a.name, m.Width, m.Height, a.r.size.Width, a.r.size.Height))
		}
		// перекрытие
		for _, c := range rep.atoms[i+1:] {
			w := min(a.r.right(), c.r.right()) - max(a.r.pos.X, c.r.pos.X)
			h := min(a.r.bottom(), c.r.bottom()) - max(a.r.pos.Y, c.r.pos.Y)
			if w <= eps || h <= eps {
				continue
			}
			line := fmt.Sprintf("%s «%s» × %s «%s»: %.0fx%.0f = %.0f т²", a.kind, a.name, c.kind, c.name, w, h, w*h)
			if allowed[a.name+"|"+c.name] {
				rep.allowed = append(rep.allowed, line)
				continue
			}
			rep.overlaps = append(rep.overlaps, line)
			rep.overlapA += w * h
		}
	}

	if dir := os.Getenv("OSMOTR_DIR"); dir != "" {
		name := strings.NewReplacer(" ", "_", "«", "", "»", "", "/", "-", ":", "").Replace(form+"_"+size+"_"+themeName) + ".png"
		p := filepath.Join(dir, name)
		if f, err := os.Create(p); err == nil {
			if err := png.Encode(f, img); err == nil {
				rep.shot = p
			}
			f.Close()
		}
		if rep.shot == "" {
			rep.shot = "СНИМОК НЕ ЗАПИСАН"
		}
	}
	return rep
}

// checkInventory — опись ЗАКРЫТА В ОБЕ СТОРОНЫ: мультимножество «вид:имя»
// найденного обязано совпасть с описью ровно.
func (r *osmotrReport) checkInventory(want []string) {
	need := map[string]int{}
	for _, w := range want {
		need[w]++
	}
	got := map[string]int{}
	for _, a := range r.atoms {
		got[a.key()]++
	}
	for k, n := range need {
		for i := got[k]; i < n; i++ {
			r.missing = append(r.missing, k)
		}
	}
	for k, n := range got {
		for i := need[k]; i < n; i++ {
			r.extra = append(r.extra, k)
		}
	}
	sort.Strings(r.missing)
	sort.Strings(r.extra)
}

func (r *osmotrReport) String() string {
	var b strings.Builder
	verdict := "ДЕЙСТВИТЕЛЬНА"
	if !r.valid() {
		verdict = fmt.Sprintf("НЕДЕЙСТВИТЕЛЬНА: из описи не найдено %q, сверх описи %q", r.missing, r.extra)
	}
	fmt.Fprintf(&b, "== %s | %s | %s — выдача %s\n", r.form, r.size, r.theme, verdict)
	fmt.Fprintf(&b, "   граница (%s): %v, ширина %.1f\n", r.boundsWhat, r.bounds, r.bounds.size.Width)
	fmt.Fprintf(&b, "   атомов %d, подложек %d, вырожденных %d\n", len(r.atoms), r.backdrops, r.degenerate)
	if len(r.zeroSized) > 0 {
		fmt.Fprintf(&b, "   нулевого размера, но с текстом (мерены по MinSize): %s\n", strings.Join(r.zeroSized, "; "))
	}
	kinds := make([]string, 0, len(r.counts))
	for k := range r.counts {
		kinds = append(kinds, k)
	}
	sort.Strings(kinds)
	var cs []string
	for _, k := range kinds {
		cs = append(cs, fmt.Sprintf("%s %d", k, r.counts[k]))
	}
	fmt.Fprintf(&b, "   состав: %s\n", strings.Join(cs, ", "))
	for _, k := range []string{"кнопка", "поле", "список"} {
		if hs := r.heights[k]; len(hs) > 0 {
			fmt.Fprintf(&b, "   шкала %s: различных высот %d %v\n", k, len(distinct(hs)), distinct(hs))
		}
	}
	fmt.Fprintf(&b, "   кадр после показа сдвинул объектов: %d\n", r.settled)
	fmt.Fprintf(&b, "   акцентных кнопок %d\n", r.accent)
	fmt.Fprintf(&b, "   вылезаний %d (сумма худших сторон %.1f т.)\n", len(r.overflow), r.overflowT)
	for _, s := range r.overflow {
		fmt.Fprintf(&b, "     ! %s\n", s)
	}
	fmt.Fprintf(&b, "   перекрытий %d (площадь %.0f т²), разрешённых по замыслу %d\n", len(r.overlaps), r.overlapA, len(r.allowed))
	for _, s := range r.overlaps {
		fmt.Fprintf(&b, "     ! %s\n", s)
	}
	for _, s := range r.allowed {
		fmt.Fprintf(&b, "     (по замыслу) %s\n", s)
	}
	fmt.Fprintf(&b, "   сжатых %d\n", len(r.squeezed))
	for _, s := range r.squeezed {
		fmt.Fprintf(&b, "     ! %s\n", s)
	}
	if r.shot != "" {
		fmt.Fprintf(&b, "   снимок: %s\n", r.shot)
	}
	return b.String()
}

func distinct(v []float32) []float32 {
	m := map[float32]bool{}
	var out []float32
	for _, x := range v {
		if !m[x] {
			m[x] = true
			out = append(out, x)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// ---------- ворота ----------

// osmotrKnown — ИЗВЕСТНЫЙ ДЕФЕКТ, разрешённый поимённо. match — кусок строки
// выдачи БЕЗ чисел (вылезание, перекрытие или сжатие), size — размер окна,
// в котором дефект известен. Разрешение, ничего не покрывшее в своём
// размере, роняет прогон.
type osmotrKnown struct {
	id, size, match string
}

// knownD1 — Д1 из осмотра 25.09.2026: при минимальной высоте главного окна
// (161 т.) диалог не помещается, Fyne сжимает его по окну, и «Отмена»
// ложится поверх содержимого. Не чинено: решение ядра и владельца.
func knownD1(match string) osmotrKnown {
	return osmotrKnown{id: "ИЗВЕСТНЫЙ ДЕФЕКТ Д1 (диалог не помещается в окно высотой 161 т.)",
		size: "минимальный", match: match}
}

// osmotrForm — форма: как открыть, что в ней обязано быть и что известно.
type osmotrForm struct {
	name string
	open func(t *testing.T, u *ui, sized func()) osmotrScene
	// inventory — ЗАКРЫТАЯ опись «вид:имя», по одной строке на объект.
	inventory []string
	// width — ширина рамки диалога; 0 — форма не диалог. Раздулся диалог
	// (например, подпись без переноса) — это дефект, а не «поместилось».
	width float32
	// mayOverlap — перекрытия ПО ЗАМЫСЛУ (пара имён), каждое — решение.
	mayOverlap []string
	known      []osmotrKnown
}

// osmotrGate — ВОРОТА: всё, что прибор нашёл, против того, что разрешено.
// Одна и та же функция у TestOsmotrForms и у канареек.
func osmotrGate(f osmotrForm, size string, rep *osmotrReport, errf func(string, ...any)) {
	if !rep.valid() {
		errf("%s | %s | %s: выдача НЕДЕЙСТВИТЕЛЬНА — из описи не найдено %q, сверх описи %q",
			f.name, rep.size, rep.theme, rep.missing, rep.extra)
	}
	if f.width > 0 && (rep.bounds.size.Width < f.width-0.5 || rep.bounds.size.Width > f.width+0.5) {
		errf("%s | %s | %s: ширина рамки диалога %.1f вместо %.1f — диалог раздулся или сжался",
			f.name, rep.size, rep.theme, rep.bounds.size.Width, f.width)
	}
	used := make([]bool, len(f.known))
	check := func(what string, lines []string) {
		for _, l := range lines {
			ok := false
			for i, k := range f.known {
				if strings.HasPrefix(size, k.size) && strings.Contains(l, k.match) {
					used[i], ok = true, true
				}
			}
			if !ok {
				errf("%s | %s | %s: %s: %s", f.name, rep.size, rep.theme, what, l)
			}
		}
	}
	check("вылезание", rep.overflow)
	check("перекрытие", rep.overlaps)
	check("сжатие", rep.squeezed)
	for i, k := range f.known {
		if strings.HasPrefix(size, k.size) && !used[i] {
			errf("%s | %s | %s: НЕИСПОЛЬЗОВАННОЕ РАЗРЕШЕНИЕ «%s: %s» — дефект, похоже, "+
				"починен: убери разрешение, иначе оно прикроет следующий", f.name, rep.size, rep.theme, k.id, k.match)
		}
	}
}

// ---------- формы ----------

// osmotrUI — ui в боевой теме заданного варианта; раскладка «переключилась»,
// в сеть не ходит. Форма «отказ раскладки» переподменяет это сама.
func osmotrUI(t *testing.T, variant fyne.ThemeVariant) *ui {
	t.Helper()
	substituteForceEnglish(t, nil)
	a := test.NewApp()
	t.Cleanup(a.Quit)
	a.Settings().SetTheme(variantTheme{Theme: theme.DefaultTheme(), v: variant})
	w := test.NewWindow(nil)
	t.Cleanup(w.Close)
	return &ui{win: w, selectedRow: -1}
}

// osmotrMain — главное окно с таблицей в боевом виде, без сервера.
func osmotrMain(u *ui) {
	u.sess = core.NewSessionWithRunner(osmotrNoServer{}, &core.ServerCreds{Host: "203.0.113.10", User: "root"})
	u.containers = []core.Container{{Name: "amnezia-awg", Dir: "/opt/amnezia/awg", Proto: "AmneziaWG", Managed: true}}
	u.clients = []core.ClientEntry{
		{ClientID: testKey, UserData: map[string]any{"clientName": "Ноутбук", "creationDate": "2026-09-22T12:34:56.789Z"}},
		{ClientID: repeatKey('Q'), UserData: map[string]any{"clientName": "Телефон Анны", "creationDate": "2026-09-20T08:00:00.000Z"}},
		{ClientID: repeatKey('Z'), UserData: map[string]any{"clientName": "Роутер дача", "creationDate": "2026-09-01T10:00:00.000Z"}},
	}
	u.handshakes = map[string]string{testKey: "2 минуты назад"}
	u.peerStats = map[string]core.PeerStat{testKey: {RxBytes: 1200000, TxBytes: 900000}}
	u.canManage = true
	u.win.SetContent(u.mainScreen())
	// Выбор протокола — БЕЗ обработчика: он пошёл бы на сервер (refresh). В
	// бою выбор делается внутри mainScreen, до показа.
	u.cur = &u.containers[0]
	u.protoSelect.Selected = u.protoSelect.Options[0]
	u.protoSelect.Refresh()
	u.table.Refresh()
}

// osmotrNoServer — «сервера нет». gate, если задан, держит ответ, пока форма
// не собрана: тестовый драйвер исполняет fyne.Do прямо в фоновой горутине
// (go test -race это ловит). В бою fyne.Do идёт в главный поток.
type osmotrNoServer struct{ gate chan struct{} }

func (s osmotrNoServer) Run(string, []byte) (string, error) {
	if s.gate != nil {
		<-s.gate
	}
	return "", fmt.Errorf("осмотр: сервера нет")
}

// withOneVault — в каталоге хранилищ ТЕСТОВОГО бинарника один пустой файл:
// на экране подключения появляется кнопка «Сервер 1». Чужие .avlt не трогаем.
func withOneVault(t *testing.T) {
	t.Helper()
	dir := core.DefaultVaultDir()
	if tmp, err := filepath.Abs(os.TempDir()); err != nil || !strings.HasPrefix(dir, tmp) {
		t.Fatalf("каталог хранилищ %s не во временном каталоге — осмотр его не трогает", dir)
	}
	if n := len(core.ListVaults(dir)); n != 0 {
		t.Fatalf("в %s уже лежит %d хранилищ — осмотр их не трогает", dir, n)
	}
	_, statErr := os.Stat(dir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	f := filepath.Join(dir, "osmotr.avlt")
	if err := os.WriteFile(f, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		os.Remove(f)
		if statErr != nil {
			os.Remove(dir)
		}
	})
}

func topPopup(t *testing.T, c fyne.Canvas) *widget.PopUp {
	t.Helper()
	pop, ok := c.Overlays().Top().(*widget.PopUp)
	if !ok {
		t.Fatalf("верхний оверлей — %T, а не диалог", c.Overlays().Top())
	}
	return pop
}

func sizeWindow(u *ui, which string) func() {
	return func() {
		if which == "минимальный" {
			// Как glfw: минимум окна — MinSize содержимого плюс поля канвы.
			p := 2 * theme.Padding()
			u.win.Resize(u.win.Content().MinSize().AddWidthHeight(p, p))
		} else {
			u.win.Resize(startWindowSize())
		}
	}
}

// connectKeyExplain — подпись над полем ключа, которую всплывашке РАЗРЕШЕНО
// накрыть по замыслу (hintpopup_test.go, openConnectScene.mayCover).
const connectKeyExplain = "Нужен админский ключ — внутри него SSH-доступ к серверу." +
	"\nПользовательский (share) ключ не подойдёт."

// layoutFailText — дословный текст отказа переключения раскладки, как в
// layouthint_test.go (wantLayoutSwitchFailed).
var layoutFailErr = errors.New("осмотр: user32 отказал")

func openConnect(vault, layoutFail bool) func(t *testing.T, u *ui, sized func()) osmotrScene {
	return func(t *testing.T, u *ui, sized func()) osmotrScene {
		if vault {
			withOneVault(t)
		}
		if layoutFail {
			substituteForceEnglish(t, layoutFailErr)
		}
		u.showConnectScreen("")
		sized()
		c := u.win.Canvas()
		mins := osmotrFrame(c.Content(), nil) // кадр показа
		firstEntry(c.Content()).SetText("vpn://кириллицаВКлюче")
		return osmotrScene{root: c.Content(), canvas: c, mins: mins}
	}
}

func openPin(layoutFail bool) func(t *testing.T, u *ui, sized func()) osmotrScene {
	return func(t *testing.T, u *ui, sized func()) osmotrScene {
		if layoutFail {
			substituteForceEnglish(t, layoutFailErr)
		}
		saved := core.NetworkTimeHosts
		core.NetworkTimeHosts = []string{"https://127.0.0.1:1"}
		t.Cleanup(func() { core.NetworkTimeHosts = saved })
		t.Cleanup(func() { waitGUIGoroutines(t) })
		u.showConnectScreen("")
		sized()
		u.showVaultPinDialog(t.TempDir()+"/нет.avlt", "Сервер 1", widget.NewButton("", nil), widget.NewLabel(""))
		// Ответ о сетевом времени (его нет) приходит из горутины; в тестовом
		// драйвере он правил бы диалог одновременно с кадром. Кадр показа —
		// ПОСЛЕ ответа: изменение «Проверка подключения…» → «Подключения к
		// интернету не обнаружено» + кнопка «Повторить» в него уже вошло.
		waitGUIGoroutines(t)
		c := u.win.Canvas()
		pop := topPopup(t, c)
		mins := osmotrFrame(pop, nil)
		passwordEntry(t, pop, 0).SetText(typedCyrillicPin)
		return osmotrScene{root: pop, canvas: c, mins: mins}
	}
}

func openSave(layoutFail bool) func(t *testing.T, u *ui, sized func()) osmotrScene {
	return func(t *testing.T, u *ui, sized func()) osmotrScene {
		if layoutFail {
			substituteForceEnglish(t, layoutFailErr)
		}
		osmotrMain(u)
		sized()
		u.offerSaveKey("vpn://не-настоящий", "203.0.113.10", "")
		c := u.win.Canvas()
		pop := topPopup(t, c)
		mins := osmotrFrame(pop, nil)
		passwordEntry(t, pop, 0).SetText(typedCyrillicPin)
		return osmotrScene{root: pop, canvas: c, mins: mins}
	}
}

func openAction(action func(u *ui)) func(t *testing.T, u *ui, sized func()) osmotrScene {
	return func(t *testing.T, u *ui, sized func()) osmotrScene {
		osmotrMain(u)
		sized()
		u.selectedRow = 0
		action(u)
		c := u.win.Canvas()
		pop := topPopup(t, c)
		return osmotrScene{root: pop, canvas: c, mins: osmotrFrame(pop, nil)}
	}
}

func openDelete(t *testing.T, u *ui, sized func()) osmotrScene {
	osmotrMain(u)
	sized()
	t.Cleanup(func() { waitGUIGoroutines(t) })
	gate := make(chan struct{})
	u.sess = core.NewSessionWithRunner(osmotrNoServer{gate: gate}, u.sess.Creds)
	u.selectedRow = 0
	u.deleteSelected()
	c := u.win.Canvas()
	pop := topPopup(t, c)
	mins := osmotrFrame(pop, nil) // кадр показа: «Узнаю, подключался ли клиент...»
	close(gate)
	waitGUIGoroutines(t) // ответ пришёл после показа: статистики нет
	return osmotrScene{root: pop, canvas: c, mins: mins}
}

func openMain(t *testing.T, u *ui, sized func()) osmotrScene {
	osmotrMain(u)
	sized()
	c := u.win.Canvas()
	return osmotrScene{root: c.Content(), canvas: c, mins: osmotrFrame(c.Content(), nil)}
}

// Описи. Составлены по прогону 25.09.2026 и сверены с кодом форм в main.go
// и со снимками; каждая строка — объект, который человек видит.
var (
	invConnect = []string{
		"подпись:Amnezia Admin", "подпись:dev (unknown)",
		"подпись:" + firstLine(connectKeyExplain),
		"поле многострочное:Вставьте админский ключ vpn://...",
		"всплывашка:подсказка про раскладку",
		"кнопка:Подключиться",
		"подпись:", // строка состояния (пуста)
	}
	invVault   = []string{"подпись:Или загрузить из сохранённых:", "кнопка:Сервер 1"}
	invFail    = []string{"подпись:" + firstLine(wantLayoutSwitchFailed)}
	invPinBase = []string{
		"подпись:Введите пин-код", "подпись:Сервер 1", "поле:Пин-код",
		"подпись:" + firstLine(wantPinLayoutHint), // зарезервированная подсказка
		"подпись:Подключение к интернету не обнаружено.",
		"кнопка:Открыть", "кнопка:Повторить", "кнопка:Отмена",
	}
	invSaveBase = []string{
		"подпись:Сохранить ключ?",
		"подпись:Сохранить этот ключ для быстрого подключ…",
		"текст:Метка", "поле:Метка", "текст:Пин-код", "поле:Пин-код", "текст:Повтор пина", "поле:Повтор пина",
		"подпись:" + firstLine(wantPinLayoutHint),
		"галка:Привязать к этой учётке Windows (файл не…",
		"текст:Рекомендуется: украденный файл будет бес…",
		"подпись:", // строка состояния
		"кнопка:Сохранить", "кнопка:Не сохранять",
	}
	invAdd = []string{
		"подпись:Новый пользователь", "текст:Имя", "поле:Имя",
		"кнопка:Создать", "кнопка:Показать изменения", "подпись:", "кнопка:Отмена",
	}
	invRename = []string{
		"подпись:Переименовать \"Ноутбук\"", "текст:Новое имя", "поле:Новое имя",
		"кнопка:Сохранить", "кнопка:Показать изменения", "подпись:", "кнопка:Отмена",
	}
	invDelete = []string{
		"подпись:Удалить пользователя?", "подпись:Имя: Ноутбук…",
		"подпись:Не удалось получить данные о подключения…",
		"кнопка:Удалить", "кнопка:Показать изменения", "подпись:", "кнопка:Отмена",
	}
	invMain = []string{
		"подпись:Сервер: root@203.0.113.10", "подпись:Протокол:", "список:(Select one)",
		"кнопка:Обновить", "кнопка:Создать", "кнопка:Переименовать", "кнопка:Вкл/Выкл",
		"кнопка:Перевыпустить", "кнопка:Удалить", "таблица:", "подпись:",
	}
)

func cat(parts ...[]string) []string {
	var out []string
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

var connectMayOverlap = []string{"подсказка про раскладку|" + firstLine(connectKeyExplain)}

// Д1 поимённо: какие строки выдачи известны в минимальном окне.
var (
	knownSaveD1 = []osmotrKnown{
		knownD1("текст «Пин-код»: снизу"), knownD1("поле «Пин-код»: снизу"),
		knownD1("текст «Повтор пина»: снизу"), knownD1("поле «Повтор пина»: снизу"),
		knownD1("подпись «Похоже, включена не английская раскладка…»: снизу"),
		knownD1("галка «Привязать к этой учётке Windows (файл не…»: снизу"),
		knownD1("текст «Рекомендуется: украденный файл будет бес…»: снизу"),
		knownD1("подпись «»: снизу"), knownD1("кнопка «Сохранить»: снизу"),
		knownD1("поле «Метка» × кнопка «Не сохранять»"),
		knownD1("поле «Пин-код» × кнопка «Не сохранять»"),
	}
	knownSaveFailD1 = append(append([]osmotrKnown{}, knownSaveD1...),
		knownD1("подпись «"+firstLine(wantLayoutSwitchFailed)+"»: снизу"))
	// knownPinFailD2 — Д2, найден осмотром 25.09.2026 (второй круг): диалог
	// пин-кода в состоянии «отказ переключения раскладки» выше окна
	// минимального размера (408 т.), и «Отмена» ложится на «Повторить».
	knownPinFailD2 = []osmotrKnown{{
		id:   "ИЗВЕСТНЫЙ ДЕФЕКТ Д2 (пин-код с отказом раскладки не помещается в окно высотой 408 т.)",
		size: "минимальный", match: "кнопка «Повторить» × кнопка «Отмена»"}}
	knownActionD1 = []osmotrKnown{
		knownD1("подпись «»: снизу"),
		knownD1("кнопка «Показать изменения» × кнопка «Отмена»"),
		knownD1("подпись «» × кнопка «Отмена»"),
	}
	knownDeleteD1 = []osmotrKnown{
		knownD1("подпись «Не удалось получить данные о подключения…»: снизу"),
		knownD1("кнопка «Удалить»: снизу"), knownD1("кнопка «Показать изменения»: снизу"),
		knownD1("подпись «»: снизу"),
		knownD1("подпись «Имя: Ноутбук…» × кнопка «Отмена»"),
		knownD1("подпись «Не удалось получить данные о подключения…» × кнопка «Отмена»"),
	}
)

var osmotrForms = []osmotrForm{
	{name: "(а) экран подключения, подсказка вкл", open: openConnect(false, false),
		inventory: invConnect, mayOverlap: connectMayOverlap},
	{name: "(а) экран подключения, 1 хранилище, подсказка вкл", open: openConnect(true, false),
		inventory: cat(invConnect, invVault), mayOverlap: connectMayOverlap},
	{name: "(а) экран подключения, отказ раскладки", open: openConnect(false, true),
		inventory: cat(invConnect, invFail), mayOverlap: connectMayOverlap},
	{name: "(б) пин-код, подсказка вкл", open: openPin(false), inventory: invPinBase, width: 412},
	{name: "(б) пин-код, отказ раскладки", open: openPin(true), inventory: cat(invPinBase, invFail), width: 412,
		known: knownPinFailD2},
	{name: "(б) сохранение ключа, подсказка вкл", open: openSave(false), inventory: invSaveBase, width: 712,
		known: knownSaveD1},
	{name: "(б) сохранение ключа, отказ раскладки", open: openSave(true), inventory: cat(invSaveBase, invFail),
		width: 712, known: knownSaveFailD1},
	{name: "(в) новый пользователь", open: openAction(func(u *ui) { u.addDialog() }), inventory: invAdd,
		width: 412, known: knownActionD1},
	{name: "(в) переименование", open: openAction(func(u *ui) { u.renameSelected() }), inventory: invRename,
		width: 412, known: knownActionD1},
	{name: "(в) удаление", open: openDelete, inventory: invDelete, width: 452, known: knownDeleteD1},
	{name: "(г) главное окно", open: openMain, inventory: invMain},
}

var osmotrThemes = []struct {
	name string
	v    fyne.ThemeVariant
}{{"светлая", theme.VariantLight}, {"тёмная", theme.VariantDark}}

var osmotrSizes = []string{"стартовый", "минимальный"}

// runOsmotr — одна форма, одна тема, один размер: замер плюс опись.
// plant — подсадка дефекта в разметку (только у канареек), после открытия.
func runOsmotr(t *testing.T, f osmotrForm, size, themeName string, v fyne.ThemeVariant,
	plant func(*testing.T, osmotrScene)) *osmotrReport {
	t.Helper()
	u := osmotrUI(t, v)
	s := f.open(t, u, sizeWindow(u, size))
	if plant != nil {
		plant(t, s)
	}
	sz := u.win.Canvas().Size()
	rep := osmotrProbe(f.name, fmt.Sprintf("%s %.0fx%.0f", size, sz.Width, sz.Height), themeName, s, f.mayOverlap)
	rep.checkInventory(f.inventory)
	return rep
}

// TestOsmotrForms — осмотр всех семейств, ВОРОТА: красный на любом
// неразрешённом дефекте вида, на недействительной выдаче, на изменившейся
// ширине диалога и на неиспользованном разрешении.
func TestOsmotrForms(t *testing.T) {
	for _, f := range osmotrForms {
		for _, size := range osmotrSizes {
			for _, th := range osmotrThemes {
				t.Run(f.name+"/"+size+"/"+th.name, func(t *testing.T) {
					rep := runOsmotr(t, f, size, th.name, th.v, nil)
					t.Log("\n" + rep.String())
					osmotrGate(f, size, rep, t.Errorf)
				})
			}
		}
	}
}

// ---------- канарейки: подсадка в РАЗМЕТКУ, проверяются ВОРОТА ----------

func formByName(t *testing.T, name string) osmotrForm {
	t.Helper()
	for _, f := range osmotrForms {
		if f.name == name {
			return f
		}
	}
	t.Fatalf("канарейка ничего не значит: нет формы %q", name)
	return osmotrForm{}
}

// gateCanary прогоняет форму с подсадкой через ТЕ ЖЕ ворота, что
// TestOsmotrForms, и требует, чтобы ворота покраснели сообщением, где есть
// want. Дословные сообщения ворот печатаются.
func gateCanary(t *testing.T, f osmotrForm, size string, plant func(*testing.T, osmotrScene), want string) {
	t.Helper()
	rep := runOsmotr(t, f, size, "светлая", theme.VariantLight, plant)
	t.Log("\n" + rep.String())
	var errs []string
	osmotrGate(f, size, rep, func(format string, a ...any) { errs = append(errs, fmt.Sprintf(format, a...)) })
	for _, e := range errs {
		t.Log("ВОРОТА: " + e)
	}
	hit := false
	for _, e := range errs {
		if strings.Contains(e, want) {
			hit = true
		}
	}
	if !hit {
		t.Errorf("ворота НЕ ПОКРАСНЕЛИ на подсадке: ждали сообщения с %q, получили %d сообщений", want, len(errs))
	}
}

func replaceIn(t *testing.T, root, old, new fyne.CanvasObject) {
	t.Helper()
	p := findParent(root, old)
	if p == nil {
		t.Fatal("канарейка ничего не значит: у объекта нет родителя-контейнера")
	}
	for i, o := range p.Objects {
		if o == old {
			p.Objects[i] = new
		}
	}
	p.Refresh()
}

// К1 — ВЧЕРАШНИЙ ДЕФЕКТ (915fc49): в разметке диалога пин-кода подсказка
// сделана всплывающей над полем пина. Раскладка ставит её на «Сервер 1».
func TestOsmotrCanaryPopupOverServerName(t *testing.T) {
	gateCanary(t, formByName(t, "(б) пин-код, подсказка вкл"), "стартовый", func(t *testing.T, s osmotrScene) {
		pin := passwordEntry(t, s.root, 0)
		h := newLayoutHint(wantPinLayoutHint, pinDialogWidth, pin)
		replaceIn(t, s.root, pin, h.box)
		h.setOn(true)
		h.box.Refresh()
	}, "перекрытие: подпись «Сервер 1» × всплывашка")
}

// К2 — вылезание: в разметке главного окна очень длинное имя сервера.
func TestOsmotrCanaryPushedOutOfWindow(t *testing.T) {
	gateCanary(t, formByName(t, "(г) главное окно"), "стартовый", func(t *testing.T, s osmotrScene) {
		var server *widget.Label
		walkVisible(s.root, func(o fyne.CanvasObject) {
			if l, ok := o.(*widget.Label); ok && strings.HasPrefix(l.Text, "Сервер: ") {
				server = l
			}
		})
		if server == nil {
			t.Fatal("канарейка ничего не значит: нет подписи «Сервер: …»")
		}
		server.SetText("Сервер: root@203.0.113.10" + strings.Repeat(" очень-длинное-имя", 12))
	}, "вылезание: подпись «Протокол:»: справа")
}

// К3 — СЖАТИЕ (случай QA-01 «б»): резерв подсказки в диалоге пин-кода
// урезан вдвое по высоте.
func TestOsmotrCanarySqueezedHint(t *testing.T) {
	gateCanary(t, formByName(t, "(б) пин-код, подсказка вкл"), "стартовый", func(t *testing.T, s osmotrScene) {
		var hint *widget.Label
		walkVisible(s.root, func(o fyne.CanvasObject) {
			if l, ok := o.(*widget.Label); ok && l.Text == wantPinLayoutHint {
				hint = l
			}
		})
		if hint == nil {
			t.Fatal("канарейка ничего не значит: подсказка не показана")
		}
		box := findParent(s.root, hint)
		full := hintMetrics(wantPinLayoutHint, pinDialogWidth)
		replaceIn(t, s.root, box, container.NewGridWrap(fyne.NewSize(full.Width, full.Height/2), hint))
	}, "сжатие: подпись «Похоже, включена не английская раскладка")
}

// К4 — ЛИШНИЙ объект: в разметку диалога переименования добавлена кнопка.
func TestOsmotrCanaryExtraButton(t *testing.T) {
	gateCanary(t, formByName(t, "(в) переименование"), "стартовый", func(t *testing.T, s osmotrScene) {
		// Рядом с кнопками действия диалога — там, где лишнюю кнопку и
		// добавил бы невнимательный разработчик.
		p := findParent(s.root, buttonByText(t, s.root, "Показать изменения"))
		if p == nil {
			t.Fatal("канарейка ничего не значит: у кнопок действия нет ряда")
		}
		p.Add(widget.NewButton("Лишняя", nil))
	}, "сверх описи [\"кнопка:Лишняя\"]")
}

// К5 — диалог РАЗДУЛСЯ: подпись об отказе раскладки без переноса (случай
// QA-01 «TextWrapOff в layoutNoticeLabel — всё зелёное»).
func TestOsmotrCanaryNoticeWithoutWrap(t *testing.T) {
	gateCanary(t, formByName(t, "(б) пин-код, отказ раскладки"), "стартовый", func(t *testing.T, s osmotrScene) {
		var n *widget.Label
		walkVisible(s.root, func(o fyne.CanvasObject) {
			if l, ok := o.(*widget.Label); ok && l.Text == wantLayoutSwitchFailed {
				n = l
			}
		})
		if n == nil {
			t.Fatal("канарейка ничего не значит: подписи об отказе нет")
		}
		n.Wrapping = fyne.TextWrapOff
		n.Refresh()
	}, "ширина рамки диалога")
}

// К6 — НЕИСПОЛЬЗОВАННОЕ РАЗРЕШЕНИЕ: дефект «починили», а разрешение осталось.
func TestOsmotrCanaryStaleAllowance(t *testing.T) {
	f := formByName(t, "(в) переименование")
	f.known = append(append([]osmotrKnown{}, f.known...), osmotrKnown{
		id: "ИЗВЕСТНЫЙ ДЕФЕКТ Д0 (канарейка: давно починен)", size: "стартовый", match: "кнопка «Отмена»: снизу"})
	gateCanary(t, f, "стартовый", nil, "НЕИСПОЛЬЗОВАННОЕ РАЗРЕШЕНИЕ")
}

// К8 — УСТАРЕВШАЯ ВЁРСТКА ПРИ НЕИЗМЕННОМ МИНИМУМЕ (ревью QA-01 о досчёте):
// кнопка сдвинута мимо раскладки, её минимум не менялся. Боевой кадр такую
// вёрстку не переложит — и кадр прибора тоже не должен: ворота обязаны
// увидеть кнопку за краем, а не «починить» её пересчётом.
func TestOsmotrCanaryStaleLayoutNotMasked(t *testing.T) {
	gateCanary(t, formByName(t, "(г) главное окно"), "стартовый", func(t *testing.T, s osmotrScene) {
		b := buttonByText(t, s.root, "Удалить")
		b.Move(b.Position().AddXY(200, 0))
	}, "вылезание: кнопка «Удалить»: справа")
}

// К7 — сломанный обход (в контейнеры не заходит): ворота обязаны сказать
// «недействительна», а не выдать чистый ноль.
func TestOsmotrCanaryBrokenWalk(t *testing.T) {
	saved := osmotrWalk
	osmotrWalk = func(o fyne.CanvasObject, fn func(fyne.CanvasObject) bool) {
		if o == nil || !o.Visible() || fn(o) {
			return
		}
		if w, ok := o.(fyne.Widget); ok { // в *fyne.Container НЕ заходит
			for _, c := range test.WidgetRenderer(w).Objects() {
				if _, isC := c.(*fyne.Container); !isC {
					fn(c)
				}
			}
		}
	}
	t.Cleanup(func() { osmotrWalk = saved })
	for _, name := range []string{"(а) экран подключения, подсказка вкл", "(б) пин-код, подсказка вкл", "(г) главное окно"} {
		gateCanary(t, formByName(t, name), "стартовый", nil, "выдача НЕДЕЙСТВИТЕЛЬНА")
	}
}

func findParent(root, child fyne.CanvasObject) *fyne.Container {
	var p *fyne.Container
	walkObjects(root, func(o fyne.CanvasObject) {
		if c, ok := o.(*fyne.Container); ok {
			for _, x := range c.Objects {
				if x == child {
					p = c
				}
			}
		}
	})
	return p
}
