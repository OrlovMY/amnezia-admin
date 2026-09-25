package main

// ОСМОТР ФОРМЫ ЦЕЛИКОМ — прибор HARD-стандарта «Осмотр страницы целиком после
// визуальной правки» (.profi, knowledge/standards/verify-in-ui.md) для GUI на
// Fyne.
//
// ЗАЧЕМ. Прибор стандарта (osmotr-probe.js) — браузерная проба, у Fyne нет ни
// DOM, ни CSS. А болезнь та же: сторожа этой ветки мерят свойства ЭЛЕМЕНТОВ
// (где стоит всплывашка, какой высоты резерв), а вид ФОРМЫ целиком не мерил
// никто — и ревьюер UX-01 вручную нашёл, что всплывашка накрывает имя сервера
// и поле «Метка» при зелёных сторожах. Прибор ниже обходит ВСЁ видимое в
// форме и отдаёт числа:
//
//	вылезание   — сколько точек объект выходит за окно или за рамку диалога;
//	перекрытие  — пары видимых объектов с общей площадью, какие и сколько;
//	сжатие      — объект получил меньше своего минимального размера (текст
//	              обрезан) — аналог пункта 3 «сжимается, а не переносится»;
//	состав      — поля, кнопки, подписи, галки, списки;
//	шкала       — различные высоты кнопок, полей, списков.
//
// ОБХОД — боевой: в скрытое не заходит (walkVisibleStop, как driver.
// WalkVisibleObjectTree). Он вынесен в переменную osmotrWalk только затем,
// чтобы канарейка могла его сломать и проверить, что прибор это заметит.
//
// «НОЛЬ — ЗАМЕР, А НЕ “НЕ СМОТРЕЛИ”». У каждой формы руками выписан опис —
// то, что прибор ОБЯЗАН найти. Не нашёл хоть одного — выдача по форме
// НЕДЕЙСТВИТЕЛЬНА целиком, а не частична, и тест красный.
//
// СНИМКИ. При заданной переменной окружения OSMOTR_DIR прибор пишет туда PNG
// каждой формы в каждой теме (canvas.Capture тестового драйвера, программная
// отрисовка). В репозиторий снимки не кладутся.

import (
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
	"fyne.io/fyne/v2/test"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"amnezia-admin/core"
)

// osmotrWalk — обход прибора. Боевой; подменяется только канарейкой.
var osmotrWalk = walkVisibleStop

// variantTheme — встроенная тема Fyne (ТА ЖЕ, что app.New() даёт в бою:
// размеры, шрифты), с принудительным вариантом светлый/тёмный.
//
// ПОЧЕМУ НЕ ТЕМА ТЕСТОВОГО ДРАЙВЕРА. test.NewApp() ставит test.Theme(), у
// которой ДРУГИЕ размеры: полоса прокрутки 16 вместо 12, рамка поля 2 вместо
// 1, скругление 4 вместо 5, заголовок 23.8 вместо 24. Осмотр на ней мерил бы
// не ту вёрстку, что видит владелец.
type variantTheme struct {
	fyne.Theme
	v fyne.ThemeVariant
}

func (t variantTheme) Color(n fyne.ThemeColorName, _ fyne.ThemeVariant) color.Color {
	return t.Theme.Color(n, t.v)
}

// osmotrAtom — наименьшая единица осмотра: то, что человек видит как одно
// целое (подпись, кнопка, поле, галка, список, таблица, всплывашка).
type osmotrAtom struct {
	kind, name string
	obj        fyne.CanvasObject
	r          rect
}

type osmotrReport struct {
	form, size, theme string
	bounds            rect
	boundsWhat        string

	atoms      []osmotrAtom
	backdrops  int // подложки (canvas.Rectangle и т.п.) — не атомы, названы числом
	degenerate int // нулевой ширины или высоты и без текста — невидимы
	zeroSized  []string
	accent     int // кнопок акцентной важности (HighImportance)
	settled    int // объектов, сдвинутых досчётом раскладки (osmotrSettle)

	overflow  []string // «имя: N т. сторона»
	overflowT float32
	overlaps  []string
	allowed   []string // перекрытия, разрешённые поимённо
	overlapA  float32
	squeezed  []string

	counts  map[string]int
	heights map[string][]float32

	missing []string // опис не найден — выдача НЕДЕЙСТВИТЕЛЬНА
	shot    string
}

func (r *osmotrReport) valid() bool { return len(r.missing) == 0 }

// osmotrClassify — чем объект является для осмотра. stop — внутрь не идём:
// его части — это он сам (Label рисует себя кусками RichText, Entry — текстом
// и курсором, таблица — прокручиваемым содержимым).
func osmotrClassify(o fyne.CanvasObject) (kind, name string, stop bool) {
	switch x := o.(type) {
	case *fyne.Container:
		if _, ok := x.Layout.(*hintFloatLayout); ok {
			return "", "", false // сама раскладка — контейнер; всплывашка ниже
		}
		return "", "", false
	case *widget.Label:
		return "подпись", firstLine(x.Text), true
	case *widget.Button:
		return "кнопка", x.Text, true
	case *widget.Entry:
		if x.MultiLine {
			return "поле многострочное", x.PlaceHolder, true
		}
		return "поле", x.PlaceHolder, true
	case *widget.Check:
		return "галка", firstLine(x.Text), true
	case *widget.Select:
		return "список", x.PlaceHolder, true
	case *widget.Table:
		return "таблица", "", true
	case *clientTable:
		// Внутрь таблицы не идём: она прокручивается в обе стороны, и её
		// ячейки законно уходят за край видимой области. Вылезание и
		// перекрытие ВНУТРИ таблицы прибор не мерит — это названная граница
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

// osmotrSettle — ДОСЧЁТ РАСКЛАДКИ, который в бою делает драйвер.
//
// Боевой glfw перед каждым кадром зовёт common.Canvas.EnsureMinSize
// (internal/driver/common/canvas.go:84): у кого минимальный размер
// изменился, у того родитель перекладывается, и так вверх до корня —
// всплывающего окна диалога, которое перекладывается под новое содержимое.
// Тестовый драйвер этого не делает: подпись, чей текст сменился ПОСЛЕ показа
// диалога (в диалоге удаления «Узнаю, подключался ли…» → «Не удалось
// получить…»), остаётся в прежней высоте и на снимке обрезана. Это был бы
// дефект тестового драйвера, выданный за дефект программы.
//
// Досчёт перекладывает ВСЁ видимое снизу вверх, а не только изменившееся.
// Для детерминированных раскладок это то же самое; разница — если в бою
// какая-то раскладка НЕ пересчитывается (минимум не изменился), досчёт её
// всё равно пересчитает и может скрыть устаревшую вёрстку. Поэтому выдача
// печатает, сколько объектов досчёт сдвинул: ноль — снимок и так совпадал.
func osmotrSettle(o fyne.CanvasObject) {
	if o == nil || !o.Visible() {
		return
	}
	switch x := o.(type) {
	case *fyne.Container:
		for _, c := range x.Objects {
			osmotrSettle(c)
		}
		if x.Layout != nil {
			x.Layout.Layout(x.Objects, x.Size())
		}
	case fyne.Widget:
		r := test.WidgetRenderer(x)
		for _, c := range r.Objects() {
			osmotrSettle(c)
		}
		r.Layout(x.Size())
	}
}

// atomRects — прямоугольники всего видимого, для счёта «что сдвинул досчёт».
func atomRects(root fyne.CanvasObject) map[fyne.CanvasObject]rect {
	out := map[fyne.CanvasObject]rect{}
	walkVisible(root, func(o fyne.CanvasObject) { out[o] = rectOf(o) })
	return out
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

// hintPopups — множество всплывашек подсказки: осмотр считает каждую одним
// атомом, а не подложкой плюс подписью, накрывающими друг друга.
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

// osmotrScene — открытая форма, готовая к осмотру.
type osmotrScene struct {
	root       fyne.CanvasObject
	canvas     fyne.Canvas
	bounds     rect
	boundsWhat string
	// need — опис: «вид:имя», которые прибор обязан найти. Руками.
	need []string
	// mayOverlap — перекрытия, разрешённые поимённо (пара «имя|имя» в любом
	// порядке). Каждая строка — чьё-то решение, а не побочный эффект.
	mayOverlap []string
}

func osmotrProbe(form, size, themeName string, s osmotrScene) *osmotrReport {
	// СНАЧАЛА ОТРИСОВКА, ПОТОМ ЗАМЕР. Fyne досчитывает раскладку лениво, при
	// рисовании: замер до Capture давал рамку диалога на 16 т. ниже той, что
	// видна на снимке (первый прогон, диалог пин-кода). Мерим то, что
	// нарисовано.
	before := atomRects(s.root)
	osmotrSettle(s.root)
	img := s.canvas.Capture()
	// Границу — тоже ПОСЛЕ отрисовки: рамка диалога, снятая до Capture,
	// отставала от нарисованной на 20 т. сверху и 20 снизу (диалог пин-кода
	// вырос, когда показалась кнопка «Повторить»).
	if pop, ok := s.root.(*widget.PopUp); ok {
		s.bounds = rectOf(pop.Content)
	} else {
		s.bounds = windowBounds(s.canvas)
	}
	rep := &osmotrReport{form: form, size: size, theme: themeName, bounds: s.bounds, boundsWhat: s.boundsWhat,
		counts: map[string]int{}, heights: map[string][]float32{}}
	for o, r := range atomRects(s.root) {
		if b, ok := before[o]; ok && b != r {
			rep.settled++
		}
	}
	pops := hintPopups(s.root)
	osmotrWalk(s.root, func(o fyne.CanvasObject) bool {
		var kind, name string
		stop := false
		if pops[o] {
			kind, name, stop = "всплывашка", "подсказка про раскладку", true
		} else {
			kind, name, stop = osmotrClassify(o)
		}
		if kind == "" {
			if _, ok := o.(*canvas.Rectangle); ok {
				rep.backdrops++
			}
			return false
		}
		r := rectOf(o)
		if r.size.Width <= 0 || r.size.Height <= 0 {
			// НУЛЕВОЙ РАЗМЕР — НЕ ЗНАЧИТ НЕВИДИМ. Заголовок диалога Fyne 2.7.4
			// раскладка не размещает вовсе (dialog/base.go, dialogLayout.Layout
			// не трогает obj[4]), а текст его всё равно рисуется от своей точки
			// — это видно на снимке. Подпись с текстом меряется по MinSize.
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

	// опис
	for _, n := range s.need {
		kind, name, _ := strings.Cut(n, ":")
		found := false
		for _, a := range rep.atoms {
			if a.kind == kind && (name == "" || a.name == name) {
				found = true
				break
			}
		}
		if !found {
			rep.missing = append(rep.missing, n)
		}
	}

	allowed := map[string]bool{}
	for _, p := range s.mayOverlap {
		a, b, _ := strings.Cut(p, "|")
		allowed[a+"|"+b], allowed[b+"|"+a] = true, true
	}

	const eps = 0.5
	for i, a := range rep.atoms {
		rep.counts[a.kind]++
		switch a.kind {
		case "кнопка", "поле", "список":
			if b, ok := a.obj.(*widget.Button); ok && b.Importance == widget.HighImportance {
				rep.accent++
			}
			rep.heights[a.kind] = append(rep.heights[a.kind], a.r.size.Height)
		}
		// 1. вылезание
		b := s.bounds
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
		// 2. перекрытие
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

func (r *osmotrReport) String() string {
	var b strings.Builder
	verdict := "ДЕЙСТВИТЕЛЬНА"
	if !r.valid() {
		verdict = "НЕДЕЙСТВИТЕЛЬНА: не найдено из описи " + strings.Join(r.missing, "; ")
	}
	fmt.Fprintf(&b, "== %s | %s | %s — выдача %s\n", r.form, r.size, r.theme, verdict)
	fmt.Fprintf(&b, "   граница (%s): %v\n", r.boundsWhat, r.bounds)
	fmt.Fprintf(&b, "   атомов %d, подложек %d, вырожденных %d\n", len(r.atoms), r.backdrops, r.degenerate)
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
	fmt.Fprintf(&b, "   досчёт раскладки сдвинул объектов: %d\n", r.settled)
	fmt.Fprintf(&b, "   акцентных кнопок %d\n", r.accent)
	fmt.Fprintf(&b, "   вылезаний %d (сумма худших сторон %.1f т.)\n", len(r.overflow), r.overflowT)
	for _, s := range r.overflow {
		fmt.Fprintf(&b, "     ! %s\n", s)
	}
	fmt.Fprintf(&b, "   перекрытий %d (площадь %.0f т²), разрешённых поимённо %d\n", len(r.overlaps), r.overlapA, len(r.allowed))
	for _, s := range r.overlaps {
		fmt.Fprintf(&b, "     ! %s\n", s)
	}
	for _, s := range r.allowed {
		fmt.Fprintf(&b, "     (разрешено) %s\n", s)
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

// ---------- формы ----------

type osmotrEnv struct {
	u     *ui
	theme string
}

// osmotrUI — ui в боевой теме заданного варианта; раскладка «переключилась»
// (обычный путь, без подписи об отказе), в сеть не ходит.
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
	// Сервера нет: любой запрос отвечает отказом. Диалог удаления поэтому
	// показывает третье состояние («статистику получить не удалось»).
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
	// Выбор протокола — БЕЗ обработчика: он пошёл бы на сервер (refresh).
	u.cur = &u.containers[0]
	u.protoSelect.Selected = u.protoSelect.Options[0]
	u.protoSelect.Refresh()
	u.table.Refresh()
}

// osmotrNoServer — «сервера нет». gate, если задан, держит ответ, пока форма
// не собрана: тестовый драйвер исполняет fyne.Do прямо в фоновой горутине, и
// без задержки ответ правил бы подписи диалога одновременно с его постройкой
// (go test -race это ловит). В бою fyne.Do идёт в главный поток.
type osmotrNoServer struct{ gate chan struct{} }

func (s osmotrNoServer) Run(string, []byte) (string, error) {
	if s.gate != nil {
		<-s.gate
	}
	return "", fmt.Errorf("осмотр: сервера нет")
}

// withOneVault — в каталоге хранилищ лежит один (пустой, поддельный) файл,
// как у владельца: на экране подключения появляется кнопка «Сервер 1».
// Каталог — рядом с ТЕСТОВЫМ бинарником; существующий не трогаем.
func withOneVault(t *testing.T) {
	t.Helper()
	dir := core.DefaultVaultDir()
	// Только рядом с ТЕСТОВЫМ бинарником (он собирается во временном
	// каталоге) и только если настоящих хранилищ там нет: чужие .avlt
	// осмотр не открывает и не трогает.
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
		if statErr != nil { // каталог создан нами
			os.Remove(dir)
		}
	})
}

func windowBounds(c fyne.Canvas) rect { return rect{size: c.Size()} }

func dialogBounds(t *testing.T, c fyne.Canvas) (fyne.CanvasObject, rect) {
	t.Helper()
	top := c.Overlays().Top()
	pop, ok := top.(*widget.PopUp)
	if !ok {
		t.Fatalf("верхний оверлей — %T, а не диалог", top)
	}
	// Рамка диалога — прямоугольник содержимого всплывающего окна: его
	// заливает themedBackground диалога (dialog/base.go, obj[1] во весь
	// размер), и именно он виден на снимке белым (тёмным) полем.
	//
	// НЕ подложка рендерера PopUp: она пересчитывается только при Resize/
	// Refresh самого PopUp и отстаёт, когда содержимое диалога выросло
	// после показа (в диалоге пин-кода появилась кнопка «Повторить» —
	// подложка осталась 134..480 при видимом поле 118..503). Мерить по ней
	// значило бы мерить то, чего на экране нет.
	if r := rectOf(pop.Content); r.size.Width > 0 && r.size.Height > 0 {
		return pop, r
	}
	t.Fatal("рамка диалога не найдена — выдача по форме недействительна")
	return nil, rect{}
}

// osmotrForm — форма: как открыть и чем мерить. size: "стартовый" или
// "минимальный" — минимальный берётся из MinSize содержимого окна, то есть
// меньше окно в бою не станет.
type osmotrForm struct {
	name string
	open func(t *testing.T, u *ui, sized func()) osmotrScene
}

func sizeWindow(u *ui, which string) func() {
	return func() {
		if which == "минимальный" {
			// Как glfw: минимум окна — MinSize содержимого плюс поля канвы
			// (canvas padded) с каждой стороны.
			p := 2 * theme.Padding()
			u.win.Resize(u.win.Content().MinSize().AddWidthHeight(p, p))
		} else {
			u.win.Resize(startWindowSize())
		}
	}
}

var osmotrForms = []osmotrForm{
	{"(а) экран подключения, подсказка вкл", func(t *testing.T, u *ui, sized func()) osmotrScene {
		u.showConnectScreen("")
		sized()
		c := u.win.Canvas()
		firstEntry(c.Content()).SetText("vpn://кириллицаВКлюче")
		c.Content().Refresh()
		return osmotrScene{root: c.Content(), canvas: c, bounds: windowBounds(c), boundsWhat: "окно",
			need:       []string{"кнопка:Подключиться", "подпись:Amnezia Admin", "поле многострочное:", "всплывашка:"},
			mayOverlap: []string{"подсказка про раскладку|" + firstLine(connectKeyExplain)}}
	}},
	{"(а) экран подключения, 1 хранилище, подсказка вкл", func(t *testing.T, u *ui, sized func()) osmotrScene {
		withOneVault(t)
		u.showConnectScreen("")
		sized()
		c := u.win.Canvas()
		firstEntry(c.Content()).SetText("vpn://кириллицаВКлюче")
		c.Content().Refresh()
		return osmotrScene{root: c.Content(), canvas: c, bounds: windowBounds(c), boundsWhat: "окно",
			need:       []string{"кнопка:Подключиться", "кнопка:Сервер 1", "поле многострочное:", "всплывашка:"},
			mayOverlap: []string{"подсказка про раскладку|" + firstLine(connectKeyExplain)}}
	}},
	{"(б) пин-код, подсказка вкл", func(t *testing.T, u *ui, sized func()) osmotrScene {
		saved := core.NetworkTimeHosts
		core.NetworkTimeHosts = []string{"https://127.0.0.1:1"}
		t.Cleanup(func() { core.NetworkTimeHosts = saved })
		t.Cleanup(func() { waitGUIGoroutines(t) })
		u.showConnectScreen("")
		sized()
		u.showVaultPinDialog(t.TempDir()+"/нет.avlt", "Сервер 1", widget.NewButton("", nil), widget.NewLabel(""))
		waitGUIGoroutines(t)
		c := u.win.Canvas()
		root, b := dialogBounds(t, c)
		passwordEntry(t, root, 0).SetText(typedCyrillicPin)
		root.Refresh()
		return osmotrScene{root: root, canvas: c, bounds: b, boundsWhat: "рамка диалога",
			need: []string{"подпись:Сервер 1", "поле:Пин-код", "кнопка:Открыть", "кнопка:Отмена", "подпись:Введите пин-код"}}
	}},
	{"(б) сохранение ключа, подсказка вкл", func(t *testing.T, u *ui, sized func()) osmotrScene {
		osmotrMain(u)
		sized()
		u.offerSaveKey("vpn://не-настоящий", "203.0.113.10", "")
		c := u.win.Canvas()
		root, b := dialogBounds(t, c)
		passwordEntry(t, root, 0).SetText(typedCyrillicPin)
		root.Refresh()
		return osmotrScene{root: root, canvas: c, bounds: b, boundsWhat: "рамка диалога",
			need: []string{"поле:", "кнопка:Сохранить", "кнопка:Не сохранять", "галка:", "текст:Метка"}}
	}},
	{"(в) новый пользователь", func(t *testing.T, u *ui, sized func()) osmotrScene {
		osmotrMain(u)
		sized()
		u.addDialog()
		c := u.win.Canvas()
		root, b := dialogBounds(t, c)
		return osmotrScene{root: root, canvas: c, bounds: b, boundsWhat: "рамка диалога",
			need: []string{"поле:Иванов Иван", "кнопка:Отмена", "текст:Имя"}}
	}},
	{"(в) переименование", func(t *testing.T, u *ui, sized func()) osmotrScene {
		osmotrMain(u)
		sized()
		u.selectedRow = 0
		u.renameSelected()
		c := u.win.Canvas()
		root, b := dialogBounds(t, c)
		return osmotrScene{root: root, canvas: c, bounds: b, boundsWhat: "рамка диалога",
			need: []string{"поле:", "кнопка:Отмена"}}
	}},
	{"(в) удаление", func(t *testing.T, u *ui, sized func()) osmotrScene {
		osmotrMain(u)
		sized()
		u.selectedRow = 0
		t.Cleanup(func() { waitGUIGoroutines(t) })
		gate := make(chan struct{})
		u.sess = core.NewSessionWithRunner(osmotrNoServer{gate: gate}, u.sess.Creds)
		u.deleteSelected()
		close(gate)
		waitGUIGoroutines(t) // запрос статистики (отказ) завершён
		c := u.win.Canvas()
		root, b := dialogBounds(t, c)
		return osmotrScene{root: root, canvas: c, bounds: b, boundsWhat: "рамка диалога",
			need: []string{"кнопка:Отмена", "подпись:Удалить пользователя?"}}
	}},
	{"(г) главное окно", func(t *testing.T, u *ui, sized func()) osmotrScene {
		osmotrMain(u)
		sized()
		c := u.win.Canvas()
		return osmotrScene{root: c.Content(), canvas: c, bounds: windowBounds(c), boundsWhat: "окно",
			need: []string{"кнопка:Обновить", "кнопка:Создать", "кнопка:Переименовать", "кнопка:Вкл/Выкл",
				"кнопка:Перевыпустить", "кнопка:Удалить", "таблица:", "список:"}}
	}},
}

// connectKeyExplain — подпись над полем ключа, которую всплывашке РАЗРЕШЕНО
// накрыть (решение уже записано в hintpopup_test.go, openConnectScene.mayCover).
const connectKeyExplain = "Нужен админский ключ — внутри него SSH-доступ к серверу." +
	"\nПользовательский (share) ключ не подойдёт."

var osmotrThemes = []struct {
	name string
	v    fyne.ThemeVariant
}{{"светлая", theme.VariantLight}, {"тёмная", theme.VariantDark}}

var osmotrSizes = []string{"стартовый", "минимальный"}

// runOsmotr — один осмотр одной формы в одной теме и одном размере.
func runOsmotr(t *testing.T, f osmotrForm, size, themeName string, v fyne.ThemeVariant) *osmotrReport {
	t.Helper()
	u := osmotrUI(t, v)
	s := f.open(t, u, sizeWindow(u, size))
	return osmotrProbe(f.name, fmt.Sprintf("%s %.0fx%.0f", size, u.win.Canvas().Size().Width, u.win.Canvas().Size().Height), themeName, s)
}

// TestOsmotrForms — осмотр всех семейств. Красный — только когда выдача
// НЕДЕЙСТВИТЕЛЬНА (обход не нашёл описи): это прибор, а не сторож вида.
// Найденные вылезания и перекрытия печатаются числами (go test -v) и
// решаются ядром и владельцем, а не тестом.
func TestOsmotrForms(t *testing.T) {
	for _, f := range osmotrForms {
		for _, size := range osmotrSizes {
			for _, th := range osmotrThemes {
				t.Run(f.name+"/"+size+"/"+th.name, func(t *testing.T) {
					rep := runOsmotr(t, f, size, th.name, th.v)
					t.Log("\n" + rep.String())
					if !rep.valid() {
						t.Errorf("выдача НЕДЕЙСТВИТЕЛЬНА: %v", rep.missing)
					}
				})
			}
		}
	}
}

// ---------- канарейки: прибор обязан споткнуться ----------

// TestOsmotrCanaryPopupOverServerName — ВЧЕРАШНИЙ ДЕФЕКТ: в диалоге пин-кода
// подсказка сделана ВСПЛЫВАЮЩЕЙ над полем пина (так было в 915fc49 до ревью
// UX-01). Раскладка hintFloatLayout ставит её над полем — то есть на «Сервер
// 1». Дефект получен РАСКЛАДКОЙ, а не сдвигом руками: досчёт раскладки
// (osmotrSettle) его не сотрёт. Прибор обязан выдать перекрытие числом.
func TestOsmotrCanaryPopupOverServerName(t *testing.T) {
	u := osmotrUI(t, theme.VariantLight)
	s := osmotrForms[2].open(t, u, sizeWindow(u, "стартовый"))
	pin := passwordEntry(t, s.root, 0)
	parent := findParent(s.root, pin)
	if parent == nil {
		t.Fatal("канарейка ничего не значит: у поля пина нет родителя-контейнера")
	}
	h := newLayoutHint(wantPinLayoutHint, pinDialogWidth, pin)
	for i, o := range parent.Objects {
		if o == pin {
			parent.Objects[i] = h.box
		}
	}
	h.setOn(true)
	parent.Refresh()

	rep := osmotrProbe("канарейка: всплывашка в диалоге пин-кода", "стартовый", "светлая", s)
	t.Log("\n" + rep.String())
	hit := false
	for _, o := range rep.overlaps {
		if strings.Contains(o, "«Сервер 1»") && strings.Contains(o, "всплывашка") {
			hit = true
		}
	}
	if !hit || rep.overlapA <= 0 {
		t.Errorf("прибор НЕ ЗАМЕТИЛ всплывашку поверх «Сервер 1»: перекрытий %d, площадь %.0f", len(rep.overlaps), rep.overlapA)
	}
}

// TestOsmotrCanaryPushedOutOfWindow — объект, вытолкнутый за край окна
// РАСКЛАДКОЙ: очень длинное имя сервера в верхней строке главного окна
// (Border раздаёт левому блоку его минимум, правый ряд кнопок уезжает).
func TestOsmotrCanaryPushedOutOfWindow(t *testing.T) {
	u := osmotrUI(t, theme.VariantLight)
	s := osmotrForms[7].open(t, u, sizeWindow(u, "стартовый"))
	var server *widget.Label
	walkVisible(s.root, func(o fyne.CanvasObject) {
		if l, ok := o.(*widget.Label); ok && strings.HasPrefix(l.Text, "Сервер: ") {
			server = l
		}
	})
	if server == nil {
		t.Fatal("канарейка ничего не значит: нет подписи «Сервер: …»")
	}
	server.SetText("Сервер: root@" + strings.Repeat("очень-длинное-имя-", 12) + "example")
	s.root.Refresh()

	rep := osmotrProbe("канарейка: длинное имя сервера", "стартовый", "светлая", s)
	t.Log("\n" + rep.String())
	if len(rep.overflow) == 0 || rep.overflowT <= 0 {
		t.Errorf("прибор НЕ ЗАМЕТИЛ вылезания за край окна: вылезаний %d", len(rep.overflow))
	}
}

// TestOsmotrCanaryBrokenWalk — сломанный обход (в контейнеры не заходит).
// Прибор обязан объявить выдачу НЕДЕЙСТВИТЕЛЬНОЙ, а не выдать чистый ноль.
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

	for _, i := range []int{0, 2, 7} {
		u := osmotrUI(t, theme.VariantLight)
		s := osmotrForms[i].open(t, u, sizeWindow(u, "стартовый"))
		rep := osmotrProbe(osmotrForms[i].name, "стартовый", "светлая", s)
		t.Log("\n" + rep.String())
		if rep.valid() {
			t.Errorf("%s: обход сломан, а выдача объявлена действительной (атомов %d, перекрытий %d, вылезаний %d) — "+
				"прибор выдал бы чистый ноль", osmotrForms[i].name, len(rep.atoms), len(rep.overlaps), len(rep.overflow))
		}
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
