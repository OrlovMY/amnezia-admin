//go:build ignore

// Генератор знака amnezia-admin (вариант 01, выбор владельца 13.10.2026):
// две «A» грубой кистью в незамкнутом круге, внутренние ноги сходятся
// внизу; цвет — акварельные полосы под маской по диагонали (приём символа
// Amnezia, https://amnezia.org/img/logos/logo-a-sym.svg; композиция и
// кривые свои). Цвета полос — из символа Amnezia, фон #1C1D21 — onyxBlack
// из amnezia-client client/ui/qml/Modules/Style/AmneziaStyle.qml.
//
// Сборка, из корня репозитория:
//
//  1. go run assets/gen.go svg assets
//     → assets/logo.svg (крупный, для 48/256) и assets/logo-small.svg
//     (упрощённый: толще мазки, без щетинок, короче шипы — для 16/32).
//
//  2. Растры — РУЧНОЙ шаг через headless Chrome (pure-Go рендереры SVG,
//     например oksvg, не понимают <mask>, а без маски знак теряет цвет).
//     Для N из 256, 48 (logo.svg) и 32, 16 (logo-small.svg): скопировать SVG
//     во временный файл с width="N" height="N" (viewBox прежний) и
//
//     chrome --headless=new --disable-gpu --hide-scrollbars \
//     --user-data-dir=<tmp> --window-size=N,N \
//     --default-background-color=00000000 \
//     --screenshot=assets/logo-N.png file:///<tmp>/logo-N.svg
//
//  3. go run assets/gen.go ico assets   → assets/logo.ico из PNG шага 2.
//
//  4. cp assets/logo-256.png cmd/gui/icon.png
//     go run github.com/tc-hib/go-winres@v0.3.3 simply --arch amd64 \
//     --manifest none --icon assets/logo.ico --out cmd/gui/rsrc
//
// .syso лежит в репозитории: `go build ./cmd/gui` под windows/amd64 берёт
// его сам. Совпадение icon.png и .syso с assets/ стережёт cmd/gui/icon_test.go.
package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
)

type pt struct{ x, y float64 }

func bez(a, b, c, d pt) func(float64) pt {
	return func(t float64) pt {
		u := 1 - t
		return pt{u*u*u*a.x + 3*u*u*t*b.x + 3*u*t*t*c.x + t*t*t*d.x,
			u*u*u*a.y + 3*u*u*t*b.y + 3*u*t*t*c.y + t*t*t*d.y}
	}
}

// arc — дуга кольца с неровным радиусом (±2.5).
func arc(c pt, r, a0, a1 float64) func(float64) pt {
	return func(t float64) pt {
		a := (a0 + (a1-a0)*t) * math.Pi / 180
		rr := r + 2.5*math.Sin(3*a+1)
		return pt{c.x + rr*math.Cos(a), c.y + rr*math.Sin(a)}
	}
}

// brush — контур мазка: ширина неравномерная, концы — острые шипы,
// края рваные (шум + редкие щетинки); small — без щетинок и шума.
func brush(rng *rand.Rand, f func(float64) pt, w, head, tail float64, small bool) string {
	const n = 110
	rough := 1.0
	if small {
		rough = 0
	}
	var L, R []pt
	nl, nr := 0.0, 0.0
	_, _ = rng.Float64(), rng.Float64() // сохраняет последовательность seed варианта 01
	for i := 0; i <= n; i++ {
		t := float64(i) / n
		p := f(t)
		q, o := f(math.Min(1, t+0.01)), f(math.Max(0, t-0.01))
		dx, dy := q.x-o.x, q.y-o.y
		l := math.Hypot(dx, dy) + 1e-9
		nx, ny := -dy/l, dx/l
		prof := 1.0
		if t < head {
			prof = math.Pow(t/head, 0.7)
		}
		if t > 1-tail {
			prof = math.Min(prof, math.Pow((1-t)/tail, 1.3))
		}
		prof *= 0.85 + 0.25*math.Sin(t*7+w)
		nl = 0.85*nl + 0.15*(rng.Float64()*2-1)
		nr = 0.85*nr + 0.15*(rng.Float64()*2-1)
		hl := w / 2 * prof * (1 + 0.22*rough*nl)
		hr := w / 2 * prof * (1 + 0.22*rough*nr)
		if prof > 0.5 && rng.Float64() < 0.025*rough {
			hl += w * 0.22 * rng.Float64() // щетинка
		}
		if prof > 0.5 && rng.Float64() < 0.025*rough {
			hr += w * 0.22 * rng.Float64()
		}
		L = append(L, pt{p.x + nx*hl, p.y + ny*hl})
		R = append(R, pt{p.x - nx*hr, p.y - ny*hr})
	}
	var b strings.Builder
	fmt.Fprintf(&b, "M%.1f %.1f", L[0].x, L[0].y)
	for _, p := range L[1:] {
		fmt.Fprintf(&b, "L%.1f %.1f", p.x, p.y)
	}
	for i := len(R) - 1; i >= 0; i-- {
		fmt.Fprintf(&b, "L%.1f %.1f", R[i].x, R[i].y)
	}
	b.WriteString("Z")
	return b.String()
}

// strokes — кольцо (r=100, разрыв сверху справа −100°…−48°), две A,
// наклонённые друг к другу, с общей нижней точкой, сквозная перекладина.
func strokes(r *rand.Rand, small bool) []string {
	P := func(x, y float64) pt { return pt{x, y} }
	wm, tail, rw := 1.35, 0.25, 15.0
	if small {
		wm, tail, rw = wm*1.15, tail*0.6, rw*1.3
	}
	return []string{
		brush(r, arc(P(128, 134), 100, -48, 260), rw, 0.06, 0.1, small),
		brush(r, bez(P(50, 248), P(60, 160), P(70, 80), P(84, 4)), 22*wm, 0.06, tail, small),
		brush(r, bez(P(84, 24), P(102, 90), P(116, 160), P(128, 214)), 18*wm, 0.1, tail, small),
		brush(r, bez(P(178, 4), P(160, 90), P(142, 160), P(128, 214)), 18*wm, 0.06, tail, small),
		brush(r, bez(P(178, 24), P(190, 90), P(198, 160), P(208, 248)), 22*wm, 0.1, tail, small),
		brush(r, bez(P(4, 140), P(90, 126), P(150, 158), P(252, 138)), 16*wm, 0.3, tail*0.6, small),
	}
}

// bands — акварельные полосы с волнистыми краями: в повёрнутой на −30°
// системе слева сверху вниз бирюза → голубые → серый → фиолетовые, справа
// розовый → жёлтые → оранжевые.
func bands(c pt) string {
	type st struct {
		y0  float64
		col string
	}
	left := []st{{-120, "#66BCB2"}, {70, "#7EBAD2"}, {104, "#87ADD4"}, {126, "#8D888C"}, {144, "#7D89C1"}, {170, "#5E5F97"}, {200, "#513F92"}, {240, "#8D888C"}}
	right := []st{{-120, "#F8C9D1"}, {72, "#FAD67F"}, {104, "#FBCF67"}, {128, "#F6A453"}, {156, "#F3AC49"}, {186, "#F18928"}}
	var b strings.Builder
	edge := func(y float64) float64 { return c.x + 10*math.Sin(y/23) }
	half := func(sts []st, lft bool, ph float64) {
		for i, s := range sts {
			y1 := 400.0
			if i+1 < len(sts) {
				y1 = sts[i+1].y0
			}
			line := func(y0 float64, rev bool) []pt {
				var p []pt
				for k := 0; k <= 16; k++ {
					t := float64(k) / 16
					var x float64
					if lft {
						x = -120 + t*(edge(y0)+122)
					} else {
						x = edge(y0) - 2 + t*(380-edge(y0))
					}
					p = append(p, pt{x, y0 + 4*math.Sin(x/17+ph+math.Round(y0)/9)})
				}
				if rev {
					for a, z := 0, len(p)-1; a < z; a, z = a+1, z-1 {
						p[a], p[z] = p[z], p[a]
					}
				}
				return p
			}
			pts := append(line(s.y0, false), line(y1, true)...)
			fmt.Fprintf(&b, `<path fill="%s" stroke="%[1]s" stroke-width="1.5" d="M%.1f %.1f`, s.col, pts[0].x, pts[0].y)
			for _, p := range pts[1:] {
				fmt.Fprintf(&b, "L%.1f %.1f", p.x, p.y)
			}
			b.WriteString(`Z"/>`)
		}
	}
	half(left, true, 0)
	half(right, false, 1.3)
	b.WriteString(`<path fill="#FEDAA5" opacity=".85" d="M150 112 C175 104 200 112 230 100 L231 107 C200 120 176 112 151 119Z"/>`)
	return fmt.Sprintf(`<g transform="rotate(-30 %g %g)">%s</g>`, c.x, c.y, b.String())
}

func svg(small bool) string {
	r := rand.New(rand.NewSource(9))
	var m strings.Builder
	for _, d := range strokes(r, small) {
		fmt.Fprintf(&m, `<path fill="white" d="%s"/>`, d)
	}
	return fmt.Sprintf(`<svg xmlns="http://www.w3.org/2000/svg" width="256" height="256" viewBox="0 0 256 256">
<title>amnezia-admin</title>
<rect width="256" height="256" rx="52" fill="#1C1D21"/>
<mask id="m" style="mask-type:alpha" maskUnits="userSpaceOnUse" x="0" y="0" width="256" height="256">%s</mask>
<g mask="url(#m)">%s</g>
</svg>
`, m.String(), bands(pt{128, 134}))
}

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "использование: go run assets/gen.go svg|ico <каталог>")
		os.Exit(2)
	}
	dir := os.Args[2]
	switch os.Args[1] {
	case "svg":
		must(os.WriteFile(filepath.Join(dir, "logo.svg"), []byte(svg(false)), 0o644))
		must(os.WriteFile(filepath.Join(dir, "logo-small.svg"), []byte(svg(true)), 0o644))
	case "ico":
		ico(dir)
	default:
		fmt.Fprintln(os.Stderr, "неизвестная команда", os.Args[1])
		os.Exit(2)
	}
}

// ico — logo.ico с PNG-кадрами 16/32/48/256 (Windows Vista+).
func ico(dir string) {
	sizes := []int{16, 32, 48, 256}
	var pngs [][]byte
	for _, n := range sizes {
		b, err := os.ReadFile(filepath.Join(dir, fmt.Sprintf("logo-%d.png", n)))
		must(err)
		pngs = append(pngs, b)
	}
	var out bytes.Buffer
	must(binary.Write(&out, binary.LittleEndian, [3]uint16{0, 1, uint16(len(sizes))}))
	off := 6 + 16*len(sizes)
	for i, n := range sizes {
		w := uint8(n % 256) // 256 кодируется нулём
		out.Write([]byte{w, w, 0, 0})
		must(binary.Write(&out, binary.LittleEndian, [2]uint16{1, 32}))
		must(binary.Write(&out, binary.LittleEndian, [2]uint32{uint32(len(pngs[i])), uint32(off)}))
		off += len(pngs[i])
	}
	for _, p := range pngs {
		out.Write(p)
	}
	must(os.WriteFile(filepath.Join(dir, "logo.ico"), out.Bytes(), 0o644))
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}
