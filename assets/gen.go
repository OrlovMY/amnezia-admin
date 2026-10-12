//go:build ignore

// Генератор знака amnezia-admin: две буквы «A» с общей средней ногой и
// общей перекладиной («ΛΛ» + черта). Один источник геометрии на SVG и
// растры, чтобы они не разошлись. Запуск из корня репозитория:
//
//	go run assets/gen.go
//
// Пишет assets/logo.svg, assets/logo-{16,32,48,256}.png, assets/logo.ico.
// Значок exe cmd/gui/rsrc_windows_amd64.syso собирается из assets/logo.ico:
//
//	go run github.com/tc-hib/go-winres@v0.3.3 simply --arch amd64 --manifest none \
//	    --icon assets/logo.ico --out cmd/gui/rsrc
//
// (.syso лежит в репозитории, поэтому обычный `go build ./cmd/gui` под
// windows/amd64 подхватывает его сам, без внешних шагов в CI.)
package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"math"
	"os"
)

const (
	bgHex  = "#1C1D21" // тёмный фон (гамма Amnezia)
	fgHex  = "#FBB26A" // тёплый персиковый акцент (гамма Amnezia)
	radius = 52.0      // скругление фона, единицы 256
	stroke = 30.0      // толщина линий, единицы 256
)

var (
	bg = color.NRGBA{0x1C, 0x1D, 0x21, 0xFF}
	fg = color.NRGBA{0xFB, 0xB2, 0x6A, 0xFF}
	// Ломаная «ΛΛ»: левая и правая A делят среднюю ногу.
	poly = [][2]float64{{36, 204}, {82, 56}, {128, 204}, {174, 56}, {220, 204}}
	// Общая перекладина через обе буквы.
	bar = [2][2]float64{{62, 154}, {194, 154}}
)

func segDist(px, py float64, a, b [2]float64) float64 {
	dx, dy := b[0]-a[0], b[1]-a[1]
	t := ((px-a[0])*dx + (py-a[1])*dy) / (dx*dx + dy*dy)
	t = math.Max(0, math.Min(1, t))
	return math.Hypot(px-(a[0]+t*dx), py-(a[1]+t*dy))
}

func inGlyph(x, y float64) bool {
	for i := 0; i+1 < len(poly); i++ {
		if segDist(x, y, poly[i], poly[i+1]) <= stroke/2 {
			return true
		}
	}
	return segDist(x, y, bar[0], bar[1]) <= stroke/2
}

func inBg(x, y float64) bool {
	cx := math.Max(radius, math.Min(256-radius, x))
	cy := math.Max(radius, math.Min(256-radius, y))
	return math.Hypot(x-cx, y-cy) <= radius
}

func render(n int) *image.NRGBA {
	img := image.NewNRGBA(image.Rect(0, 0, n, n))
	const ss = 8
	s := 256.0 / float64(n)
	for py := 0; py < n; py++ {
		for px := 0; px < n; px++ {
			var a, r, g, b float64
			for j := 0; j < ss; j++ {
				for i := 0; i < ss; i++ {
					x := (float64(px) + (float64(i)+0.5)/ss) * s
					y := (float64(py) + (float64(j)+0.5)/ss) * s
					if !inBg(x, y) {
						continue
					}
					c := bg
					if inGlyph(x, y) {
						c = fg
					}
					a++
					r += float64(c.R)
					g += float64(c.G)
					b += float64(c.B)
				}
			}
			if a == 0 {
				continue
			}
			img.SetNRGBA(px, py, color.NRGBA{uint8(r / a), uint8(g / a), uint8(b / a), uint8(a * 255 / (ss * ss))})
		}
	}
	return img
}

func svg() string {
	var pts string
	for i, p := range poly {
		if i > 0 {
			pts += " "
		}
		pts += fmt.Sprintf("%g,%g", p[0], p[1])
	}
	return fmt.Sprintf(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 256 256" width="256" height="256">
  <title>amnezia-admin</title>
  <rect width="256" height="256" rx="%g" fill="%s"/>
  <g fill="none" stroke="%s" stroke-width="%g" stroke-linecap="round" stroke-linejoin="round">
    <polyline points="%s"/>
    <line x1="%g" y1="%g" x2="%g" y2="%g"/>
  </g>
</svg>
`, radius, bgHex, fgHex, stroke, pts, bar[0][0], bar[0][1], bar[1][0], bar[1][1])
}

func main() {
	sizes := []int{16, 32, 48, 256}
	var pngs [][]byte
	for _, n := range sizes {
		var buf bytes.Buffer
		must(png.Encode(&buf, render(n)))
		pngs = append(pngs, buf.Bytes())
		must(os.WriteFile(fmt.Sprintf("assets/logo-%d.png", n), buf.Bytes(), 0o644))
	}
	must(os.WriteFile("assets/logo.svg", []byte(svg()), 0o644))
	// ICO с PNG-кадрами (Windows Vista+).
	var ico bytes.Buffer
	must(binary.Write(&ico, binary.LittleEndian, [3]uint16{0, 1, uint16(len(sizes))}))
	off := 6 + 16*len(sizes)
	for i, n := range sizes {
		w := uint8(n % 256) // 256 кодируется нулём
		ico.Write([]byte{w, w, 0, 0})
		must(binary.Write(&ico, binary.LittleEndian, [2]uint16{1, 32}))
		must(binary.Write(&ico, binary.LittleEndian, [2]uint32{uint32(len(pngs[i])), uint32(off)}))
		off += len(pngs[i])
	}
	for _, p := range pngs {
		ico.Write(p)
	}
	must(os.WriteFile("assets/logo.ico", ico.Bytes(), 0o644))
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}
