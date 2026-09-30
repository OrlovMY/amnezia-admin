// Package testpath — сравнение путей для тестов, которые трогают каталоги
// рядом с тестовым бинарником: такой тест обязан работать ТОЛЬКО во
// временном каталоге ОС. Вынесено из cmd/gui/a1b_test.go (A1б), чтобы
// cmd/cli сравнивал пути тем же способом (ревью QA долгов, 30.09.2026):
// строковое сравнение через filepath.Clean не видит символьных ссылок
// (/var → /private/var на macOS) и коротких имён Windows (RUNNER~1).
package testpath

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// Canon — абсолютный путь с раскрытыми символьными ссылками. Хвост, которого
// ещё нет на диске, приклеивается к раскрытому существующему предку.
func Canon(p string) string {
	p, err := filepath.Abs(p)
	if err != nil {
		return filepath.Clean(p)
	}
	var tail []string
	for cur := p; ; {
		if r, err := filepath.EvalSymlinks(cur); err == nil {
			return filepath.Join(append([]string{r}, tail...)...)
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return p
		}
		tail = append([]string{filepath.Base(cur)}, tail...)
		cur = parent
	}
}

// InsideTempDir — лежит ли p внутри временного каталога ОС. Обе стороны —
// через Canon; сравнение по частям пути через filepath.Rel, на Windows без
// учёта регистра.
func InsideTempDir(p string) bool {
	tmp, cp := Canon(os.TempDir()), Canon(p)
	if runtime.GOOS == "windows" {
		tmp, cp = strings.ToLower(tmp), strings.ToLower(cp)
	}
	rel, err := filepath.Rel(tmp, cp)
	return err == nil && rel != "." && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}
