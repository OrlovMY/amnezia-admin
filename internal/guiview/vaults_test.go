package guiview

import (
	"errors"
	"path/filepath"
	"testing"
)

// TestSavedKeyStatusTable — дословные тексты SavedKeyStatus, включая
// третье состояние «номер неизвестен» (список не прочитан или файла в нём
// нет). Доезд до окна — cmd/gui/a1b_test.go (TestA1bSavedKeyNumber*).
func TestSavedKeyStatusTable(t *testing.T) {
	dir := filepath.Join("x", "Настройки")
	a, b, c := filepath.Join(dir, "0a.avlt"), filepath.Join(dir, "5b.avlt"), filepath.Join(dir, "f0.avlt")
	const unknown = "Ключ сохранён. Под каким номером он в списке сохранённых — определить не удалось."
	cases := []struct {
		name   string
		vaults []string
		err    error
		saved  string
		want   string
	}{
		{"первый из трёх", []string{a, b, c}, nil, a, "Ключ сохранён (Сервер 1)."},
		{"в середине — позиция, а не число файлов", []string{a, b, c}, nil, b, "Ключ сохранён (Сервер 2)."},
		{"последний", []string{a, b, c}, nil, c, "Ключ сохранён (Сервер 3)."},
		{"список не прочитан", nil, errors.New("отказ"), b, unknown},
		{"файла в списке нет", []string{a, c}, nil, b, unknown},
		{"путь неизвестен", []string{a, b, c}, nil, "", unknown},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := SavedKeyStatus(tc.vaults, tc.err, tc.saved); got != tc.want {
				t.Errorf("SavedKeyStatus = %q, want %q", got, tc.want)
			}
		})
	}
}
