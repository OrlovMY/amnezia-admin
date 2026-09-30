package core

// Долг Н8 (ДОЛГИ-ПРОДУКТ, 30.09.2026): счётчик неверных пинов.

import (
	"os"
	"path/filepath"
	"testing"
)

// TestDebtsSaveThrottleCorruptNotOverwritten — ТЕСТ РАЗЛИЧЕНИЯ, компилируется
// на c65420e (сигнатура SaveThrottle прежняя) и падает там поведением:
// прежде битый throttle.json молча заменялся картой из одной записи —
// счётчики остальных хранилищ обнулялись, а вызывающий получал nil.
func TestDebtsSaveThrottleCorruptNotOverwritten(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "throttle.json")
	if err := os.WriteFile(path, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := SaveThrottle(dir, "a.avlt", ThrottleState{Fails: 1})
	if err == nil {
		t.Fatal("SaveThrottle поверх повреждённого throttle.json вернул nil — " +
			"«не удалось» выдано за «сохранено»")
	}
	got, _ := os.ReadFile(path)
	if string(got) != "{" {
		t.Fatalf("повреждённый throttle.json молча перезаписан: %q", got)
	}
}

// TestDebtsLoadThrottleThreeStates — табличный случай: «файла нет» (ноль,
// штатно) ≠ «файл не читается» ≠ «файл повреждён». Не компилируется на
// c65420e: там у LoadThrottle не было возврата ошибки — третье состояние
// сигнатура не выражала, и чинить пришлось в ней (CLAUDE.md).
func TestDebtsLoadThrottleThreeStates(t *testing.T) {
	cases := []struct {
		name    string
		prep    func(path string)
		wantErr bool
	}{
		{"файла нет — ноль попыток", func(string) {}, false},
		{"повреждён", func(p string) { os.WriteFile(p, []byte("{"), 0o600) }, true},
		{"не читается (на месте файла каталог)", func(p string) { os.Mkdir(p, 0o700) }, true},
		{"null — пустая карта", func(p string) { os.WriteFile(p, []byte("null"), 0o600) }, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			c.prep(filepath.Join(dir, "throttle.json"))
			st, err := LoadThrottle(dir, "a.avlt")
			if (err != nil) != c.wantErr {
				t.Fatalf("err = %v, ожидалась ошибка: %v", err, c.wantErr)
			}
			if st != (ThrottleState{}) {
				t.Fatalf("состояние %+v, ожидался ноль", st)
			}
		})
	}
}
