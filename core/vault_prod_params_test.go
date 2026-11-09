package core

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

// TestProdArgonParamsFloor — нижняя граница стоимости KDF для новых файлов
// .avlt/.aabk. Тесты cmd/cli и cmd/gui ставят лёгкие параметры ради скорости;
// без этого сторожа подмена боевых на лёгкие в продукте (в том числе через
// init()) прошла бы незамеченной (аудит TIMING-FLAKES-2, M1). Значение
// читается прямо в тесте — после всех init() пакета.
// Канарейки: подмена боевых параметров на {64, 1, 1} — прямо в vault.go и
// через init() в отдельном файле пакета.
func TestProdArgonParamsFloor(t *testing.T) {
	floor := ArgonParams{MemoryKiB: 512 * 1024, Time: 4, Threads: 4}
	p := ProdArgonParams
	if p.MemoryKiB < floor.MemoryKiB || p.Time < floor.Time || p.Threads < floor.Threads {
		t.Fatalf("боевые параметры Argon2 ослаблены: %+v, нижняя граница %+v", p, floor)
	}
}

// TestCoreTestsDoNotAssignProdArgon — тест пакета core, подменивший
// ProdArgonParams до TestProdArgonParamsFloor, обезвредил бы сторожа:
// подмены лёгкими параметрами допустимы только в других пакетах.
// Ловит присваивание всей переменной или поля и взятие адреса (&); граница —
// текстовый поиск: подмену через reflect или unsafe он не увидит.
func TestCoreTestsDoNotAssignProdArgon(t *testing.T) {
	files, err := filepath.Glob("*_test.go")
	if err != nil || len(files) == 0 {
		t.Fatalf("файлы тестов core не найдены (%v) — проверка не выполнилась бы", err)
	}
	assign := regexp.MustCompile(`ProdArgonParams\s*(\.\w+\s*)?=[^=]|&\s*ProdArgonParams\b`)
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("%s не прочитан: %v", f, err)
		}
		if assign.Match(b) {
			t.Errorf("%s присваивает ProdArgonParams или берёт его адрес — это обезвреживает TestProdArgonParamsFloor", f)
		}
	}
}
