package core

import "testing"

// prodArgonAtInit — ProdArgonParams, снятые при инициализации пакета, до
// того как тесты подменят их лёгкими (backup_test, migrate_test и др. ставят
// дешёвый KDF ради скорости). Сверяется именно этот снимок: значение во время
// теста может быть уже подменено соседним тестом.
var prodArgonAtInit = ProdArgonParams

// TestProdArgonParamsFloor — нижняя граница стоимости KDF для новых файлов
// .avlt/.aabk. Пять тестов ставят лёгкие параметры; без этого сторожа подмена
// боевых на лёгкие в продукте прошла бы незамеченной (аудит TIMING-FLAKES-2, M1).
// Канарейка: ProdArgonParams = {64, 1, 1} обязана ронять тест.
func TestProdArgonParamsFloor(t *testing.T) {
	floor := ArgonParams{MemoryKiB: 512 * 1024, Time: 4, Threads: 4}
	p := prodArgonAtInit
	if p.MemoryKiB < floor.MemoryKiB || p.Time < floor.Time || p.Threads < floor.Threads {
		t.Fatalf("боевые параметры Argon2 ослаблены: %+v, нижняя граница %+v", p, floor)
	}
}
