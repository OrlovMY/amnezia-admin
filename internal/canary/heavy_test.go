package canary

import (
	"runtime"
	"testing"
)

// heavySlots ограничивает число одновременных полных прогонов Run.
// Прогон — это настоящая программа (собранный cmd/cli) против своего
// fakesrv с собственным портом и каталогами; общих переменных пакета он не
// меняет. Но внутри есть окна по времени (барьер LegacyPairWait К4,
// CommandDelay), и без предела десяток прогонов на 2–4 ядрах CI мог бы их
// растянуть. Поэтому — не больше половины ядер, от 2 до 4.
var heavySlots = make(chan struct{}, heavyLimit())

func heavyLimit() int {
	n := runtime.NumCPU() / 2
	if n < 2 {
		n = 2
	}
	if n > 4 {
		n = 4
	}
	return n
}

// heavy — тест (или подтест) с полным прогоном Run идёт параллельно с
// такими же, под пределом heavySlots. Вызывать ТОЛЬКО в тестах, которые не
// меняют переменных пакета (ageCheck, sudoKeyMaker, k5Deadline): их меняют
// последовательные тесты, и параллельные стартуют лишь после них.
// Для родителя с параллельными подтестами — t.Parallel без слота, иначе
// родитель держал бы слот, дожидаясь подтестов.
func heavy(t *testing.T) {
	t.Helper()
	t.Parallel()
	heavySlots <- struct{}{}
	t.Cleanup(func() { <-heavySlots })
}
