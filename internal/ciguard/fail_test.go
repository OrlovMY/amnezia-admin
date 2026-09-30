// Файл fail_test.go — единственная точка, через которую сторожа пакета
// сообщают о провале.
//
// Зачем метка (ревью QA-01, раунд 2). Канарейка (plant_test.go) раньше
// искала ожидаемую фразу во ВСЁМ выводе -test.v, куда попадает и текст
// t.Logf. Сторож, у которого Errorf подменён на Logf, печатал ту же фразу,
// падал строкой ниже по чужой причине (индекс −1), и канарейка оставалась
// зелёной. Теперь провал печатается с меткой «ПРОВАЛ:», и канарейка ищет
// фразу только в блоках с меткой. Подмена Errorf на Logf здесь, в
// помощнике, роняет все подсадки разом — её нельзя не увидеть.
package ciguard

import "testing"

const failMark = "ПРОВАЛ: "

func fail(t *testing.T, format string, args ...any) {
	t.Helper()
	t.Errorf(failMark+format, args...)
}

func fatal(t *testing.T, format string, args ...any) {
	t.Helper()
	t.Fatalf(failMark+format, args...)
}
