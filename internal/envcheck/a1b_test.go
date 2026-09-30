package envcheck

import (
	"bytes"
	"strings"
	"testing"
)

// A1б — ТЕСТ ДОЕЗДА долга A1-II: «библиотеку C определить не удалось» и
// «не хватает libGL.so.1» приходят из подставной ОС тем же путём, что в бою
// (detect → Report), и совет о пакетах НЕ утверждает Debian/Fedora.
//
// Тест различения — вторая строка таблицы TestMissingHardBeatsUnknownLibc
// (envcheck_test.go): тот же вход с опознанной glibc даёт прежний совет.
//
// На f0febbd этот тест падает: вывод содержал «Установите их: Debian/Ubuntu»
// без единого слова о том, что система может быть Alpine.
func TestA1bUnknownLibcAdviceArrives(t *testing.T) {
	ldconfig := ldconfigOut(without("libGL.so.1")...)
	cases := []struct {
		name string
		out  map[string]string
	}{
		{"getconf и ldd отсутствуют", map[string]string{"ldconfig -p": ldconfig}},
		{"ldd --version дал нераспознанный вывод", map[string]string{
			"ldd --version": "some other tool 1.2.3\n", "ldconfig -p": ldconfig}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := &fakeOS{out: c.out}
			r := detect(f.deps(), "linux", "amd64", env(map[string]string{"DISPLAY": ":0"}))
			if r.Libc.Kind != "" {
				t.Fatalf("тест перестал что-либо проверять: libc опознана как %+v", r.Libc)
			}
			if !r.Graph.Known || strings.Join(r.Graph.MissingHard, ",") != "libGL.so.1" {
				t.Fatalf("тест перестал что-либо проверять: Graph = %+v", r.Graph)
			}
			var b bytes.Buffer
			Report(r, &b)
			out := b.String()
			if !strings.Contains(out, "Библиотека C: определить не удалось\n") {
				t.Fatalf("строка признака потеряна:\n%s", out)
			}
			if !strings.Contains(out, "Alpine — графическая версия там не работает вовсе") {
				t.Errorf("при неопознанной libc совет не называет развилку Alpine — "+
					"«не знаем, какая система» звучит как «Debian»:\n%s", out)
			}
			if strings.Contains(out, "libGL.so.1. Установите их:") {
				t.Errorf("при неопознанной libc напечатан безусловный совет glibc-систем:\n%s", out)
			}
			if !strings.Contains(out, "Графический интерфейс не запустится") {
				t.Errorf("приговор «не запустится» при нехватке жёсткой зависимости потерян:\n%s", out)
			}
		})
	}
}
