package envcheck

import (
	"bytes"
	"runtime"
	"strings"
	"testing"
)

// wantNonLinux — итог check для Windows и macOS (A1б, Р2; редакция UI-01,
// РЕВЬЮ-A1Б-UX.md).
const wantNonLinux = "Для Windows и macOS проверять нечего: графической версии не нужны дополнительные библиотеки, она должна запуститься. Если не откроется — пользуйтесь консольной версией."

// TestA1bNonLinuxNoPromiseDiffers — ТЕСТ РАЗЛИЧЕНИЯ (У4): «проверили, всё на
// месте» (Linux) и «проверять было нечего» (Windows, macOS) — разные итоги.
// На f0febbd оба печатали «Графический интерфейс запустится.».
func TestA1bNonLinuxNoPromiseDiffers(t *testing.T) {
	linux := verdict(Result{GOOS: "linux", GOARCH: "amd64", Libc: Libc{Kind: "glibc", Version: "2.36"},
		Graph: Graphics{Known: true}, Sess: SessionX11})
	if linux != "Графический интерфейс запустится." {
		t.Fatalf("Linux с полной проверкой: %q — тест перестал что-либо проверять", linux)
	}
	for _, p := range [][2]string{{"windows", "amd64"}, {"darwin", "arm64"}} {
		got := verdict(Result{GOOS: p[0], GOARCH: p[1]})
		if got == linux {
			t.Errorf("%s/%s: итог %q — тот же, что после полной проверки на Linux, хотя не проверялось ничего", p[0], p[1], got)
		}
		if got != wantNonLinux {
			t.Errorf("%s/%s: итог %q, хочу %q", p[0], p[1], got, wantNonLinux)
		}
	}
}

// TestA1bNonLinuxNoPromiseArrives — ТЕСТ ДОЕЗДА: выбор ОС боевым путём
// detect → Report. ОС подставлена параметром detect — без запуска на другой
// ОС иначе нельзя. На настоящих Windows/macOS (CI) вторая половина теста
// проходит тот же путь через Detect(OSDeps()) без подстановки.
func TestA1bNonLinuxNoPromiseArrives(t *testing.T) {
	for _, p := range [][2]string{{"windows", "amd64"}, {"darwin", "arm64"}} {
		f := &fakeOS{}
		var b bytes.Buffer
		Report(detect(f.deps(), p[0], p[1], env(nil)), &b)
		out := b.String()
		if strings.Contains(out, "Графический интерфейс запустится.") {
			t.Errorf("%s/%s: check обещает запуск, ничего не проверив:\n%s", p[0], p[1], out)
		}
		if !strings.HasSuffix(out, wantNonLinux+"\n") {
			t.Errorf("%s/%s: последняя строка не та:\n%s", p[0], p[1], out)
		}
	}
	g, a := runtime.GOOS, runtime.GOARCH
	if (g == "windows" && a == "amd64") || (g == "darwin" && a == "arm64") {
		var b bytes.Buffer
		Report(Detect(OSDeps()), &b)
		if !strings.HasSuffix(b.String(), wantNonLinux+"\n") {
			t.Errorf("настоящая ОС %s/%s: вывод check:\n%s", g, a, b.String())
		}
	}
}
