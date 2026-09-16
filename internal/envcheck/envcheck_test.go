// Табличные тесты пакета envcheck.
//
// ИСТОЧНИК ОБРАЗЦОВ. Реальные выводы `getconf GNU_LIBC_VERSION`,
// `ldd --version` и `ldconfig -p` с машины владельца на момент написания
// тестов не предъявлены (файл envcheck-samples.txt отсутствует). Поэтому
// КАЖДЫЙ образец ниже помечен одним из двух:
//
//	«по памяти — не доказательство, источник: память модели» — образец
//	    написан по памяти и подлежит сверке с реальным выводом (пункт
//	    приёмки К задания);
//
// Страховка на это время — случаи «нераспознанный вывод»: любой вывод,
// который разбор не узнал, обязан давать «определить не удалось», а не
// ложное «нет». Если образец окажется неверным, поведение выродится в
// честное «определить не удалось», а не в неверный совет пользователю.
package envcheck

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"
)

// --- Вспомогательное: подставные зависимости ---------------------------

type fakeOS struct {
	out   map[string]string // "getconf GNU_LIBC_VERSION" -> stdout (наличие ключа = команда есть)
	files map[string]bool
	calls []string
}

func (f *fakeOS) deps() Deps {
	return Deps{
		Run: func(name string, args ...string) (string, error) {
			key := strings.TrimSpace(name + " " + strings.Join(args, " "))
			f.calls = append(f.calls, key)
			if out, ok := f.out[key]; ok {
				return out, nil
			}
			return "", errors.New("команда не найдена: " + key)
		},
		Exists: func(path string) bool { return f.files[path] },
	}
}

func (f *fakeOS) called(key string) bool {
	for _, c := range f.calls {
		if c == key {
			return true
		}
	}
	return false
}

func env(pairs map[string]string) func(string) string {
	return func(k string) string { return pairs[k] }
}

// allLibs — фактический состав зависимостей релизного GUI, снятый с бинаря
// amnezia-admin-gui-linux-amd64 версии v0.1.0 разбором ELF (DT_NEEDED) и
// поиском имён в теле бинаря. Это ДОКАЗАТЕЛЬСТВО, а не память модели.
// libm.so.6 и libc.so.6 сюда не входят: они покрыты признаком «библиотека C»
// и отдельно не проверяются.
var allLibs = []string{
	// жёсткие зависимости (DT_NEEDED)
	"libGL.so.1", "libX11.so.6",
	// подгружаются на ходу (dlopen)
	"libEGL.so.1", "libXcursor.so.1", "libXi.so.6", "libXinerama.so.1",
	"libXrandr.so.2", "libXxf86vm.so.1", "libXrender.so.1",
}

// without — allLibs без перечисленных имён.
func without(absent ...string) []string {
	var present []string
	for _, l := range allLibs {
		skip := false
		for _, a := range absent {
			if a == l {
				skip = true
			}
		}
		if !skip {
			present = append(present, l)
		}
	}
	return present
}

// ldconfigOut — образец вывода `ldconfig -p`.
// ПО ПАМЯТИ — НЕ ДОКАЗАТЕЛЬСТВО, источник: память модели.
func ldconfigOut(libs ...string) string {
	var b strings.Builder
	b.WriteString("1462 libs found in cache `/etc/ld.so.cache'\n")
	for _, l := range libs {
		fmt.Fprintf(&b, "\t%s (libc6,x86-64) => /usr/lib/x86_64-linux-gnu/%s\n", l, l)
	}
	return b.String()
}

// linuxAllGood — заготовка «здоровый Debian»: всё на месте.
func linuxAllGood() *fakeOS {
	return &fakeOS{
		out: map[string]string{
			"getconf GNU_LIBC_VERSION": "glibc 2.36\n",
			"ldconfig -p":              ldconfigOut(allLibs...),
			// ПО ПАМЯТИ — НЕ ДОКАЗАТЕЛЬСТВО, источник: память модели.
			"cat /etc/os-release": "PRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\nNAME=\"Debian GNU/Linux\"\nID=debian\n",
		},
		files: map[string]bool{},
	}
}

// --- Библиотека C -------------------------------------------------------

// TestLibcFromLdd: разбор версии glibc не завязан на один дистрибутив.
// Три первые строки `ldd --version` — ПО ПАМЯТИ, НЕ ДОКАЗАТЕЛЬСТВО,
// источник: память модели.
func TestLibcFromLdd(t *testing.T) {
	cases := []struct {
		name string
		out  string
		want string
	}{
		{"debian", "ldd (Ubuntu GLIBC 2.35-0ubuntu3.8) 2.35\nCopyright (C) 2022 Free Software Foundation, Inc.\n", "2.35"},
		{"fedora", "ldd (GNU libc) 2.39\nCopyright (C) 2024 Free Software Foundation, Inc.\n", "2.39"},
		{"arch", "ldd (GNU libc) 2.41\nCopyright (C) 2025 Free Software Foundation, Inc.\n", "2.41"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := &fakeOS{out: map[string]string{
				"ldd --version": c.out,
				"ldconfig -p":   ldconfigOut(allLibs...),
			}}
			r := detect(f.deps(), "linux", "amd64", env(map[string]string{"DISPLAY": ":0"}))
			if r.Libc.Kind != "glibc" || r.Libc.Version != c.want {
				t.Fatalf("Libc = %+v, хочу glibc %s", r.Libc, c.want)
			}
		})
	}
}

// TestGetconfWins: способ 1 имеет приоритет, ldd не вызывается.
func TestGetconfWins(t *testing.T) {
	f := &fakeOS{out: map[string]string{
		"getconf GNU_LIBC_VERSION": "glibc 2.39\n",
		"ldd --version":            "ldd (GNU libc) 9.99\n",
		"ldconfig -p":              ldconfigOut(allLibs...),
	}}
	r := detect(f.deps(), "linux", "amd64", env(nil))
	if r.Libc.Kind != "glibc" || r.Libc.Version != "2.39" {
		t.Fatalf("Libc = %+v, хочу glibc 2.39", r.Libc)
	}
	if f.called("ldd --version") {
		t.Errorf("ldd --version вызван, хотя getconf дал ответ: %v", f.calls)
	}
}

// TestGetconfMissingFallbackLdd: переход на способ 2.
func TestGetconfMissingFallbackLdd(t *testing.T) {
	f := &fakeOS{out: map[string]string{
		"ldd --version": "ldd (GNU libc) 2.39\n",
		"ldconfig -p":   ldconfigOut(allLibs...),
	}}
	r := detect(f.deps(), "linux", "amd64", env(nil))
	if r.Libc.Kind != "glibc" || r.Libc.Version != "2.39" {
		t.Fatalf("Libc = %+v, хочу glibc 2.39", r.Libc)
	}
}

// TestLibcBothCommandsMissing: обе команды отсутствуют, musl-файлов нет →
// «определить не удалось» и итог «Проверить не удалось: …», а НЕ «musl» и
// НЕ «не запустится». Ключевой случай правила Г4.
func TestLibcBothCommandsMissing(t *testing.T) {
	f := &fakeOS{out: map[string]string{"ldconfig -p": ldconfigOut(allLibs...)}}
	r := detect(f.deps(), "linux", "amd64", env(map[string]string{"DISPLAY": ":0"}))
	if r.Libc.Kind != "" {
		t.Fatalf("Libc.Kind = %q, хочу «определить не удалось» (пустую)", r.Libc.Kind)
	}
	if got := verdict(r); !strings.HasPrefix(got, "Проверить не удалось:") {
		t.Fatalf("итог = %q, хочу «Проверить не удалось: …»", got)
	}
}

// TestLibcLddWithoutVersion (правка № 4): `ldd --version` вернул строку без
// номера версии, getconf отсутствует → «определить не удалось», НЕ musl.
// Это и есть страховка от неверного образца.
func TestLibcLddWithoutVersion(t *testing.T) {
	f := &fakeOS{out: map[string]string{
		"ldd --version": "some other tool\n",
		"ldconfig -p":   ldconfigOut(allLibs...),
	}}
	r := detect(f.deps(), "linux", "amd64", env(map[string]string{"DISPLAY": ":0"}))
	if r.Libc.Kind != "" {
		t.Fatalf("Libc.Kind = %q, хочу «определить не удалось»", r.Libc.Kind)
	}
	if got := verdict(r); !strings.HasPrefix(got, "Проверить не удалось:") {
		t.Fatalf("итог = %q, хочу «Проверить не удалось: …»", got)
	}
}

// TestMusl: обеих команд нет, есть загрузчик musl (x86_64 и aarch64).
// Имена файлов — ПО ПАМЯТИ, НЕ ДОКАЗАТЕЛЬСТВО, источник: память модели.
func TestMusl(t *testing.T) {
	for _, p := range []string{"/lib/ld-musl-x86_64.so.1", "/lib/ld-musl-aarch64.so.1"} {
		t.Run(p, func(t *testing.T) {
			f := &fakeOS{files: map[string]bool{p: true}}
			r := detect(f.deps(), "linux", "amd64", env(nil))
			if r.Libc.Kind != "musl" {
				t.Fatalf("Libc.Kind = %q, хочу musl", r.Libc.Kind)
			}
			if got := verdict(r); got != textMusl {
				t.Fatalf("итог = %q, хочу %q", got, textMusl)
			}
		})
	}
}

// --- Библиотеки графики -------------------------------------------------

// TestGraphicsAllPresent: ldconfig -p со всем фактическим составом →
// «все на месте».
func TestGraphicsAllPresent(t *testing.T) {
	f := linuxAllGood()
	r := detect(f.deps(), "linux", "amd64", env(map[string]string{"DISPLAY": ":0"}))
	if !r.Graph.Known || len(r.Graph.MissingHard) != 0 || len(r.Graph.MissingDlopen) != 0 {
		t.Fatalf("Graph = %+v, хочу «все на месте»", r.Graph)
	}
	if got := verdict(r); got != textWillRun {
		t.Fatalf("итог = %q, хочу %q", got, textWillRun)
	}
}

// TestGraphicsMissing: списки — только отсутствующие, в порядке таблицы, и
// разложены по классам: жёсткая зависимость (без неё процесс не стартует)
// отдельно от подгружаемых на ходу.
func TestGraphicsMissing(t *testing.T) {
	cases := []struct {
		name       string
		absent     []string
		wantHard   []string
		wantDlopen []string
	}{
		{"без libGL", []string{"libGL.so.1"}, []string{"libGL.so.1"}, nil},
		{"без libXi и libXinerama", []string{"libXi.so.6", "libXinerama.so.1"}, nil, []string{"libXi.so.6", "libXinerama.so.1"}},
		{"без libX11 и libXrender", []string{"libX11.so.6", "libXrender.so.1"}, []string{"libX11.so.6"}, []string{"libXrender.so.1"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := &fakeOS{out: map[string]string{
				"getconf GNU_LIBC_VERSION": "glibc 2.36\n",
				"ldconfig -p":              ldconfigOut(without(c.absent...)...),
			}}
			r := detect(f.deps(), "linux", "amd64", env(map[string]string{"DISPLAY": ":0"}))
			if !r.Graph.Known {
				t.Fatalf("Graph.Known = false, хотя ldconfig отработал: %+v", r.Graph)
			}
			if strings.Join(r.Graph.MissingHard, ",") != strings.Join(c.wantHard, ",") {
				t.Errorf("MissingHard = %v, хочу %v", r.Graph.MissingHard, c.wantHard)
			}
			if strings.Join(r.Graph.MissingDlopen, ",") != strings.Join(c.wantDlopen, ",") {
				t.Errorf("MissingDlopen = %v, хочу %v", r.Graph.MissingDlopen, c.wantDlopen)
			}
		})
	}
}

// TestDlopenLibMissing: нет libXrandr.so.2 — библиотеки, которую GUI
// подгружает на ходу. Прежний список из шести имён её не знал и уверенно
// говорил «Графический интерфейс запустится.» машине, где GUI может упасть.
func TestDlopenLibMissing(t *testing.T) {
	f := &fakeOS{out: map[string]string{
		"getconf GNU_LIBC_VERSION": "glibc 2.36\n",
		"ldconfig -p":              ldconfigOut(without("libXrandr.so.2")...),
	}}
	r := detect(f.deps(), "linux", "amd64", env(map[string]string{"DISPLAY": ":0"}))
	want := "Графический интерфейс может не запуститься: обязательные библиотеки на месте, но не хватает — libXrandr.so.2. Установите их: Debian/Ubuntu — `libxrandr2`; Fedora — `libXrandr`."
	if got := verdict(r); got != want {
		t.Fatalf("итог = %q, хочу %q", got, want)
	}
}

// TestHardLibMissing: нет libGL.so.1 — жёсткой зависимости из DT_NEEDED. Без
// неё процесс не стартует вообще, итог отрицательный и уверенный.
func TestHardLibMissing(t *testing.T) {
	f := &fakeOS{out: map[string]string{
		"getconf GNU_LIBC_VERSION": "glibc 2.36\n",
		"ldconfig -p":              ldconfigOut(without("libGL.so.1")...),
	}}
	r := detect(f.deps(), "linux", "amd64", env(map[string]string{"DISPLAY": ":0"}))
	want := "Графический интерфейс не запустится: не хватает библиотек — libGL.so.1. Установите их: Debian/Ubuntu — `libgl1`; Fedora — `mesa-libGL`."
	if got := verdict(r); got != want {
		t.Fatalf("итог = %q, хочу %q", got, want)
	}
}

// TestLibcLibsNotChecked: libc.so.6 и libm.so.6 — тоже жёсткие зависимости
// GUI, но отдельно не проверяются и в вывод не попадают: их наличие уже
// определяется признаком «библиотека C».
func TestLibcLibsNotChecked(t *testing.T) {
	f := linuxAllGood() // в ldconfig-выводе нет ни libc.so.6, ни libm.so.6
	r := detect(f.deps(), "linux", "amd64", env(map[string]string{"DISPLAY": ":0"}))
	if got := verdict(r); got != textWillRun {
		t.Fatalf("итог = %q, хочу %q", got, textWillRun)
	}
	var b bytes.Buffer
	Report(r, &b)
	for _, name := range []string{"libc.so.6", "libm.so.6"} {
		if strings.Contains(b.String(), name) {
			t.Errorf("%s попал в вывод:\n%s", name, b.String())
		}
	}
}

// TestGraphicsLdconfigEmptyFallsBackToFiles (П5): пустой вывод ldconfig —
// неудача способа 1; итог определяется ТОЛЬКО способом 2, и пустой ldconfig
// сам по себе «нет» не даёт никогда.
func TestGraphicsLdconfigEmptyFallsBackToFiles(t *testing.T) {
	files := map[string]bool{"/usr/lib/x86_64-linux-gnu": true}
	for _, l := range allLibs {
		files["/usr/lib/x86_64-linux-gnu/"+l] = true
	}
	f := &fakeOS{
		out:   map[string]string{"getconf GNU_LIBC_VERSION": "glibc 2.36\n", "ldconfig -p": ""},
		files: files,
	}
	r := detect(f.deps(), "linux", "amd64", env(map[string]string{"DISPLAY": ":0"}))
	if !r.Graph.Known || len(r.Graph.MissingHard) != 0 || len(r.Graph.MissingDlopen) != 0 {
		t.Fatalf("Graph = %+v, хочу «все на месте» по файлам", r.Graph)
	}
}

// TestGraphicsLdconfigGarbageNoDirs (правка № 4): ldconfig вернул код 0 и
// текст без строк формата «имя.so.N … => /путь», ни один каталог не
// существует → «определить не удалось», а НЕ «не хватает всех шести».
func TestGraphicsLdconfigGarbageNoDirs(t *testing.T) {
	f := &fakeOS{out: map[string]string{
		"getconf GNU_LIBC_VERSION": "glibc 2.36\n",
		"ldconfig -p":              "usage: ldconfig [OPTION...]\n",
	}}
	r := detect(f.deps(), "linux", "amd64", env(map[string]string{"DISPLAY": ":0"}))
	if r.Graph.Known {
		t.Fatalf("Graph = %+v, хочу «определить не удалось»", r.Graph)
	}
	if got := verdict(r); !strings.HasPrefix(got, "Проверить не удалось:") {
		t.Fatalf("итог = %q, хочу «Проверить не удалось: …»", got)
	}
}

// TestGraphicsByFiles: ldconfig отсутствует, библиотеки найдены файлами —
// Fedora (/usr/lib64) и Debian (/usr/lib/x86_64-linux-gnu).
// Раскладки каталогов — ПО ПАМЯТИ, НЕ ДОКАЗАТЕЛЬСТВО, источник: память модели.
func TestGraphicsByFiles(t *testing.T) {
	cases := []struct{ name, dir string }{
		{"fedora", "/usr/lib64"},
		{"debian", "/usr/lib/x86_64-linux-gnu"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			files := map[string]bool{c.dir: true}
			for _, l := range allLibs {
				files[c.dir+"/"+l] = true
			}
			f := &fakeOS{
				out:   map[string]string{"getconf GNU_LIBC_VERSION": "glibc 2.39\n"},
				files: files,
			}
			r := detect(f.deps(), "linux", "amd64", env(map[string]string{"DISPLAY": ":0"}))
			if !r.Graph.Known || len(r.Graph.MissingHard) != 0 || len(r.Graph.MissingDlopen) != 0 {
				t.Fatalf("Graph = %+v, хочу «все на месте»", r.Graph)
			}
		})
	}
}

// TestGraphicsNoLdconfigNoDirs: ldconfig отсутствует и ни один путь не
// существует → «определить не удалось», а НЕ «не хватает всех шести».
func TestGraphicsNoLdconfigNoDirs(t *testing.T) {
	f := &fakeOS{out: map[string]string{"getconf GNU_LIBC_VERSION": "glibc 2.39\n"}}
	r := detect(f.deps(), "linux", "amd64", env(map[string]string{"DISPLAY": ":0"}))
	if r.Graph.Known {
		t.Fatalf("Graph = %+v, хочу «определить не удалось»", r.Graph)
	}
}

// --- Графическая сессия -------------------------------------------------

func TestSession(t *testing.T) {
	cases := []struct {
		name string
		envs map[string]string
		want Session
	}{
		{"x11", map[string]string{"DISPLAY": ":0"}, SessionX11},
		{"wayland", map[string]string{"WAYLAND_DISPLAY": "wayland-0"}, SessionWayland},
		{"обе пустые", map[string]string{}, SessionNone},
		{"обе заданы", map[string]string{"DISPLAY": ":0", "WAYLAND_DISPLAY": "wayland-0"}, SessionX11},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := linuxAllGood()
			r := detect(f.deps(), "linux", "amd64", env(c.envs))
			if r.Sess != c.want {
				t.Fatalf("Sess = %v, хочу %v", r.Sess, c.want)
			}
		})
	}
}

// --- Приоритет итогов ---------------------------------------------------

// TestMuslBeatsMissingLibs: musl и нехватка библиотек одновременно →
// печатается про Alpine (на Alpine ставить libgl1 бесполезно).
func TestMuslBeatsMissingLibs(t *testing.T) {
	f := &fakeOS{
		out:   map[string]string{"ldconfig -p": ldconfigOut("libX11.so.6")},
		files: map[string]bool{"/lib/ld-musl-x86_64.so.1": true},
	}
	r := detect(f.deps(), "linux", "amd64", env(nil))
	if got := verdict(r); got != textMusl {
		t.Fatalf("итог = %q, хочу %q", got, textMusl)
	}
}

// TestLinuxArm64NoGUI: правило общее, а не про Intel-мак. Графический
// интерфейс обещается ТОЛЬКО для пары ОС+архитектура, под которую бинарь
// действительно собирается. linux/arm64 в релизе нет — даже когда с glibc и
// библиотеками всё в порядке, «запустится» говорить нельзя.
func TestLinuxArm64NoGUI(t *testing.T) {
	f := linuxAllGood()
	r := detect(f.deps(), "linux", "arm64", env(map[string]string{"DISPLAY": ":0"}))
	if got := verdict(r); got != textNoGUIPlatform {
		t.Fatalf("итог = %q, хочу %q", got, textNoGUIPlatform)
	}
}

// TestGUITargets: список целей GUI — одна таблица в коде; для каждой цели
// «запустится», для соседних пар — «не собираем».
func TestGUITargets(t *testing.T) {
	cases := []struct {
		goos, goarch string
		want         bool
	}{
		{"linux", "amd64", true},
		{"darwin", "arm64", true},
		{"windows", "amd64", true},
		{"linux", "arm64", false},
		{"darwin", "amd64", false},
		{"windows", "arm64", false},
		{"freebsd", "amd64", false},
	}
	for _, c := range cases {
		t.Run(c.goos+"/"+c.goarch, func(t *testing.T) {
			if got := isGUITarget(c.goos, c.goarch); got != c.want {
				t.Fatalf("isGUITarget(%q, %q) = %v, хочу %v", c.goos, c.goarch, got, c.want)
			}
		})
	}
}

// TestNonLinuxVerdict (П2): итог выбирается по паре ОС+архитектура и
// сверяется с фактическим составом релиза. На Intel-маке графической версии
// нет — обещать её нельзя.
func TestNonLinuxVerdict(t *testing.T) {
	cases := []struct{ goos, goarch, want string }{
		{"windows", "amd64", textWillRun},
		{"darwin", "arm64", textWillRun},
		{"darwin", "amd64", textNoGUIPlatform},
	}
	for _, c := range cases {
		t.Run(c.goos+"/"+c.goarch, func(t *testing.T) {
			f := &fakeOS{}
			r := detect(f.deps(), c.goos, c.goarch, env(nil))
			if got := verdict(r); got != c.want {
				t.Fatalf("итог = %q, хочу %q", got, c.want)
			}
			if len(f.calls) != 0 {
				t.Errorf("на не-Linux выполнялись команды: %v", f.calls)
			}
		})
	}
}

// --- Дословность вывода (эталоны Д6) -----------------------------------

// TestReportGolden сравнивает ВЕСЬ вывод целиком с эталонами задания
// (раздел Д6), а не через strings.Contains: Contains пропускает лишний
// пробел, лишнюю строку и изменившийся порядок.
func TestReportGolden(t *testing.T) {
	cases := []struct {
		name string
		r    Result
		want string
	}{
		{
			"а) Linux, всё на месте",
			Result{GOOS: "linux", GOARCH: "amd64", OSName: "Debian GNU/Linux 12 (bookworm)",
				Libc: Libc{Kind: "glibc", Version: "2.36"}, Graph: Graphics{Known: true}, Sess: SessionX11},
			"Проверка окружения\n" +
				"ОС: Debian GNU/Linux 12 (bookworm)\n" +
				"Архитектура: amd64\n" +
				"Библиотека C: glibc 2.36\n" +
				"Библиотеки графики: все на месте\n" +
				"Графическая сессия: есть (X11)\n" +
				"Графический интерфейс запустится.\n",
		},
		{
			"б) Linux, не хватает библиотек, сессии нет",
			Result{GOOS: "linux", GOARCH: "amd64", OSName: "Debian GNU/Linux 12 (bookworm)",
				Libc:  Libc{Kind: "glibc", Version: "2.36"},
				Graph: Graphics{Known: true, MissingHard: []string{"libGL.so.1"}}, Sess: SessionNone},
			"Проверка окружения\n" +
				"ОС: Debian GNU/Linux 12 (bookworm)\n" +
				"Архитектура: amd64\n" +
				"Библиотека C: glibc 2.36\n" +
				"Библиотеки графики: не хватает: libGL.so.1\n" +
				"Графическая сессия: нет\n" +
				"Графическая сессия не найдена — так и должно быть при работе по SSH; графическую версию запускают на своём компьютере.\n" +
				"Графический интерфейс не запустится: не хватает библиотек — libGL.so.1. Установите их: Debian/Ubuntu — `libgl1`; Fedora — `mesa-libGL`.\n",
		},
		{
			"з) Linux, всё на месте, но графической сессии нет (по SSH)",
			Result{GOOS: "linux", GOARCH: "amd64", OSName: "Debian GNU/Linux 12 (bookworm)",
				Libc: Libc{Kind: "glibc", Version: "2.36"}, Graph: Graphics{Known: true}, Sess: SessionNone},
			"Проверка окружения\n" +
				"ОС: Debian GNU/Linux 12 (bookworm)\n" +
				"Архитектура: amd64\n" +
				"Библиотека C: glibc 2.36\n" +
				"Библиотеки графики: все на месте\n" +
				"Графическая сессия: нет\n" +
				"Графическая сессия не найдена — так и должно быть при работе по SSH; графическую версию запускают на своём компьютере.\n" +
				"Графический интерфейс запустится на компьютере с графическим рабочим столом; здесь графической сессии нет, поэтому запускать его нужно не отсюда.\n",
		},
		{
			"и) Linux, glibc старее порога",
			Result{GOOS: "linux", GOARCH: "amd64", OSName: "CentOS Linux 7 (Core)",
				Libc: Libc{Kind: "glibc", Version: "2.17"}, Graph: Graphics{Known: true}, Sess: SessionX11},
			"Проверка окружения\n" +
				"ОС: CentOS Linux 7 (Core)\n" +
				"Архитектура: amd64\n" +
				"Библиотека C: glibc 2.17\n" +
				"Библиотеки графики: все на месте\n" +
				"Графическая сессия: есть (X11)\n" +
				"Графический интерфейс не запустится: система старее, чем нужно графической версии (нужна glibc 2.34 или новее, здесь glibc 2.17). Пользуйтесь консольной версией — она работает везде: у неё нет ни одной внешней зависимости.\n",
		},
		{
			"ж) Linux, не хватает подгружаемых на ходу библиотек",
			Result{GOOS: "linux", GOARCH: "amd64", OSName: "Debian GNU/Linux 12 (bookworm)",
				Libc:  Libc{Kind: "glibc", Version: "2.36"},
				Graph: Graphics{Known: true, MissingDlopen: []string{"libXrandr.so.2", "libXrender.so.1"}}, Sess: SessionX11},
			"Проверка окружения\n" +
				"ОС: Debian GNU/Linux 12 (bookworm)\n" +
				"Архитектура: amd64\n" +
				"Библиотека C: glibc 2.36\n" +
				"Библиотеки графики: обязательные на месте, может не хватать: libXrandr.so.2, libXrender.so.1\n" +
				"Графическая сессия: есть (X11)\n" +
				"Графический интерфейс может не запуститься: обязательные библиотеки на месте, но не хватает — libXrandr.so.2, libXrender.so.1. Установите их: Debian/Ubuntu — `libxrandr2 libxrender1`; Fedora — `libXrandr libXrender`.\n",
		},
		{
			"в) Linux, musl",
			Result{GOOS: "linux", GOARCH: "amd64", OSName: "Alpine Linux v3.20",
				Libc: Libc{Kind: "musl"}, Graph: Graphics{Known: false}, Sess: SessionNone},
			"Проверка окружения\n" +
				"ОС: Alpine Linux v3.20\n" +
				"Архитектура: amd64\n" +
				"Библиотека C: musl\n" +
				"Библиотеки графики: определить не удалось\n" +
				"Графическая сессия: нет\n" +
				"Графическая сессия не найдена — так и должно быть при работе по SSH; графическую версию запускают на своём компьютере.\n" +
				"Графический интерфейс не запустится: система на musl (Alpine). Пользуйтесь консольной версией — она работает везде.\n",
		},
		{
			"г) Linux, определить не удалось",
			Result{GOOS: "linux", GOARCH: "amd64", OSName: "Void Linux",
				Libc: Libc{}, Graph: Graphics{Known: false}, Sess: SessionWayland},
			"Проверка окружения\n" +
				"ОС: Void Linux\n" +
				"Архитектура: amd64\n" +
				"Библиотека C: определить не удалось\n" +
				"Библиотеки графики: определить не удалось\n" +
				"Графическая сессия: есть (Wayland)\n" +
				"Проверить не удалось: библиотека C, библиотеки графики. Консольная версия работает независимо от этого.\n",
		},
		{
			"д1) не-Linux, GUI собирается",
			Result{GOOS: "windows", GOARCH: "amd64", OSName: "Windows"},
			"Проверка окружения\n" +
				"ОС: Windows\n" +
				"Архитектура: amd64\n" +
				"Графический интерфейс запустится.\n",
		},
		{
			"е) Linux, под который GUI не собирается (linux/arm64)",
			Result{GOOS: "linux", GOARCH: "arm64", OSName: "Debian GNU/Linux 12 (bookworm)"},
			"Проверка окружения\n" +
				"ОС: Debian GNU/Linux 12 (bookworm)\n" +
				"Архитектура: arm64\n" +
				"Графической версии для этой платформы нет. Пользуйтесь консольной версией — она работает везде.\n",
		},
		{
			"д2) не-Linux, GUI не собирается",
			Result{GOOS: "darwin", GOARCH: "amd64", OSName: "macOS"},
			"Проверка окружения\n" +
				"ОС: macOS\n" +
				"Архитектура: amd64\n" +
				"Графической версии для этой платформы нет. Пользуйтесь консольной версией — она работает везде.\n",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var b bytes.Buffer
			Report(c.r, &b)
			if b.String() != c.want {
				t.Fatalf("вывод:\n%s\nхочу:\n%s", b.String(), c.want)
			}
		})
	}
}

// TestOSNameFromOsRelease: PRETTY_NAME читается и очищается от кавычек.
// Образец /etc/os-release — ПО ПАМЯТИ, НЕ ДОКАЗАТЕЛЬСТВО, источник: память модели.
func TestOSNameFromOsRelease(t *testing.T) {
	f := linuxAllGood()
	r := detect(f.deps(), "linux", "amd64", env(map[string]string{"DISPLAY": ":0"}))
	if r.OSName != "Debian GNU/Linux 12 (bookworm)" {
		t.Fatalf("OSName = %q", r.OSName)
	}
	if got := verdict(r); got != textWillRun {
		t.Fatalf("итог = %q, хочу %q", got, textWillRun)
	}
}

// TestOSNameUnknown: ОС не прочиталась — «определить не удалось», и это
// попадает в итог, а не подменяется чем-то утвердительным.
func TestOSNameUnknown(t *testing.T) {
	f := &fakeOS{out: map[string]string{
		"getconf GNU_LIBC_VERSION": "glibc 2.36\n",
		"ldconfig -p":              ldconfigOut(allLibs...),
	}}
	r := detect(f.deps(), "linux", "amd64", env(map[string]string{"DISPLAY": ":0"}))
	if r.OSName != "" {
		t.Fatalf("OSName = %q, хочу пустую (/etc/os-release не читается)", r.OSName)
	}
	var b bytes.Buffer
	Report(r, &b)
	if !strings.Contains(b.String(), "ОС: определить не удалось\n") {
		t.Fatalf("нет строки «ОС: определить не удалось»:\n%s", b.String())
	}
	// Решение координатора: название ОС — справочная строка, на итог она не
	// влияет. Всё остальное в порядке — значит «запустится».
	if got := verdict(r); got != textWillRun {
		t.Fatalf("итог = %q, хочу %q: нечитаемый /etc/os-release на итог влиять не должен", got, textWillRun)
	}
}

// --- Ревью: порог glibc, признак glibc, разбор ldconfig, запасной путь ----

// TestGlibcTooOld (К1): версия glibc старее порога — уверенное «не
// запустится», даже когда все библиотеки на месте. Порог 2.34 снят замером
// по релизному бинарю (разбор .dynstr), это доказательство, а не README.
func TestGlibcTooOld(t *testing.T) {
	f := &fakeOS{out: map[string]string{
		"getconf GNU_LIBC_VERSION": "glibc 2.17\n",
		"ldconfig -p":              ldconfigOut(allLibs...),
	}}
	r := detect(f.deps(), "linux", "amd64", env(map[string]string{"DISPLAY": ":0"}))
	want := "Графический интерфейс не запустится: система старее, чем нужно графической версии (нужна glibc 2.34 или новее, здесь glibc 2.17). Пользуйтесь консольной версией — она работает везде: у неё нет ни одной внешней зависимости."
	if got := verdict(r); got != want {
		t.Fatalf("итог = %q, хочу %q", got, want)
	}
}

// TestGlibcVersionCompareIsNumeric (К1): сравнение покомпонентное, не
// строковое. «2.9» меньше «2.34», хотя как строка — больше.
func TestGlibcVersionCompareIsNumeric(t *testing.T) {
	cases := []struct {
		ver string
		old bool // старее порога
	}{
		{"2.9", true},
		{"2.17", true},
		{"2.33", true},
		{"2.34", false},
		{"2.36", false},
		{"2.40", false},
		{"3.0", false},
	}
	for _, c := range cases {
		t.Run(c.ver, func(t *testing.T) {
			f := &fakeOS{out: map[string]string{
				"getconf GNU_LIBC_VERSION": "glibc " + c.ver + "\n",
				"ldconfig -p":              ldconfigOut(allLibs...),
			}}
			r := detect(f.deps(), "linux", "amd64", env(map[string]string{"DISPLAY": ":0"}))
			tooOld := strings.HasPrefix(verdict(r), "Графический интерфейс не запустится: система старее")
			if tooOld != c.old {
				t.Fatalf("glibc %s: итог = %q", c.ver, verdict(r))
			}
		})
	}
}

// TestLddNeedsGlibcMarker (К2): строка `ldd --version` обязана содержать
// «glibc» или «GNU libc». Любая другая программа с номером версии в выводе
// не превращается в «glibc <число>».
func TestLddNeedsGlibcMarker(t *testing.T) {
	f := &fakeOS{out: map[string]string{
		"ldd --version": "some other tool 1.2.3\n",
		"ldconfig -p":   ldconfigOut(allLibs...),
	}}
	r := detect(f.deps(), "linux", "amd64", env(map[string]string{"DISPLAY": ":0"}))
	if r.Libc.Kind != "" {
		t.Fatalf("Libc = %+v, хочу «определить не удалось»", r.Libc)
	}
}

// TestMuslRejectedByWholeOutput (К2): «musl» отвергается по ВСЕМУ выводу, а
// не по первой непустой строке. Иначе вывод, где номер версии идёт первым,
// объявил бы Alpine системой с glibc, и проверка загрузчика уже не
// выполнилась бы.
func TestMuslRejectedByWholeOutput(t *testing.T) {
	f := &fakeOS{
		out: map[string]string{
			"ldd --version": "Version 1.2.5\nmusl libc (x86_64)\nDynamic Program Loader\n",
			"ldconfig -p":   ldconfigOut(allLibs...),
		},
		files: map[string]bool{"/lib/ld-musl-x86_64.so.1": true},
	}
	r := detect(f.deps(), "linux", "amd64", env(nil))
	if r.Libc.Kind != "musl" {
		t.Fatalf("Libc = %+v, хочу musl", r.Libc)
	}
	if got := verdict(r); got != textMusl {
		t.Fatalf("итог = %q, хочу %q", got, textMusl)
	}
}

// TestLdconfigNameMatchedExactly (В3): имя сопоставляется по полю SONAME
// строки, а не подстрокой по всему тексту. Имя, встреченное внутри чужого
// пути, наличием библиотеки не считается.
func TestLdconfigNameMatchedExactly(t *testing.T) {
	out := ldconfigOut(without("libXrandr.so.2")...)
	out += "\tlibQt5Gui.so.5 (libc6,x86-64) => /opt/libXrandr.so.2/libQt5Gui.so.5\n"
	f := &fakeOS{out: map[string]string{
		"getconf GNU_LIBC_VERSION": "glibc 2.36\n",
		"ldconfig -p":              out,
	}}
	r := detect(f.deps(), "linux", "amd64", env(map[string]string{"DISPLAY": ":0"}))
	if strings.Join(r.Graph.MissingDlopen, ",") != "libXrandr.so.2" {
		t.Fatalf("MissingDlopen = %v, хочу [libXrandr.so.2]: имя из чужого пути не должно засчитываться", r.Graph.MissingDlopen)
	}
}

// TestLdconfigArchMatters (В4): для цели x86-64 годятся только 64-битные
// записи. Кэш, где те же имена лежат только как i386, — это «не хватает», а
// не «всё на месте».
func TestLdconfigArchMatters(t *testing.T) {
	out := "9 libs found in cache\n"
	for _, l := range allLibs {
		out += "\t" + l + " (libc6) => /usr/lib/i386-linux-gnu/" + l + "\n"
	}
	f := &fakeOS{out: map[string]string{
		"getconf GNU_LIBC_VERSION": "glibc 2.36\n",
		"ldconfig -p":              out,
	}}
	r := detect(f.deps(), "linux", "amd64", env(map[string]string{"DISPLAY": ":0"}))
	if !r.Graph.Known {
		t.Fatalf("Graph = %+v: строки формата разобраны, значит способ 1 удался", r.Graph)
	}
	if len(r.Graph.MissingHard) != 2 {
		t.Fatalf("MissingHard = %v, хочу обе жёсткие: 32-битные записи для нашей цели не годятся", r.Graph.MissingHard)
	}
}

// TestLdconfigArm64Arch (В4): на arm64 годятся записи AArch64.
func TestLdconfigArm64Arch(t *testing.T) {
	out := "9 libs found in cache\n"
	for _, l := range allLibs {
		out += "\t" + l + " (libc6,AArch64) => /usr/lib/aarch64-linux-gnu/" + l + "\n"
	}
	f := &fakeOS{out: map[string]string{
		"getconf GNU_LIBC_VERSION": "glibc 2.36\n",
		"ldconfig -p":              out,
	}}
	// linux/arm64 GUI не собирается, поэтому смотрим на признак, а не на итог.
	g := detectGraphics(f.deps(), "arm64")
	if !g.Known || len(g.MissingHard) != 0 || len(g.MissingDlopen) != 0 {
		t.Fatalf("Graph = %+v, хочу «все на месте»", g)
	}
}

// TestDirsWithoutAnyLib (В5): каталог существует, но ни одной искомой
// библиотеки в нём нет — «определить не удалось», а не «нет всех». Иначе на
// нестандартной раскладке (NixOS, Guix, свой префикс) исправной машине
// велят ставить пакеты.
func TestDirsWithoutAnyLib(t *testing.T) {
	f := &fakeOS{
		out:   map[string]string{"getconf GNU_LIBC_VERSION": "glibc 2.36\n"},
		files: map[string]bool{"/usr/lib": true, "/usr/lib64": true},
	}
	r := detect(f.deps(), "linux", "amd64", env(map[string]string{"DISPLAY": ":0"}))
	if r.Graph.Known {
		t.Fatalf("Graph = %+v, хочу «определить не удалось»", r.Graph)
	}
}

// TestDirsWithSomeLibs (В5): если хоть что-то из искомого в каталогах есть,
// каталоги авторитетны, и ненайденное — действительно ненайденное.
func TestDirsWithSomeLibs(t *testing.T) {
	files := map[string]bool{"/usr/lib64": true}
	for _, l := range without("libXrandr.so.2") {
		files["/usr/lib64/"+l] = true
	}
	f := &fakeOS{
		out:   map[string]string{"getconf GNU_LIBC_VERSION": "glibc 2.36\n"},
		files: files,
	}
	r := detect(f.deps(), "linux", "amd64", env(map[string]string{"DISPLAY": ":0"}))
	if !r.Graph.Known || strings.Join(r.Graph.MissingDlopen, ",") != "libXrandr.so.2" {
		t.Fatalf("Graph = %+v, хочу «не хватает libXrandr.so.2»", r.Graph)
	}
}

// TestNoSessionVerdict (З10): «Графическая сессия: нет» и «Графический
// интерфейс запустится.» в одном выводе противоречат друг другу.
func TestNoSessionVerdict(t *testing.T) {
	f := linuxAllGood()
	r := detect(f.deps(), "linux", "amd64", env(nil))
	if got := verdict(r); got != textWillRunNoSession {
		t.Fatalf("итог = %q, хочу %q", got, textWillRunNoSession)
	}
}

// TestPrettyNameWithSpaces (З11): PRETTY_NAME = "X" с пробелами вокруг «=».
func TestPrettyNameWithSpaces(t *testing.T) {
	f := linuxAllGood()
	f.out["cat /etc/os-release"] = "NAME = \"Debian GNU/Linux\"\nPRETTY_NAME = \"Debian GNU/Linux 12 (bookworm)\"\n"
	r := detect(f.deps(), "linux", "amd64", env(map[string]string{"DISPLAY": ":0"}))
	if r.OSName != "Debian GNU/Linux 12 (bookworm)" {
		t.Fatalf("OSName = %q", r.OSName)
	}
}
