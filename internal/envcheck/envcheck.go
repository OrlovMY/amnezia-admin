// Пакет envcheck отвечает на вопрос «запустится ли графическая версия на
// этой машине» — до того, как человек попробует её запустить.
//
// Почему проверку печатает консольная версия, а не графическая: при
// отсутствии libGL динамический компоновщик убивает процесс GUI ДО первой
// строки Go-кода, поэтому ни init(), ни начало main() в GUI не выполнятся —
// диагностику обязан печатать статический CLI.
//
// Пакет не импортирует ничего, кроме стандартной библиотеки (ни Fyne, ни
// CGO), и всё, что он узнаёт об ОС, он узнаёт через подставляемые
// зависимости Deps — чтобы случаи Alpine/Fedora/«нет ldconfig»
// воспроизводились в тестах на машине разработчика (Windows).
//
// Пакет ничего не загружает и не открывает dlopen-ом: попытка
// «по-настоящему» загрузить libGL на сломанной системе убила бы процесс
// ровно тем же способом, что и GUI, — диагностика не должна падать вместе с
// тем, что диагностирует.
//
// Главное правило пакета: «определить не удалось» НИКОГДА не превращается в
// «нет». Не нашли список библиотек — это не «библиотек нет»: ldconfig есть
// не везде, и совет ставить пакеты, которые уже стоят, стоит доверия к
// утилите.
package envcheck

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
)

// Тексты для человека — дословно из задания (UI-01): не пересказывать и не
// «улучшать». Любая правка этих строк — правка эталонов теста дословности.
const (
	textHeader      = "Проверка окружения"
	textWillRun     = "Графический интерфейс запустится."
	textMissingLibs = "Графический интерфейс не запустится: не хватает библиотек — %s. Установите их: Debian/Ubuntu — `%s`; Fedora — `%s`."
	textMusl        = "Графический интерфейс не запустится: система на musl (Alpine). Пользуйтесь консольной версией — она работает везде."
	// textOldGlibc — система старее, чем нужно графической версии. Редакция
	// ожидает подтверждения UI-01 (см. .ask, п. 1в).
	textOldGlibc = "Графический интерфейс не запустится: система старее, чем нужно графической версии (нужна glibc %s или новее, здесь glibc %s). Пользуйтесь консольной версией — она работает везде: у неё нет ни одной внешней зависимости."
	// textWillRunNoSession — всё в порядке, но графической сессии здесь нет.
	// Говорить просто «запустится» рядом со строкой «Графическая сессия: нет»
	// нельзя: это противоречие. Редакция ожидает подтверждения UI-01
	// (см. .ask, п. 1г).
	textWillRunNoSession = "Графический интерфейс запустится на компьютере с графическим рабочим столом; здесь графической сессии нет, поэтому запускать его нужно не отсюда."
	// Подстановка в textCannotCheck — перечень названий признаков через
	// запятую; редакция ожидает подтверждения UI-01 (см. .ask, п. 1).
	textCannotCheck = "Проверить не удалось: %s. Консольная версия работает независимо от этого."
	// textMaybeMissingLibs — промежуточный итог: жёсткие зависимости на
	// месте, но библиотек, которые GUI подгружает на ходу (dlopen), не
	// видно. Уверенного «не запустится» здесь быть не может, «всё хорошо» —
	// тоже. Редакция ожидает подтверждения UI-01 (см. .ask, п. 1).
	textMaybeMissingLibs = "Графический интерфейс может не запуститься: обязательные библиотеки на месте, но не хватает — %s. Установите их: Debian/Ubuntu — `%s`; Fedora — `%s`."
	textNoGUIPlatform    = "Графической версии для этой платформы нет. Пользуйтесь консольной версией — она работает везде."
	textSSHSession       = "Графическая сессия не найдена — так и должно быть при работе по SSH; графическую версию запускают на своём компьютере."
	textUnknown          = "определить не удалось"
)

// Классы графических библиотек.
const (
	libHard    = iota // жёсткая зависимость (DT_NEEDED): без неё процесс не стартует
	libDlopen         // подгружается на ходу (dlopen): таблица зависимостей её не показывает
	libByLibcC        // жёсткая, но уже покрыта признаком «библиотека C»
)

// graphicsLibs — фактический состав зависимостей релизного GUI.
//
// ИСТОЧНИК — ДОКАЗАТЕЛЬСТВО, А НЕ ПАМЯТЬ МОДЕЛИ (в отличие от образцов
// выводов ldd/ldconfig в тестах): список снят координатором с релизного
// бинаря amnezia-admin-gui-linux-amd64 версии v0.1.0 разбором ELF
// (debug/elf, таблица DT_NEEDED) и поиском имён библиотек в теле бинаря.
// Замер: ELFCLASS64, EM_X86_64, загрузчик /lib64/ld-linux-x86-64.so.2;
// DT_NEEDED всего четыре — libGL.so.1, libX11.so.6, libm.so.6, libc.so.6;
// в теле присутствует dlopen и найдены имена libEGL.so.1, libXcursor.so.1,
// libXi.so.6, libXinerama.so.1, libXrandr.so.2, libXxf86vm.so.1,
// libXrender.so.1 (libwayland-client.so.0 и libXext.so.6 НЕ найдены).
//
// Прежний список из шести имён (libGL, libEGL, libX11, libXcursor, libXi,
// libXinerama) был неверен: в нём не было libXrandr.so.2, libXxf86vm.so.1 и
// libXrender.so.1, то есть проверка могла сказать «все на месте» машине, где
// GUI упадёт. Порядок в таблице важен: в нём печатаются списки нехватающих.
// OSMesa в состав не входит — программная отрисовка не то, на что рассчитан
// релизный GUI.
var graphicsLibs = []struct {
	SOName string
	Class  int
	Debian string // имя пакета Debian/Ubuntu
	Fedora string // имя пакета Fedora
}{
	{"libGL.so.1", libHard, "libgl1", "mesa-libGL"},
	{"libX11.so.6", libHard, "libx11-6", "libX11"},
	// libm.so.6 и libc.so.6 — тоже жёсткие зависимости, но отдельно не
	// проверяются и в вывод не попадают: их наличие уже определяется
	// признаком «библиотека C» (glibc/musl), и дублировать это в перечне
	// графических библиотек пользователю незачем.
	{"libm.so.6", libByLibcC, "", ""},
	{"libc.so.6", libByLibcC, "", ""},
	{"libEGL.so.1", libDlopen, "libegl1", "mesa-libEGL"},
	{"libXcursor.so.1", libDlopen, "libxcursor1", "libXcursor"},
	{"libXi.so.6", libDlopen, "libxi6", "libXi"},
	{"libXinerama.so.1", libDlopen, "libxinerama1", "libXinerama"},
	{"libXrandr.so.2", libDlopen, "libxrandr2", "libXrandr"},
	{"libXxf86vm.so.1", libDlopen, "libxxf86vm1", "libXxf86vm"},
	{"libXrender.so.1", libDlopen, "libxrender1", "libXrender"},
}

// glibcMin — минимальная версия glibc, с которой запускается релизный GUI.
//
// ИСТОЧНИК — ДОКАЗАТЕЛЬСТВО, А НЕ README И НЕ ПАМЯТЬ МОДЕЛИ: замер
// координатора по тому же релизному бинарю v0.1.0 (разбор .dynstr, версии
// символов). Найденные версии: GLIBC_2.2.5, 2.3.2, 2.3.4, 2.4, 2.7, 2.9,
// 2.14, 2.17, 2.27, 2.32, 2.34 — максимум GLIBC_2.34. На glibc старее
// процесс падает с «GLIBC_2.34 not found». Консольная версия статическая,
// внешних зависимостей у неё ноль (тот же замер), поэтому она работает и
// там, где GUI не запустится.
const glibcMin = "2.34"

// cmpVersion сравнивает версии покомпонентно и численно: «2.9» меньше
// «2.34», хотя как строки они сравниваются наоборот. Возвращает -1, 0 или 1;
// нечисловой компонент считается нулём.
func cmpVersion(a, b string) int {
	as, bs := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(as) || i < len(bs); i++ {
		x, y := 0, 0
		if i < len(as) {
			x, _ = strconv.Atoi(as[i])
		}
		if i < len(bs) {
			y, _ = strconv.Atoi(bs[i])
		}
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	return 0
}

// packagesFor — имена пакетов для перечисленных SONAME (пустые пропускаются).
func packagesFor(libs []string, fedora bool) string {
	var out []string
	for _, name := range libs {
		for _, l := range graphicsLibs {
			if l.SOName != name {
				continue
			}
			pkg := l.Debian
			if fedora {
				pkg = l.Fedora
			}
			if pkg != "" {
				out = append(out, pkg)
			}
		}
	}
	return strings.Join(out, " ")
}

// guiTargets — пары ОС+архитектура, под которые графическое приложение
// действительно собирается и попадает в релиз (scripts/build-release.sh).
// Одна таблица на весь пакет: добавится цель — правится одно место.
//
// Правило, ради которого таблица существует: check обещает графический
// интерфейс ТОЛЬКО для пары из этого списка. Для любой другой пары —
// формулировка «графической версии для этой платформы нет»: утилита не
// имеет права обещать бинарь, которого в релизе не существует.
var guiTargets = map[string]bool{
	"linux/amd64":   true,
	"darwin/arm64":  true,
	"windows/amd64": true,
}

func isGUITarget(gooS, goarcH string) bool { return guiTargets[gooS+"/"+goarcH] }

// muslLoaders — загрузчики musl; их наличие и есть признак Alpine.
var muslLoaders = []string{
	"/lib/ld-musl-x86_64.so.1",
	"/lib/ld-musl-aarch64.so.1",
}

// Deps — подставляемые зависимости: всё, что пакет узнаёт об ОС, он узнаёт
// только через них.
type Deps struct {
	Run    func(name string, args ...string) (stdout string, err error) // выполнить команду
	Exists func(path string) bool                                       // существует ли файл
}

// Libc — состояние признака «библиотека C»: Kind == "" означает «определить
// не удалось» (третье состояние, которого не бывает у bool).
type Libc struct {
	Kind    string // "glibc" | "musl" | "" — определить не удалось
	Version string // только для glibc
}

// Graphics — состояние признака «библиотеки графики». Known == false —
// «определить не удалось», и это НЕ то же самое, что «не хватает всех».
//
// Два списка, потому что классы зависимостей разные: без жёсткой (DT_NEEDED)
// процесс не стартует вообще — это уверенное «не запустится»; библиотеки,
// подгружаемые на ходу (dlopen), таблица зависимостей не показывает, их
// нехватка означает «может не запуститься», а не приговор.
type Graphics struct {
	Known         bool
	MissingHard   []string
	MissingDlopen []string
}

// Session — графическая сессия. «Нет» здесь — полноценное состояние, а не
// неудача: по SSH сессии нет закономерно, и это не ошибка.
type Session int

const (
	SessionNone Session = iota
	SessionX11
	SessionWayland
)

// Result — снимок окружения. У каждого признака три состояния.
type Result struct {
	GOOS   string
	GOARCH string
	OSName string // PRETTY_NAME; "" — определить не удалось
	Libc   Libc
	Graph  Graphics
	Sess   Session
}

// OSDeps — боевая реализация зависимостей.
func OSDeps() Deps {
	return Deps{
		Run: func(name string, args ...string) (string, error) {
			out, err := exec.Command(name, args...).Output()
			return string(out), err
		},
		Exists: func(path string) bool {
			_, err := os.Stat(path)
			return err == nil
		},
	}
}

// Detect — чистая функция: никаких обращений к ОС мимо d.
func Detect(d Deps) Result {
	return detect(d, runtime.GOOS, runtime.GOARCH, os.Getenv)
}

// detect — то же, что Detect, но с явными ОС, архитектурой и чтением
// переменных окружения: иначе случаи darwin/amd64 и linux не проверить на
// машине разработчика, где GOOS всегда windows.
func detect(d Deps, gooS, goarcH string, getenv func(string) string) Result {
	r := Result{GOOS: gooS, GOARCH: goarcH}
	if gooS != "linux" {
		// На не-Linux ни glibc, ни ldconfig, ни X11-сессии не существует:
		// печатаются только ОС, архитектура и итог по паре ОС+архитектура.
		r.OSName = nonLinuxOSName(gooS)
		return r
	}
	r.OSName = detectOSName(d)
	if !isGUITarget(gooS, goarcH) {
		// Linux, под который графическое приложение не собирается
		// (linux/arm64): признаки glibc и библиотек здесь ничего не решают —
		// бинаря нет в любом случае, и разбирать окружение незачем.
		return r
	}
	r.Libc = detectLibc(d)
	r.Graph = detectGraphics(d, goarcH)
	r.Sess = detectSession(getenv)
	return r
}

func nonLinuxOSName(gooS string) string {
	switch gooS {
	case "windows":
		return "Windows"
	case "darwin":
		return "macOS"
	default:
		return gooS
	}
}

// detectOSName читает PRETTY_NAME из /etc/os-release. Чтение идёт через
// Run("cat", …), а не через os.ReadFile, чтобы Detect оставалась чистой
// относительно Deps (обращений к ОС мимо d нет) и чтобы случай «файла нет»
// воспроизводился в тестах. Не прочиталось — «определить не удалось».
func detectOSName(d Deps) string {
	out, err := d.Run("cat", "/etc/os-release")
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(out, "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok || strings.TrimSpace(key) != "PRETTY_NAME" {
			continue
		}
		// Пробелы вокруг «=» в os-release встречаются; кавычки бывают и
		// двойные, и одинарные.
		v := strings.Trim(strings.TrimSpace(value), "\"'")
		if v != "" {
			return v
		}
	}
	return ""
}

var versionRe = regexp.MustCompile(`\d+\.\d+(?:\.\d+)*`)

// detectLibc: способ 1 — getconf, способ 2 — ldd --version, затем признак
// musl по файлу загрузчика. Неудача всего перечисленного даёт «определить не
// удалось» и НИКОГДА «нет»/«musl».
func detectLibc(d Deps) Libc {
	if out, err := d.Run("getconf", "GNU_LIBC_VERSION"); err == nil {
		if v := parseGetconf(out); v != "" {
			return Libc{Kind: "glibc", Version: v}
		}
	}
	if out, err := d.Run("ldd", "--version"); err == nil {
		if v := parseLddVersion(out); v != "" {
			return Libc{Kind: "glibc", Version: v}
		}
	}
	for _, p := range muslLoaders {
		if d.Exists(p) {
			return Libc{Kind: "musl"}
		}
	}
	return Libc{}
}

// parseGetconf разбирает вывод вида "glibc 2.39".
func parseGetconf(out string) string {
	fields := strings.Fields(out)
	if len(fields) < 2 || !strings.EqualFold(fields[0], "glibc") {
		return ""
	}
	if !versionRe.MatchString(fields[1]) {
		return ""
	}
	return fields[1]
}

// parseLddVersion берёт номер версии из вывода `ldd --version`.
//
// Два жёстких условия, без которых способ врёт:
//  1. «musl» отвергается по ВСЕМУ выводу, а не по первой непустой строке:
//     ldd из musl печатает собственный номер версии, и если номер стоит
//     первой строкой, наивный разбор объявит Alpine системой с glibc — до
//     проверки загрузчика /lib/ld-musl-* дело тогда уже не дойдёт;
//  2. строка обязана содержать «glibc» или «GNU libc», иначе любая другая
//     программа с номером версии в выводе превратится в «glibc <число>».
//
// Любое из условий не выполнено — неудача способа, то есть «определить не
// удалось»; ни «нет», ни «musl» отсюда не следует.
func parseLddVersion(out string) string {
	if strings.Contains(strings.ToLower(out), "musl") {
		return ""
	}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		low := strings.ToLower(line)
		if !strings.Contains(low, "glibc") && !strings.Contains(low, "gnu libc") {
			return ""
		}
		m := versionRe.FindAllString(line, -1)
		if len(m) == 0 {
			return ""
		}
		return m[len(m)-1]
	}
	return ""
}

// ldconfigLineRe — строка вида `имя.so.N (флаги) => /путь`. Имя и флаги —
// отдельными группами: имя сравнивается точно (поиск подстрокой по всему
// тексту засчитал бы имя, встреченное внутри чужого пути), а по флагам
// определяется разрядность записи. Если в выводе нет ни одной такой строки,
// способ 1 считается неудавшимся, и «нет библиотек» из него не следует.
var ldconfigLineRe = regexp.MustCompile(`(?m)^\s*(\S+\.so\.\d+)\s+\(([^)]*)\)\s*=>\s*(/\S*)\s*$`)

// archMatches: годится ли запись ldconfig для нашей цели. У 64-битной записи
// на x86-64 в поле флагов стоит «x86-64», на arm64 — «AArch64». Записи i386
// нашему бинарю не годятся, поэтому кэш, где лежат только они, — это «не
// хватает», а не «всё на месте».
func archMatches(flags, goarcH string) bool {
	f := strings.ToLower(flags)
	switch goarcH {
	case "amd64":
		return strings.Contains(f, "x86-64")
	case "arm64":
		return strings.Contains(f, "aarch64")
	default:
		return true
	}
}

// ldconfigLibs — имена библиотек нужной разрядности из вывода `ldconfig -p`.
// Второе значение говорит, удался ли разбор вообще (нашлась ли хоть одна
// строка ожидаемого формата).
func ldconfigLibs(out, goarcH string) (map[string]bool, bool) {
	ms := ldconfigLineRe.FindAllStringSubmatch(out, -1)
	if len(ms) == 0 {
		return nil, false
	}
	set := make(map[string]bool, len(ms))
	for _, m := range ms {
		if archMatches(m[2], goarcH) {
			set[m[1]] = true
		}
	}
	return set, true
}

// detectGraphics: способ 1 — ldconfig -p, способ 2 — наличие файлов в
// известных каталогах. Провал обоих — «определить не удалось».
func detectGraphics(d Deps, goarcH string) Graphics {
	if out, err := d.Run("ldconfig", "-p"); err == nil && strings.TrimSpace(out) != "" {
		if set, ok := ldconfigLibs(out, goarcH); ok {
			return missingByClasses(func(lib string) bool { return set[lib] })
		}
	}

	var dirs []string
	for _, dir := range libDirs(goarcH) {
		if d.Exists(dir) {
			dirs = append(dirs, dir)
		}
	}
	if len(dirs) == 0 {
		// Ни списка, ни каталогов — мы просто не знаем. «Не хватает всех»
		// отсюда не следует.
		return Graphics{}
	}
	found := map[string]bool{}
	for _, l := range graphicsLibs {
		if l.Class == libByLibcC {
			continue
		}
		for _, dir := range dirs {
			if d.Exists(dir + "/" + l.SOName) {
				found[l.SOName] = true
				break
			}
		}
	}
	if len(found) == 0 {
		// Существование каталога не делает его содержимое авторитетным. Не
		// нашлось НИ ОДНОЙ искомой библиотеки — перед нами скорее
		// нестандартная раскладка (NixOS, Guix, свой префикс), чем машина
		// без графики: «определить не удалось», а не «нет всех».
		return Graphics{}
	}
	return missingByClasses(func(lib string) bool { return found[lib] })
}

// missingByClasses раскладывает ненайденные библиотеки по двум классам.
// Класс libByLibcC (libc.so.6, libm.so.6) не проверяется вовсе: он покрыт
// признаком «библиотека C».
func missingByClasses(found func(lib string) bool) Graphics {
	g := Graphics{Known: true}
	for _, l := range graphicsLibs {
		if l.Class == libByLibcC || found(l.SOName) {
			continue
		}
		if l.Class == libHard {
			g.MissingHard = append(g.MissingHard, l.SOName)
		} else {
			g.MissingDlopen = append(g.MissingDlopen, l.SOName)
		}
	}
	return g
}

// libDirs — каталоги способа 2. Отсутствие каталога — не «нет библиотеки», а
// просто следующий путь из списка.
func libDirs(goarcH string) []string {
	triplet := "x86_64-linux-gnu"
	if goarcH == "arm64" {
		triplet = "aarch64-linux-gnu"
	}
	return []string{"/usr/lib/" + triplet, "/usr/lib64", "/usr/lib"}
}

func detectSession(getenv func(string) string) Session {
	if strings.TrimSpace(getenv("DISPLAY")) != "" {
		return SessionX11
	}
	if strings.TrimSpace(getenv("WAYLAND_DISPLAY")) != "" {
		return SessionWayland
	}
	return SessionNone
}

// verdict — итоговая строка (ровно одна из пяти формулировок).
//
// Порядок разрешения: musl перевешивает нехватку библиотек (на Alpine
// ставить libgl1 бесполезно), нехватка библиотек перевешивает «определить не
// удалось», «определить не удалось» — последний. Отсутствие графической
// сессии на выбор итога не влияет: по SSH её нет закономерно.
func verdict(r Result) string {
	// Итог сверяется с фактическим составом релиза, а не с «это Linux или
	// нет»: пары вне guiTargets (linux/arm64, Intel-мак и любая другая)
	// получают одну и ту же формулировку — бинаря под них не существует.
	if !isGUITarget(r.GOOS, r.GOARCH) {
		return textNoGUIPlatform
	}
	if r.GOOS != "linux" {
		return textWillRun
	}
	if r.Libc.Kind == "musl" {
		return textMusl
	}
	if r.Libc.Kind == "glibc" && cmpVersion(r.Libc.Version, glibcMin) < 0 {
		// Система старее, чем нужно графической версии: на такой glibc
		// процесс падает с «GLIBC_2.34 not found» — снова до первой строки
		// Go-кода, как и при отсутствии libGL.
		return fmt.Sprintf(textOldGlibc, glibcMin, r.Libc.Version)
	}
	if r.Graph.Known && len(r.Graph.MissingHard) > 0 {
		// Жёсткая зависимость: без неё динамический компоновщик убьёт
		// процесс до первой строки Go-кода.
		return fmt.Sprintf(textMissingLibs,
			strings.Join(r.Graph.MissingHard, ", "),
			packagesFor(r.Graph.MissingHard, false),
			packagesFor(r.Graph.MissingHard, true))
	}
	if r.Graph.Known && len(r.Graph.MissingDlopen) > 0 {
		return fmt.Sprintf(textMaybeMissingLibs,
			strings.Join(r.Graph.MissingDlopen, ", "),
			packagesFor(r.Graph.MissingDlopen, false),
			packagesFor(r.Graph.MissingDlopen, true))
	}
	// Название ОС в итог не входит: это справочная строка, и нечитаемый
	// /etc/os-release не повод объявлять проверку несостоявшейся.
	var unknown []string
	if r.Libc.Kind == "" {
		unknown = append(unknown, "библиотека C")
	}
	if !r.Graph.Known {
		unknown = append(unknown, "библиотеки графики")
	}
	if len(unknown) > 0 {
		return fmt.Sprintf(textCannotCheck, strings.Join(unknown, ", "))
	}
	if r.Sess == SessionNone {
		// «Графическая сессия: нет» и «Графический интерфейс запустится.» в
		// одном выводе противоречат друг другу: здесь он как раз не
		// запустится — запускать его нужно с графического рабочего стола.
		return textWillRunNoSession
	}
	return textWillRun
}

// Report печатает строки для человека. Состав строк задан эталонами задания
// (Д6) и проверяется тестом дословности целиком.
func Report(r Result, w io.Writer) {
	fmt.Fprintln(w, textHeader)
	fmt.Fprintln(w, "ОС: "+orUnknown(r.OSName))
	fmt.Fprintln(w, "Архитектура: "+orUnknown(r.GOARCH))
	if r.GOOS == "linux" && isGUITarget(r.GOOS, r.GOARCH) {
		fmt.Fprintln(w, "Библиотека C: "+libcLine(r.Libc))
		fmt.Fprintln(w, "Библиотеки графики: "+graphicsLine(r.Graph))
		fmt.Fprintln(w, "Графическая сессия: "+sessionLine(r.Sess))
		if r.Sess == SessionNone {
			fmt.Fprintln(w, textSSHSession)
		}
	}
	fmt.Fprintln(w, verdict(r))
}

func orUnknown(s string) string {
	if s == "" {
		return textUnknown
	}
	return s
}

func libcLine(l Libc) string {
	switch l.Kind {
	case "glibc":
		return "glibc " + l.Version
	case "musl":
		return "musl"
	default:
		return textUnknown
	}
}

func graphicsLine(g Graphics) string {
	if !g.Known {
		return textUnknown
	}
	if len(g.MissingHard) > 0 {
		return "не хватает: " + strings.Join(g.MissingHard, ", ")
	}
	if len(g.MissingDlopen) > 0 {
		return "обязательные на месте, может не хватать: " + strings.Join(g.MissingDlopen, ", ")
	}
	return "все на месте"
}

func sessionLine(s Session) string {
	switch s {
	case SessionX11:
		return "есть (X11)"
	case SessionWayland:
		return "есть (Wayland)"
	default:
		return "нет"
	}
}
