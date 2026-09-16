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
	"strings"
)

// Тексты для человека — дословно из задания (UI-01): не пересказывать и не
// «улучшать». Любая правка этих строк — правка эталонов теста дословности.
const (
	textHeader      = "Проверка окружения"
	textWillRun     = "Графический интерфейс запустится."
	textMissingLibs = "Графический интерфейс не запустится: не хватает библиотек — %s. Установите их: Debian/Ubuntu — `libgl1 libx11-6 libxcursor1 libxi6 libxinerama1`; Fedora — `mesa-libGL libX11 libXcursor libXi libXinerama`."
	textMusl        = "Графический интерфейс не запустится: система на musl (Alpine). Пользуйтесь консольной версией — она работает везде."
	// Подстановка в textCannotCheck — перечень названий признаков через
	// запятую; редакция ожидает подтверждения UI-01 (см. .ask, п. 1).
	textCannotCheck   = "Проверить не удалось: %s. Консольная версия работает независимо от этого."
	textNoGUIPlatform = "Графической версии для этой платформы нет. Пользуйтесь консольной версией — она работает везде."
	textSSHSession    = "Графическая сессия не найдена — так и должно быть при работе по SSH; графическую версию запускают на своём компьютере."
	textUnknown       = "определить не удалось"
)

// requiredLibs — ровно шесть SONAME, которые нужны релизному GUI (снято
// координатором с релизного бинаря v0.1.0). Порядок важен: в нём печатается
// список нехватающих. OSMesa в обязательные не входит — программная
// отрисовка не то, на что рассчитан релизный GUI.
var requiredLibs = []string{
	"libGL.so.1",
	"libEGL.so.1",
	"libX11.so.6",
	"libXcursor.so.1",
	"libXi.so.6",
	"libXinerama.so.1",
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
type Graphics struct {
	Known   bool
	Missing []string
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
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "PRETTY_NAME=") {
			continue
		}
		v := strings.TrimPrefix(line, "PRETTY_NAME=")
		v = strings.Trim(v, "\"'")
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

// parseLddVersion берёт номер версии из первой непустой строки
// `ldd --version`. Строка без номера версии — неудача способа, а не «musl»
// и не «нет». Строка с упоминанием musl тоже отвергается: ldd из musl
// печатает собственный номер версии, и принять его за glibc нельзя.
func parseLddVersion(out string) string {
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.Contains(strings.ToLower(line), "musl") {
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

// ldconfigLineRe — строка вида `имя.so.N (…) => /путь`. Если в выводе нет ни
// одной такой строки, способ 1 считается неудавшимся (вывод нераспознан), и
// «нет библиотек» из него не следует.
var ldconfigLineRe = regexp.MustCompile(`(?m)^\s*\S+\.so\.\d+\s+\([^)]*\)\s*=>\s*/`)

// detectGraphics: способ 1 — ldconfig -p, способ 2 — наличие файлов в
// известных каталогах. Провал обоих — «определить не удалось».
func detectGraphics(d Deps, goarcH string) Graphics {
	if out, err := d.Run("ldconfig", "-p"); err == nil && strings.TrimSpace(out) != "" && ldconfigLineRe.MatchString(out) {
		return Graphics{Known: true, Missing: missingIn(func(lib string) bool {
			return strings.Contains(out, lib)
		})}
	}

	var dirs []string
	for _, dir := range libDirs(goarcH) {
		if d.Exists(dir) {
			dirs = append(dirs, dir)
		}
	}
	if len(dirs) == 0 {
		// Ни списка, ни каталогов — мы просто не знаем. «Не хватает всех
		// шести» отсюда не следует.
		return Graphics{}
	}
	return Graphics{Known: true, Missing: missingIn(func(lib string) bool {
		for _, dir := range dirs {
			if d.Exists(dir + "/" + lib) {
				return true
			}
		}
		return false
	})}
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

func missingIn(found func(lib string) bool) []string {
	var missing []string
	for _, lib := range requiredLibs {
		if !found(lib) {
			missing = append(missing, lib)
		}
	}
	return missing
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
	if r.Graph.Known && len(r.Graph.Missing) > 0 {
		return fmt.Sprintf(textMissingLibs, strings.Join(r.Graph.Missing, ", "))
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
	if len(g.Missing) == 0 {
		return "все на месте"
	}
	return "не хватает: " + strings.Join(g.Missing, ", ")
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
