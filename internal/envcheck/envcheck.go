// Пакет envcheck отвечает на вопрос «запустится ли графическая версия на
// этой машине» — до того, как человек попробует её запустить.
//
// Почему проверку печатает консольная версия, а не графическая: при
// отсутствии libGL динамический компоновщик убивает процесс GUI ДО первой
// строки Go-кода, поэтому ни init(), ни начало main() в GUI не выполнятся —
// диагностику обязан печатать статический CLI.
//
// Пакет не импортирует ничего, кроме стандартной библиотеки (ни Fyne, ни
// CGO), и все обращения к ОС идёт через подставляемые зависимости Deps —
// чтобы случаи Alpine/Fedora/«нет ldconfig» воспроизводились в тестах на
// машине разработчика (Windows).
//
// Главное правило пакета: «определить не удалось» НИКОГДА не превращается в
// «нет». Не нашли список библиотек — это не «библиотек нет».
package envcheck

import "io"

// Тексты для человека — дословно из задания (UI-01): не пересказывать и не
// «улучшать». Любая правка этих строк — правка эталонов теста дословности.
const (
	textHeader        = "Проверка окружения"
	textWillRun       = "Графический интерфейс запустится."
	textMissingLibs   = "Графический интерфейс не запустится: не хватает библиотек — %s. Установите их: Debian/Ubuntu — `libgl1 libx11-6 libxcursor1 libxi6 libxinerama1`; Fedora — `mesa-libGL libX11 libXcursor libXi libXinerama`."
	textMusl          = "Графический интерфейс не запустится: система на musl (Alpine). Пользуйтесь консольной версией — она работает везде."
	textCannotCheck   = "Проверить не удалось: %s. Консольная версия работает независимо от этого."
	textNoGUIPlatform = "Графической версии для этой платформы нет. Пользуйтесь консольной версией — она работает везде."
	textSSHSession    = "Графическая сессия не найдена — так и должно быть при работе по SSH; графическую версию запускают на своём компьютере."
	textUnknown       = "определить не удалось"
)

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
// неудача: по SSH сессии нет закономерно.
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
func OSDeps() Deps { return Deps{} }

// Detect — чистая функция: никаких обращений к ОС мимо d.
func Detect(d Deps) Result { return Result{} }

// detect — то же, что Detect, но с явными ОС, архитектурой и чтением
// переменных окружения: иначе случаи darwin/amd64 и linux не проверить на
// машине разработчика, где GOOS всегда windows.
func detect(d Deps, goos, goarch string, getenv func(string) string) Result {
	return Result{}
}

// verdict — итоговая строка (ровно одна из пяти формулировок).
func verdict(r Result) string { return "" }

// Report печатает строки для человека.
func Report(r Result, w io.Writer) {}
