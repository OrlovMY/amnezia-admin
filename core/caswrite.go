package core

// A3б, PR-1 (проект БК-A3Б-ГОНКА-CAS.md, вариант В3): сверка и замена обоих
// файлов — ОДНА серверная команда под flock на хосте. Прежние отдельные
// `sha256sum` и `cat > P.tmp && mv` удалены: между ними успевал записать
// другой писатель, и его запись молча пропадала (окно 1); откат писал вслепую
// и стирал чужую запись (окно 2); общий P.tmp мог смешать две записи (окно 3);
// два файла менялись двумя командами (окно 4).
//
// Текст команды экспортирован (CASWriteScript, CASWriteCommand, CASWriteStdin),
// чтобы проверка в настоящих оболочках (PR-2) исполняла ровно его, а не копию.

import (
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// Метки фазы — $0 скрипта; различают две серверные команды в журналах.
const (
	CASLabelApply    = "amnezia-admin-apply"
	CASLabelRollback = "amnezia-admin-rollback"
)

// CASLockDir — замок записи: flock на КАТАЛОГЕ /run/lock, а не на файле в
// нём (аудит AU-LOGIC H1). Файл замка, созданный пользователем без sudo,
// root при fs.protected_regular (по умолчанию в Debian/Ubuntu) открыть с
// O_CREAT не может — flock давал 66 на каждой записи под sudo. Каталог
// /run/lock существует всегда (1777, root), открывается на чтение без
// O_CREAT и root, и любым пользователем. Косая черта в конце обязательна
// (повторный аудит AU-LOGIC): без неё при отсутствии каталога flock создал
// бы обычный ФАЙЛ /run/lock (root может) и сломал бы чужие замки до
// перезагрузки; с ней open(O_CREAT) на «каталог/» невозможен — flock
// выходит с 66 («замок не открыт — ничего не записано»). Ничего не
// создаётся ни от пользователя, ни от root — нет ни владельца, ни mkdir. Цена: замок общий для всех
// контейнеров хоста (запись в разные контейнеры идёт по очереди) и для
// любой программы, взявшей flock на /run/lock (такая займёт нас — исход
// «занято», не порча).
const CASLockDir = "/run/lock/"

// CASAbsent — ожидаемая «сумма» файла, которого не должно быть.
const CASAbsent = "absent"

// CASTempInfix — часть протокола: временные файлы записи называются
// <файл>.aa.<pid> в каталоге назначения, и под замком скрипт удаляет ВСЕ
// такие файлы (остатки убитых писателей). Другой инструмент не вправе
// создавать там файлы с этим именем.
const CASTempInfix = ".aa."

// Таймауты: внешний (на хосте) держит клиента flock/docker exec, внутренний
// (в контейнере) — сам скрипт. Внутренний меньше: скрипт умирает раньше,
// чем снимется замок, и запись не переживает замок (SEC R2).
//
// Внешний обязан быть больше, чем ожидание замка плюс внутренний (SEC R2'):
// иначе внешний убьёт flock, пока скрипт в контейнере ещё пишет, и замок
// снимется раньше записи. Запас — на запуск docker exec.
const (
	casLockWait     = 15
	casInnerTimeout = 50
	casOuterMargin  = 10
	casOuterTimeout = casLockWait + casInnerTimeout + casOuterMargin
)

// CASWriteScript — POSIX sh, исполняется в контейнере: sh -c СКРИПТ МЕТКА
// КАТАЛОГ СУММА_WG0 СУММА_ТАБЛИЦЫ; stdin — две строки base64 (wg0.conf,
// clientsTable). Одинарных кавычек в тексте нет (он сам в одинарных).
//
// Коды выхода — закрытый список (casOutcomeOf): 0 записано; 3 файл изменён
// другим, ничего не записано; 5 нет утилиты, ничего не записано; 6 wg0.conf
// уже заменён, clientsTable — нет (частичная запись). 4 — код flock (-E 4):
// замок занят. Любой иной код — «неизвестно, записано ли».
//
// umask 077 — временные файлы, а после mv и сами wg0.conf/clientsTable,
// получают 0600 (в wg0.conf приватный ключ сервера).
//
// Причина отказа mv (A3б PR-3, замечание QA) выводится в stderr с меткой
// «not moved: <файл>: …»: при частичной записи человек обязан узнать, почему
// clientsTable не заменена. Прежде stderr mv глушился, чтобы слово «denied»
// после записи не вызвало повтор под sudo; теперь повтор решает
// casDeniedBeforeWrite, и строка с меткой «not moved:» для неё — признак
// того, что скрипт уже шёл, то есть отказ НЕ «до записи» (SEC F1).
//
// Строка wg0.conf "-" — «не менять wg0.conf» (rename и т.п.): сверка идёт,
// файл не переписывается. "-" не входит в алфавит base64.
//
// read, а не head -c: head на канале читает с запасом и съел бы начало
// второй строки; read в POSIX sh читает по байту.
const CASWriteScript = `umask 077
d=$1; ww=$2; wt=$3
for t in sha256sum base64 mv rm; do command -v "$t" >/dev/null 2>&1 || { echo "missing tool: $t" >&2; exit 5; }; done
nw="$d/wg0.conf` + CASTempInfix + `$$"; nt="$d/clientsTable` + CASTempInfix + `$$"
rm -f "$d"/wg0.conf` + CASTempInfix + `* "$d"/clientsTable` + CASTempInfix + `* || exit 1
IFS= read -r W || exit 1
IFS= read -r T || exit 1
if [ "$W" != "-" ]; then printf %s "$W" | base64 -d > "$nw" || { rm -f "$nw"; exit 1; }; fi
printf %s "$T" | base64 -d > "$nt" || { rm -f "$nw" "$nt"; exit 1; }
hsum() { if [ -e "$1" ]; then s=$(sha256sum < "$1") || return 1; echo "${s%% *}"; else echo absent; fi; }
hw=$(hsum "$d/wg0.conf") || { rm -f "$nw" "$nt"; exit 1; }
ht=$(hsum "$d/clientsTable") || { rm -f "$nw" "$nt"; exit 1; }
if [ "$hw" != "$ww" ]; then rm -f "$nw" "$nt"; echo "changed: wg0.conf" >&2; exit 3; fi
if [ "$ht" != "$wt" ]; then rm -f "$nw" "$nt"; echo "changed: clientsTable" >&2; exit 3; fi
if [ "$W" != "-" ]; then e=$(mv -f "$nw" "$d/wg0.conf" 2>&1) || { rm -f "$nw" "$nt"; echo "not moved: wg0.conf: $e" >&2; exit 1; }; fi
e=$(mv -f "$nt" "$d/clientsTable" 2>&1) || { rm -f "$nt"; echo "not moved: clientsTable: $e" >&2; [ "$W" = "-" ] && exit 1; exit 6; }
exit 0`

var (
	reCASName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]*$`)
	reCASDir  = regexp.MustCompile(`^/[A-Za-z0-9_./-]+$`)
	reCASSum  = regexp.MustCompile(`^([0-9a-f]{64}|absent)$`)
)

// CASWriteCommand собирает серверную команду записи: замок на хосте
// (flock на каталоге CASLockDir), ожидание замка casLockWait, вся команда —
// не дольше casOuterTimeout. Аргументы проверяются до сборки: в текст
// команды не может попасть ничего, кроме имени, пути и сумм.
func CASWriteCommand(label, container, dir, wantWg, wantTbl string) (string, error) {
	return casWriteCommand(label, container, dir, wantWg, wantTbl, false)
}

// CASWriteCommandSudo — та же команда для повтора под sudo (AU-LOGIC PR-4,
// H1): sudo стоит ВНУТРИ замка, прямо перед docker — `… flock … /run/lock/
// sudo -n docker exec …`. sudo сверяет sudoers с ПЕРВОЙ программой после
// себя; прежний повтор `sudo timeout … flock … docker …` требовал права на
// timeout и отказывал пользователю с `NOPASSWD: docker`, которому v0.2.0
// (`sudo docker exec …`) писать позволял. timeout и flock идут от
// пользователя: замок на каталоге открывается без прав. `-n` — sudo не ждёт
// пароль внутри замка, а сразу отказывает.
func CASWriteCommandSudo(label, container, dir, wantWg, wantTbl string) (string, error) {
	return casWriteCommand(label, container, dir, wantWg, wantTbl, true)
}

func casWriteCommand(label, container, dir, wantWg, wantTbl string, sudo bool) (string, error) {
	if label != CASLabelApply && label != CASLabelRollback {
		return "", fmt.Errorf("недопустимая метка записи %q", label)
	}
	if !reCASName.MatchString(container) {
		return "", fmt.Errorf("недопустимое имя контейнера %q", container)
	}
	if !reCASDir.MatchString(dir) {
		return "", fmt.Errorf("недопустимый каталог %q", dir)
	}
	if !reCASSum.MatchString(wantWg) || !reCASSum.MatchString(wantTbl) {
		return "", fmt.Errorf("недопустимая контрольная сумма")
	}
	docker := "docker"
	if sudo {
		docker = "sudo -n docker"
	}
	return fmt.Sprintf("timeout %d flock -w %d -E 4 %s %s exec -i %s timeout %d sh -c '%s' %s %s %s %s",
		casOuterTimeout, casLockWait, CASLockDir, docker, container, casInnerTimeout, CASWriteScript, label, dir, wantWg, wantTbl), nil
}

// CASWriteStdin — stdin команды: две строки base64; wg == nil — "-", то есть
// wg0.conf не переписывать.
func CASWriteStdin(wg, tbl []byte) []byte {
	w := "-"
	if wg != nil {
		w = base64.StdEncoding.EncodeToString(wg)
	}
	return []byte(w + "\n" + base64.StdEncoding.EncodeToString(tbl) + "\n")
}

// ErrServerBusy — замок на сервере держит другая копия программы; ничего не
// записано.
var ErrServerBusy = errors.New("сервер занят другой копией программы")

// ErrServerToolMissing — на сервере нет нужной утилиты; ничего не записано.
var ErrServerToolMissing = errors.New("на сервере нет нужной утилиты")

// ErrWriteUnknown — неизвестно, записано ли: код выхода вне закрытого списка
// или не получен вовсе. Это не успех и не «не записано».
var ErrWriteUnknown = errors.New("неизвестно, записаны ли изменения")

// ErrSudoDenied — sudo отказал запустить docker (нет права или нужен
// пароль); docker exec не запускался, ничего не записано.
var ErrSudoDenied = errors.New("sudo не разрешил запуск docker")

// ErrRollbackForeign — откат не выполнен: после нашей записи файлы изменил
// кто-то другой, и откат стёр бы его изменения.
var ErrRollbackForeign = errors.New("откат не выполнен: после нашей записи файлы изменил другой")

// ErrWriteNotStarted — запись не начиналась (резервная копия не создана,
// команда не собрана): ничего не записано, повтор безвреден (A3б PR-3,
// раунд 4 — закрытый список исходов пути Apply).
var ErrWriteNotStarted = errors.New("запись не начиналась")

// notStarted — обёртка «запись не начиналась» с исходной причиной.
type notStarted struct{ err error }

func (n notStarted) Error() string   { return n.err.Error() }
func (n notStarted) Unwrap() []error { return []error{ErrWriteNotStarted, n.err} }

// ErrLockUnavailable — замок записи /run/lock/ не открылся (код 66 flock);
// docker exec не запускался, ничего не записано. Частный случай
// ErrServerToolMissing (errors.Is верно для обоих): выделен, чтобы человеку
// сказать о замке, а не о недостающей утилите (A3б PR-3).
var ErrLockUnavailable = errors.New("не открыт замок записи на сервере")

// ErrWritePartial — записано частично: wg0.conf заменён, clientsTable — нет
// (код 6). Частный случай ErrWriteUnknown (errors.Is верно для обоих):
// состояние сервера для плана — «неизвестно», но что именно записано,
// известно, и человеку это говорится (A3б PR-3).
var ErrWritePartial = errors.New("записано частично")

type casOutcome int

const (
	casWritten casOutcome = iota
	casChanged
	casBusy
	casToolMissing
	casPartial
	casLockOpen
	casSudoDenied
	casUnknown
)

// casOutcomeOf — закрытый список кодов выхода. 6 — частичная запись: для
// человека это «неизвестно» (ErrWriteUnknown), но с названием, что именно
// записано. 127 — «команда не найдена»
// оболочкой (нет timeout/flock на хосте или sh в контейнере): до записи дело
// не дошло, поэтому это тоже «нет утилиты». Всё прочее, включая ошибку без
// кода выхода (обрыв связи) и 124 (timeout), — «неизвестно».
func casOutcomeOf(err error) (casOutcome, int) {
	if err == nil {
		return casWritten, 0
	}
	var es interface{ ExitStatus() int }
	if !errors.As(err, &es) {
		return casUnknown, -1
	}
	switch code := es.ExitStatus(); code {
	case 3:
		return casChanged, code
	case 4:
		return casBusy, code
	case 5, 127:
		return casToolMissing, code
	case 66:
		// flock: не открыт файл замка — docker exec не запускался.
		return casLockOpen, code
	case 6:
		return casPartial, code
	default:
		return casUnknown, code
	}
}

// casWriteError — исход записи, отличный от «записано». Error() печатает
// только msg (текст команды со скриптом человеку не нужен); причина — через
// Unwrap.
type casWriteError struct {
	outcome casOutcome
	msg     string
	cause   error
}

func (e *casWriteError) Error() string { return e.msg }
func (e *casWriteError) Unwrap() error { return e.cause }

func (e *casWriteError) Is(target error) bool {
	switch e.outcome {
	case casChanged:
		return target == ErrCASMismatch
	case casBusy:
		return target == ErrServerBusy
	case casToolMissing:
		return target == ErrServerToolMissing
	case casLockOpen:
		return target == ErrServerToolMissing || target == ErrLockUnavailable
	case casSudoDenied:
		return target == ErrSudoDenied
	case casPartial:
		return target == ErrWriteUnknown || target == ErrWritePartial
	case casUnknown:
		return target == ErrWriteUnknown
	}
	return false
}

var (
	reCASChanged = regexp.MustCompile(`changed: (wg0\.conf|clientsTable)`)
	reCASMissing = regexp.MustCompile(`missing tool: (\S+)`)
)

// casDeniedBeforeWrite — отказ docker в доступе к своему сокету: docker exec
// не запускался, значит скрипт не начинался и записи не было.
func casDeniedBeforeWrite(err error) bool {
	if err == nil {
		return false
	}
	// Только stderr: текст ошибки sshRunner начинается с САМОЙ команды, а в
	// ней — текст скрипта с меткой «not moved: »; по всему тексту признак не
	// срабатывал никогда (слияние H1, найдено моделью канарейки PR4.2).
	s := strings.ToLower(stderrTail(err))
	if strings.Contains(s, "not moved: ") {
		return false // скрипт уже шёл и дошёл до mv — отказ после начала записи
	}
	return strings.Contains(s, "permission denied") &&
		(strings.Contains(s, "docker.sock") || strings.Contains(s, "docker daemon socket"))
}

// reSudoDenied — ЗАКРЫТЫЙ список сообщений sudo об отказе (sudo 1.9, язык
// C/английский). Код 1 при повторе под sudo — общий и для sudo, и для
// скрипта; отличить отказ sudo можно только по его тексту. Сообщения
// скрипта начинаются с «changed:», «missing tool:», сообщения docker — с
// «Error»/«docker:», строки «sudo:» или «Sorry, user» не даёт никто, кроме
// sudo. Текст на другом языке (sudo переводит по LANG сервера) в список не
// попадёт — тогда исход остаётся «неизвестно», в осторожную сторону.
var reSudoDenied = regexp.MustCompile(`sudo: a password is required|sudo: a terminal is required|` +
	`Sorry, user \S+ is not allowed to execute|I'm afraid I can't do that|is not in the sudoers file`)

// casSudoRefused — повтор под sudo отказан самим sudo (код 1 и его текст).
func casSudoRefused(err error) bool {
	var es interface{ ExitStatus() int }
	return err != nil && errors.As(err, &es) && es.ExitStatus() == 1 && reSudoDenied.MatchString(stderrTail(err))
}

// sudoersUser — имя пользователя для подсказки строки sudoers: настоящее,
// если оно из безопасного набора символов, иначе заглушка (имя попадает в
// текст, который человек копирует в sudoers).
func sudoersUser(c *ServerCreds) string {
	if c != nil && reSudoersUser.MatchString(c.User) {
		return c.User
	}
	return "<пользователь>"
}

var reSudoersUser = regexp.MustCompile(`^[a-z_][a-z0-9_.-]{0,31}$`)

// stderrTail — хвост после последнего "stderr: " (формат sshRunner и fakesrv).
func stderrTail(err error) string {
	s := err.Error()
	if i := strings.LastIndex(s, "stderr: "); i >= 0 {
		s = s[i+len("stderr: "):]
	}
	s = strings.TrimSpace(s)
	if len(s) > 300 {
		s = s[:300] + "…"
	}
	return s
}

// casWrite заменяет оба файла, только если их текущие суммы равны
// wantWg/wantTbl. nil — записано; иначе *casWriteError с исходом.
func (s *Session) casWrite(c *Container, label, wantWg, wantTbl string, wg, tbl []byte) error {
	cmd, err := CASWriteCommand(label, c.Name, c.Dir, wantWg, wantTbl)
	if err != nil {
		return fmt.Errorf("запись не выполнена: %w", notStarted{err})
	}
	stdin := CASWriteStdin(wg, tbl)
	// Не через s.docker (SEC F1): общий фолбэк повторяет под sudo любую
	// команду со словом «denied», в том числе после частичной записи, и
	// повтор отвечал «изменил другой». Здесь под sudo повторяем, только если
	// отказ точно случился до записи — docker не пустил к своему сокету.
	_, runErr := s.run(cmd, stdin)
	sudoRefused := false
	if casDeniedBeforeWrite(runErr) {
		sudoCmd, err := CASWriteCommandSudo(label, c.Name, c.Dir, wantWg, wantTbl)
		if err != nil {
			return fmt.Errorf("запись не выполнена: %w", err)
		}
		_, runErr = s.run(sudoCmd, stdin)
		sudoRefused = casSudoRefused(runErr)
	}
	outcome, code := casOutcomeOf(runErr)
	if sudoRefused {
		outcome = casSudoDenied
	}
	switch outcome {
	case casWritten:
		return nil
	case casChanged:
		file := "wg0.conf или clientsTable" // какой — неизвестно (SEC F2)
		if m := reCASChanged.FindStringSubmatch(stderrTail(runErr)); m != nil {
			file = m[1]
		}
		return &casWriteError{outcome: outcome, cause: runErr,
			msg: fmt.Sprintf("файл %s/%s изменился с момента чтения — обновите список и повторите", c.Dir, file)}
	case casPartial:
		return &casWriteError{outcome: outcome, cause: runErr,
			msg: fmt.Sprintf("записано частично: wg0.conf заменён, clientsTable — нет (%s); обновите список, прежде чем повторять; резервные копии на сервере: %s/backup/", stderrTail(runErr), c.Dir)}
	case casBusy:
		// A3б PR-3 (Low аудита PR-1): замок может держать и посторонняя
		// программа, не только наша копия.
		return &casWriteError{outcome: outcome, cause: runErr,
			msg: fmt.Sprintf("запись на сервере занята (замок %s держит другой процесс, возможно, другая копия программы) — ничего не записано; повторите через минуту", CASLockDir)}
	case casSudoDenied:
		return &casWriteError{outcome: outcome, cause: runErr,
			msg: fmt.Sprintf("docker без sudo недоступен, а sudo не разрешил запустить docker (%s) — ничего не записано; для того, кто настраивал сервер: нужна строка sudoers «%s ALL=(root) NOPASSWD: /usr/bin/docker» (путь к docker — вывод command -v docker на сервере)", stderrTail(runErr), sudoersUser(s.Creds))}
	case casLockOpen:
		return &casWriteError{outcome: outcome, cause: runErr,
			msg: fmt.Sprintf("не удалось открыть замок %s (код 66: %s) — ничего не записано", CASLockDir, stderrTail(runErr))}
	case casToolMissing:
		tool := "timeout, flock, docker или sudo (на хосте) либо timeout или sh (в контейнере)"
		if m := reCASMissing.FindStringSubmatch(stderrTail(runErr)); m != nil {
			tool = m[1]
		}
		return &casWriteError{outcome: outcome, cause: runErr,
			msg: fmt.Sprintf("на сервере нет утилиты %s (код %d) — ничего не записано", tool, code)}
	}
	codeText := "код выхода не получен"
	if code >= 0 {
		codeText = fmt.Sprintf("код выхода %d", code)
	}
	return &casWriteError{outcome: casUnknown, cause: runErr,
		msg: fmt.Sprintf("неизвестно, записаны ли изменения (%s: %s) — обновите список, прежде чем повторять; резервные копии на сервере: %s/backup/", codeText, stderrTail(runErr), c.Dir)}
}

// isCASPartial — исход «записано частично» (код 6).
func isCASPartial(err error) bool {
	var ce *casWriteError
	return errors.As(err, &ce) && ce.outcome == casPartial
}
