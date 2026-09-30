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

// CASAbsent — ожидаемая «сумма» файла, которого не должно быть.
const CASAbsent = "absent"

// CASWriteScript — POSIX sh, исполняется в контейнере: sh -c СКРИПТ МЕТКА
// КАТАЛОГ СУММА_WG0 СУММА_ТАБЛИЦЫ; stdin — две строки base64 (wg0.conf,
// clientsTable). Одинарных кавычек в тексте нет (он сам в одинарных).
//
// Коды выхода — закрытый список (casOutcomeOf): 0 записано; 3 файл изменён
// другим, ничего не записано; 5 нет утилиты, ничего не записано. 4 — код
// flock (-E 4): замок занят. Любой иной код — «неизвестно, записано ли».
//
// Строка wg0.conf "-" — «не менять wg0.conf» (rename и т.п.): сверка идёт,
// файл не переписывается. "-" не входит в алфавит base64.
//
// read, а не head -c: head на канале читает с запасом и съел бы начало
// второй строки; read в POSIX sh читает по байту.
const CASWriteScript = `d=$1; ww=$2; wt=$3
for t in sha256sum base64 mv rm; do command -v "$t" >/dev/null 2>&1 || { echo "missing tool: $t" >&2; exit 5; }; done
nw="$d/wg0.conf.aa.$$"; nt="$d/clientsTable.aa.$$"
rm -f "$d"/wg0.conf.aa.* "$d"/clientsTable.aa.* || exit 1
IFS= read -r W || exit 1
IFS= read -r T || exit 1
if [ "$W" != "-" ]; then printf %s "$W" | base64 -d > "$nw" || { rm -f "$nw"; exit 1; }; fi
printf %s "$T" | base64 -d > "$nt" || { rm -f "$nw" "$nt"; exit 1; }
hsum() { if [ -e "$1" ]; then s=$(sha256sum < "$1") || return 1; echo "${s%% *}"; else echo absent; fi; }
hw=$(hsum "$d/wg0.conf") || { rm -f "$nw" "$nt"; exit 1; }
ht=$(hsum "$d/clientsTable") || { rm -f "$nw" "$nt"; exit 1; }
if [ "$hw" != "$ww" ]; then rm -f "$nw" "$nt"; echo "changed: wg0.conf" >&2; exit 3; fi
if [ "$ht" != "$wt" ]; then rm -f "$nw" "$nt"; echo "changed: clientsTable" >&2; exit 3; fi
if [ "$W" != "-" ]; then mv -f "$nw" "$d/wg0.conf" || exit 1; fi
mv -f "$nt" "$d/clientsTable" || exit 1
exit 0`

var (
	reCASName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]*$`)
	reCASDir  = regexp.MustCompile(`^/[A-Za-z0-9_./-]+$`)
	reCASSum  = regexp.MustCompile(`^([0-9a-f]{64}|absent)$`)
)

// CASWriteCommand собирает серверную команду записи: замок на хосте
// (/run/lock, файл на каждый контейнер), ожидание замка 15 с, вся команда —
// не дольше 60 с. Аргументы проверяются до сборки: в текст команды не может
// попасть ничего, кроме имени, пути и сумм.
func CASWriteCommand(label, container, dir, wantWg, wantTbl string) (string, error) {
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
	return fmt.Sprintf("timeout 60 flock -w 15 -E 4 /run/lock/amnezia-admin.%s.lock docker exec -i %s sh -c '%s' %s %s %s %s",
		container, container, CASWriteScript, label, dir, wantWg, wantTbl), nil
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

// ErrRollbackForeign — откат не выполнен: после нашей записи файлы изменил
// кто-то другой, и откат стёр бы его изменения.
var ErrRollbackForeign = errors.New("откат не выполнен: после нашей записи файлы изменил другой")

type casOutcome int

const (
	casWritten casOutcome = iota
	casChanged
	casBusy
	casToolMissing
	casUnknown
)

// casOutcomeOf — закрытый список кодов выхода. 127 — «команда не найдена»
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
	case casUnknown:
		return target == ErrWriteUnknown
	}
	return false
}

var (
	reCASChanged = regexp.MustCompile(`changed: (wg0\.conf|clientsTable)`)
	reCASMissing = regexp.MustCompile(`missing tool: (\S+)`)
)

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
		return fmt.Errorf("запись не выполнена: %w", err)
	}
	_, runErr := s.docker(cmd, CASWriteStdin(wg, tbl))
	outcome, code := casOutcomeOf(runErr)
	switch outcome {
	case casWritten:
		return nil
	case casChanged:
		file := "wg0.conf"
		if m := reCASChanged.FindStringSubmatch(stderrTail(runErr)); m != nil {
			file = m[1]
		}
		return &casWriteError{outcome: outcome, cause: runErr,
			msg: fmt.Sprintf("файл %s изменился с момента чтения — обновите список и повторите", c.Dir+"/"+file)}
	case casBusy:
		return &casWriteError{outcome: outcome, cause: runErr,
			msg: "сервер занят другой копией программы — ничего не записано; повторите через минуту"}
	case casToolMissing:
		tool := "timeout, flock или sh"
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
