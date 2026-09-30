// Файл throttle.go — простой персистентный throttle попыток ввода пина для
// vault-хранилища (.avlt): 10 неверных попыток подряд → блокировка на 5 минут.
// Хранится в открытом виде (throttle.json рядом с .avlt-файлами) — это
// намеренно НЕ криптографическая защита, только UX-ограничение перебора со
// стороны самой утилиты.
//
// Отсутствие файла — штатно: ноль попыток. Файл есть, но прочитать или
// разобрать его не удалось, или записать не удалось — СОСТОЯНИЕ НЕИЗВЕСТНО
// (долг Н8, решение SEC-01 30.09.2026): функции возвращают ошибку, и ввод
// пина закрыт, пока это не исправлено (fail-closed). Прежде битый файл
// читался как ноль попыток — то есть сбрасывал блокировку (признак 2
// CLAUDE.md), — а ошибка записи отбрасывалась.
//
// ГРАНИЦЫ (что счётчик НЕ ограничивает, названо сознательно):
//   - удаление или откат throttle.json — у кого есть доступ к файлам
//     пользователя, у того и сам .avlt, и перебор он ведёт вне программы;
//   - несколько запущенных экземпляров программы (раунд 4 долгов, AU-LOGIC
//     М-2, решение ядра — не чинить): чтение-изменение-запись без блокировки
//     между процессами, две одновременные неверные попытки из двух окон
//     могут учесться как одна, K окон дают около 10·K попыток до блокировки.
//     Кто может запускать программу, тот имеет и .avlt; ключ защищает
//     медленное получение ключа из пина (argon2id, core/vault.go), а счётчик —
//     лишь ограничение попыток через интерфейс одного окна.
package core

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"
)

// ThrottleState — состояние счётчика неудачных попыток для одного vault-файла
type ThrottleState struct {
	Fails        int       `json:"fails"`
	BlockedUntil time.Time `json:"blockedUntil"`
}

const (
	throttleMaxFails = 10
	throttleBlockDur = 5 * time.Minute
)

// CheckThrottle сообщает, заблокированы ли попытки на момент now, и сколько
// времени остаётся до снятия блокировки.
func CheckThrottle(st ThrottleState, now time.Time) (blocked bool, remaining time.Duration) {
	if now.Before(st.BlockedUntil) {
		return true, st.BlockedUntil.Sub(now)
	}
	return false, 0
}

// RegisterFailure увеличивает счётчик неудач; при достижении
// throttleMaxFails выставляет блокировку на throttleBlockDur и обнуляет
// счётчик (следующий цикл из 10 попыток начнётся заново после разблокировки).
func RegisterFailure(st ThrottleState, now time.Time) ThrottleState {
	st.Fails++
	if st.Fails >= throttleMaxFails {
		st.BlockedUntil = now.Add(throttleBlockDur)
		st.Fails = 0
	}
	return st
}

// RegisterSuccess — успешный ввод пина полностью сбрасывает состояние.
func RegisterSuccess() ThrottleState {
	return ThrottleState{}
}

func throttleFilePath(dir string) string {
	return filepath.Join(dir, "throttle.json")
}

// ThrottleError — счётчик попыток не удалось прочитать или записать. Путь и
// причина — отдельными полями, чтобы интерфейс назвал их человеку прямо, не
// повторяя путь дважды (ошибки os уже содержат путь).
//
// Path — путь, на котором операция РЕАЛЬНО не удалась (раунд 4 долгов,
// AU-LOGIC Н-1): при сбое записи временного throttle.json.tmp это он, а не
// throttle.json, которого в этот момент может не быть вовсе. Fault — что с
// этим путём, чтобы совет человеку был по сути: «удалите» — только если
// файл есть и повреждён.
type ThrottleError struct {
	Op    string // "прочитать" или "сохранить"
	Path  string
	Err   error
	Fault ThrottleFault
}

// ThrottleFault — что не так с путём из ThrottleError.
type ThrottleFault int

const (
	// FaultOther — иная причина (например, нет папки, диск недоступен).
	FaultOther ThrottleFault = iota
	// FaultCorrupt — файл есть, прочитан, но содержимое не разбирается.
	FaultCorrupt
	// FaultIsDir — на месте файла папка.
	FaultIsDir
	// FaultDenied — нет прав.
	FaultDenied
)

// newThrottleError — ошибка с путём неудавшейся операции и её разбором.
func newThrottleError(op, path string, err error, corrupt bool) *ThrottleError {
	e := &ThrottleError{Op: op, Path: path, Err: err}
	switch {
	case corrupt:
		e.Fault = FaultCorrupt
	case isDir(path):
		e.Fault = FaultIsDir
	case errors.Is(err, fs.ErrPermission):
		e.Fault = FaultDenied
	}
	return e
}

func isDir(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && fi.IsDir()
}

func (e *ThrottleError) Error() string {
	return fmt.Sprintf("не удалось %s счётчик попыток %s: %s", e.Op, e.Path, e.Reason())
}

func (e *ThrottleError) Unwrap() error { return e.Err }

// Reason — причина без пути (у *os.PathError путь уже есть в Path).
func (e *ThrottleError) Reason() string {
	if e.Err == nil {
		return "причина неизвестна"
	}
	var pe *os.PathError
	if errors.As(e.Err, &pe) {
		return pe.Err.Error()
	}
	var le *os.LinkError
	if errors.As(e.Err, &le) {
		return le.Err.Error()
	}
	return e.Err.Error()
}

// readThrottleMap — ТРИ ИСХОДА: файла нет (пустая карта, nil); прочитан
// (карта, nil); есть, но не читается или не разбирается (nil, ошибка).
func readThrottleMap(path string) (map[string]ThrottleState, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return map[string]ThrottleState{}, nil
	}
	if err != nil {
		return nil, newThrottleError("прочитать", path, err, false)
	}
	var m map[string]ThrottleState
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, newThrottleError("прочитать", path, fmt.Errorf("файл повреждён (%v)", err), true)
	}
	if m == nil { // в файле буквально null
		m = map[string]ThrottleState{}
	}
	return m, nil
}

// LoadThrottle читает состояние для vaultName (basename файла .avlt, например
// "a1b2c3d4.avlt") из throttle.json в каталоге dir. Нет файла или записи для
// vaultName — нулевое состояние без ошибки (попыток не было). Файл есть, но
// не читается или повреждён — *ThrottleError: сколько попыток израсходовано,
// неизвестно, и ноль здесь был бы выдумкой, снимающей ограничение.
func LoadThrottle(dir, vaultName string) (ThrottleState, error) {
	m, err := readThrottleMap(throttleFilePath(dir))
	if err != nil {
		return ThrottleState{}, err
	}
	return m[vaultName], nil
}

// SaveThrottle сохраняет состояние для vaultName, не трогая записи других
// vault-файлов в том же throttle.json. Запись атомарна (tmp+rename), права
// 0600. Повреждённый существующий файл НЕ перезаписывается молча: в нём могли
// быть счётчики других хранилищ, и молчаливая замена сбросила бы их.
func SaveThrottle(dir, vaultName string, st ThrottleState) error {
	path := throttleFilePath(dir)
	// wrap — с путём, на котором не удалось (Н-1): каталог, .tmp или сам файл.
	wrap := func(at string, err error) error { return newThrottleError("сохранить", at, err, false) }
	if err := os.MkdirAll(dir, 0755); err != nil {
		return wrap(dir, err)
	}
	m, err := readThrottleMap(path)
	if err != nil {
		return err
	}
	m[vaultName] = st

	out, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return wrap(path, err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, out, 0600); err != nil {
		return wrap(tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return wrap(path, err)
	}
	return nil
}
