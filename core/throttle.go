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
package core

import (
	"encoding/json"
	"errors"
	"fmt"
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
type ThrottleError struct {
	Op   string // "прочитать" или "сохранить"
	Path string
	Err  error
}

func (e *ThrottleError) Error() string {
	return fmt.Sprintf("не удалось %s счётчик попыток %s: %s", e.Op, e.Path, e.Reason())
}

func (e *ThrottleError) Unwrap() error { return e.Err }

// Reason — причина без пути (у *os.PathError путь уже есть в Path).
func (e *ThrottleError) Reason() string {
	var pe *os.PathError
	if errors.As(e.Err, &pe) {
		return pe.Err.Error()
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
		return nil, &ThrottleError{Op: "прочитать", Path: path, Err: err}
	}
	var m map[string]ThrottleState
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, &ThrottleError{Op: "прочитать", Path: path,
			Err: fmt.Errorf("файл повреждён (%v)", err)}
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
	wrap := func(err error) error { return &ThrottleError{Op: "сохранить", Path: path, Err: err} }
	if err := os.MkdirAll(dir, 0755); err != nil {
		return wrap(err)
	}
	m, err := readThrottleMap(path)
	if err != nil {
		return err
	}
	m[vaultName] = st

	out, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return wrap(err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, out, 0600); err != nil {
		return wrap(err)
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return wrap(err)
	}
	return nil
}
