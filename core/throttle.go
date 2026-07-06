// Файл throttle.go — простой персистентный throttle попыток ввода пина для
// vault-хранилища (.avlt): 10 неверных попыток подряд → блокировка на 5 минут.
// Хранится в открытом виде (throttle.json рядом с .avlt-файлами) — это
// намеренно НЕ криптографическая защита, только UX-ограничение перебора со
// стороны самой утилиты; порча или отсутствие файла не должны запирать
// пользователя (fail-open по доступности).
package core

import (
	"encoding/json"
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

// LoadThrottle читает состояние для vaultName (basename файла .avlt, например
// "a1b2c3d4.avlt") из throttle.json в каталоге dir. Отсутствие файла, битый
// JSON или отсутствие записи для vaultName — не ошибка, возвращается нулевое
// состояние (доступ не блокируется из-за порчи служебного файла).
func LoadThrottle(dir, vaultName string) ThrottleState {
	data, err := os.ReadFile(throttleFilePath(dir))
	if err != nil {
		return ThrottleState{}
	}
	var m map[string]ThrottleState
	if err := json.Unmarshal(data, &m); err != nil {
		return ThrottleState{}
	}
	return m[vaultName]
}

// SaveThrottle сохраняет состояние для vaultName, не трогая записи других
// vault-файлов в том же throttle.json. Запись атомарна (tmp+rename), права
// 0600 (файл содержит только счётчики/таймстамп, но не секреты — тем не менее
// незачем делать его мировидимым).
func SaveThrottle(dir, vaultName string, st ThrottleState) error {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	path := throttleFilePath(dir)
	m := map[string]ThrottleState{}
	if data, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(data, &m) // best-effort: битый существующий файл — начинаем с чистой карты
	}
	if m == nil {
		m = map[string]ThrottleState{}
	}
	m[vaultName] = st

	out, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, out, 0600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}
