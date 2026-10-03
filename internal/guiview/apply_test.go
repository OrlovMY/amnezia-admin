package guiview

import (
	"errors"
	"testing"

	"amnezia-admin/core"
)

// TestApplyRetryAllowed — закрытый список повтора «Применить» (раунд 4,
// AU-LOGIC Н-1/Н-2). Различение: неклассифицированная ошибка и исходы, где
// что-то записано или неизвестно, — без повтора; повтор — только где запись
// доказанно не начиналась и план не устарел. Подмена «неклассифицированное →
// повтор» краснеет на первой строке таблицы.
func TestApplyRetryAllowed(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"неклассифицированное", errors.New("что-то ещё"), false},
		{"изменён другим", core.ErrCASMismatch, false},
		{"неизвестно", core.ErrWriteUnknown, false},
		{"откат не выполнен", errors.Join(core.ErrRollbackNotDone, core.ErrServerBusy), false},
		{"итог отката неизвестен", errors.Join(core.ErrRollbackUnknown, core.ErrWriteUnknown), false},
		{"отменено", core.ErrRolledBack, false},
		{"занято", core.ErrServerBusy, true},
		{"нет утилиты", core.ErrServerToolMissing, true},
		{"замок", errors.Join(core.ErrLockUnavailable, core.ErrServerToolMissing), true},
		{"запись не начиналась", core.ErrWriteNotStarted, true},
	}
	for _, c := range cases {
		if got := ApplyRetryAllowed(c.err); got != c.want {
			t.Errorf("%s: повтор = %v, ожидалось %v", c.name, got, c.want)
		}
	}
}
