package guiview

import "amnezia-admin/internal/writeoutcome"

// ApplyStatus — строка статуса окна «Изменения перед применением» после
// исхода записи (A3б PR-3): заголовок исхода и что делать. Если повтор того
// же плана недопустим (кнопка «Применить» остаётся выключенной), добавлено,
// что окно нужно закрыть: действие из совета («обновите список») делается
// в главном окне.
func ApplyStatus(t writeoutcome.Text) string {
	s := t.Title + ". " + t.Next
	if !t.Retry {
		s += " Закройте это окно кнопкой «Закрыть»."
	}
	return s
}

// ApplyRetryAllowed — снова ли включать «Применить» после ошибки sess.Apply:
// только если исход в закрытом списке повтора writeoutcome (запись
// доказанно не начиналась, план не устарел). Неклассифицированная ошибка —
// НЕТ: неизвестно, записано ли (A3б PR-3, раунд 4, AU-LOGIC Н-1/Н-2).
func ApplyRetryAllowed(err error) bool {
	t, ok := writeoutcome.Describe(err)
	return ok && t.Retry
}
