package core

import "testing"

// TestRollbackOutcomeTableComplete — сторож таблицы исходов отката (раунд 6,
// AU-LOGIC Н-5): ровно 9 клеток, каждая заполнена; «сервер нужно
// перезапустить» (NotApplied) — ТОЛЬКО в клетке «файлы совпали × рантайм не
// совпал»; «отменено и проверено» — только «совпали × совпал»; при файлах
// «не совпали» — только FilesDiffer, при «неизвестно» — только Unverified.
func TestRollbackOutcomeTableComplete(t *testing.T) {
	fileStates := []checkState{checkSame, checkDiffer, checkUnknown}
	runtimeStates := []checkState{checkSame, checkDiffer, checkUnknown, checkNotNeeded}
	if len(rollbackOutcome) != 12 {
		t.Fatalf("клеток %d, должно быть ровно 12", len(rollbackOutcome))
	}
	for _, f := range fileStates {
		for _, r := range runtimeStates {
			got, ok := rollbackOutcome[rollbackCell{f, r}]
			if !ok || got == nil {
				t.Errorf("клетка (файлы %d, рантайм %d) пуста", f, r)
				continue
			}
			var want error
			switch {
			case f == checkSame && (r == checkSame || r == checkNotNeeded):
				want = ErrRolledBack
			case f == checkSame && r == checkDiffer:
				want = ErrRolledBackNotApplied
			case f == checkDiffer:
				want = ErrRolledBackFilesDiffer
			default:
				want = ErrRollbackUnverified
			}
			if got != want {
				t.Errorf("клетка (файлы %d, рантайм %d): %v, ожидалось %v", f, r, got, want)
			}
		}
	}
}
