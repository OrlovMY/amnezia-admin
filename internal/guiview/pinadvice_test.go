package guiview

import (
	"errors"
	"strings"
	"testing"

	"amnezia-admin/core"
)

// TestPinThrottleAdviceByFault — раунд 5 долгов (AU-LOGIC М-5, пункт 1):
// совет в диалоге закрытого пина — по сути разбора. «Удалите его, он
// повреждён» — ТОЛЬКО у повреждённого файла; ни «иное», ни «нет прав», ни
// «папка» его не получают. Подмена аудитора (`case core.FaultCorrupt,
// core.FaultOther:`) роняет тест.
func TestPinThrottleAdviceByFault(t *testing.T) {
	const corruptAdvice = "удалите его, он повреждён"
	cases := []struct {
		fault core.ThrottleFault
		want  string
	}{
		{core.FaultCorrupt, corruptAdvice},
		{core.FaultIsDir, "на месте файла — папка, переименуйте или удалите её"},
		{core.FaultDenied, "у программы нет прав на него"},
		{core.FaultOther, "проверьте, доступна ли папка программы для записи"},
	}
	for _, c := range cases {
		text := PinThrottleUnknown(&core.ThrottleError{Op: "прочитать", Path: `C:\x\throttle.json`,
			Err: errors.New("причина"), Fault: c.fault})
		if !strings.Contains(text, c.want) {
			t.Errorf("разбор %d: нет совета %q: %q", c.fault, c.want, text)
		}
		if c.fault != core.FaultCorrupt && strings.Contains(text, corruptAdvice) {
			t.Errorf("разбор %d: совет «удалите, он повреждён» не по сути: %q", c.fault, text)
		}
	}
}
