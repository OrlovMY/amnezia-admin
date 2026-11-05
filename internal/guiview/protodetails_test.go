package guiview

import (
	"strings"
	"testing"

	"amnezia-admin/core"
)

// TestDetailTextThreeStates — «не удалось узнать» отличается и от значения,
// и от «не применяется»; ни одно состояние не печатается пустым или нулём.
func TestDetailTextThreeStates(t *testing.T) {
	for _, c := range []struct {
		f    core.DetailField
		want string
	}{
		{core.DetailField{State: core.DetailKnown, Value: "51820"}, "51820"},
		{core.DetailField{State: core.DetailKnown}, "не удалось узнать (значение пустое)"},
		{core.DetailField{State: core.DetailNotApplies, Reason: "у XRay нет подсети"}, "не применяется (у XRay нет подсети)"},
		{core.DetailField{State: core.DetailUnknown, Reason: "файла wg0.conf нет"}, "не удалось узнать: файла wg0.conf нет"},
		{core.DetailField{}, "не удалось узнать"},
	} {
		if got := DetailText(c.f); got != c.want {
			t.Errorf("%+v: %q, ждали %q", c.f, got, c.want)
		}
	}
	txt := ProtoDetailsText(core.ProtoDetails{})
	if strings.Count(txt, "не удалось узнать") != 6 || strings.Contains(txt, ": \n") || strings.HasSuffix(txt, ": ") || strings.Contains(txt, ": 0") {
		t.Errorf("пустые подробности напечатаны не как «не удалось узнать»:\n%s", txt)
	}
}
