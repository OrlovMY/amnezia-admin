package canary

import (
	"strings"
	"testing"

	"amnezia-admin/core"
)

// TestSelectWG — канарейка обходит все контейнеры семейства WG; -container
// выбирает один; нет ни одного — «НЕ ПРОВЕРЕНО» с перечнем найденного.
func TestSelectWG(t *testing.T) {
	cs := []core.Container{
		{Name: "amnezia-xray", Proto: "XRay"},
		{Name: "amnezia-awg2", Dir: "/opt/amnezia/awg", Proto: "awg2"},
		{Name: "amnezia-awg", Dir: "/opt/amnezia/awg", Proto: "AmneziaWG"},
	}
	sel, why := SelectWG(cs, "")
	if len(sel) != 2 || sel[0].Name != "amnezia-awg2" || sel[1].Name != "amnezia-awg" || why != "" {
		t.Errorf("все: %+v %q", sel, why)
	}
	sel, _ = SelectWG(cs, "amnezia-awg2")
	if len(sel) != 1 || sel[0].Name != "amnezia-awg2" {
		t.Errorf("-container amnezia-awg2: %+v", sel)
	}
	for _, c := range []struct {
		cs   []core.Container
		only string
		want string
	}{
		{cs[:1], "", "на сервере нет протокола семейства WG"},
		{cs, "amnezia-wireguard", "контейнера amnezia-wireguard семейства WG на сервере нет"},
		{cs, "amnezia-xray", "контейнера amnezia-xray семейства WG на сервере нет"},
	} {
		sel, why := SelectWG(c.cs, c.only)
		if len(sel) != 0 || !strings.HasPrefix(why, "НЕ ПРОВЕРЕНО: ") || !strings.Contains(why, c.want) || !strings.Contains(why, "amnezia-xray (XRay)") {
			t.Errorf("%q: %+v %q", c.only, sel, why)
		}
	}
}

// TestTable — итог «шаг × контейнер», «—» — шаг на контейнере не шёл.
func TestTable(t *testing.T) {
	per := map[string][]Result{
		"amnezia-awg":  {{ID: "К4", Name: "гонка", Status: Pass}, {ID: "К7", Name: "v0.2.0", Status: Pass}},
		"amnezia-awg2": {{ID: "К4", Name: "гонка", Status: NotChecked}, {ID: "К7", Name: "v0.2.0", Status: NotApplicable}, {ID: "К8", Name: "awg2", Status: Fail}},
	}
	got := Table([]string{"amnezia-awg", "amnezia-awg2"}, per)
	want := "шаг | amnezia-awg | amnezia-awg2\n" +
		"К4 гонка | ПРОЙДЕН | НЕ ПРОВЕРЕНО\n" +
		"К7 v0.2.0 | ПРОЙДЕН | НЕ ПРИМЕНИМО\n" +
		"К8 awg2 | — | НЕ ПРОЙДЕН\n"
	if got != want {
		t.Errorf("таблица:\n%s\nждали:\n%s", got, want)
	}
}
