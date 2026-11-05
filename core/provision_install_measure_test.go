package core

import "testing"

// TestMeasuredOfTable — сводка измерения: строк о контейнере нет — «не
// знаем», а не «совпало»; «не узнали» главнее «не совпало».
func TestMeasuredOfTable(t *testing.T) {
	row := func(st CompatState) CompatRow { return CompatRow{Container: "amnezia-awg2", State: st} }
	cases := []struct {
		rows []CompatRow
		want CompatState
	}{
		{nil, CompatUnknown},
		{[]CompatRow{{Container: "amnezia-xray", State: CompatMatch}}, CompatUnknown},
		{[]CompatRow{row(CompatMatch), row(CompatMatch)}, CompatMatch},
		{[]CompatRow{row(CompatMatch), row(CompatMismatch)}, CompatMismatch},
		{[]CompatRow{row(CompatMismatch), row(CompatUnknown)}, CompatUnknown},
	}
	for i, c := range cases {
		if got := measuredOf(&CompatReport{Rows: c.rows}, "amnezia-awg2"); got != c.want {
			t.Errorf("случай %d: %d, ждали %d", i, got, c.want)
		}
	}
}
