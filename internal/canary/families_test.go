package canary

import (
	"errors"
	"strings"
	"testing"
)

// TestRequiredFamilies — QA W1, находка 4: «только awg» — НЕ ПРОВЕРЕНО
// (amnezia-awg2 не исполнялся вживую); «только awg + -skip-family
// amnezia-awg2» — ПРОЙДЕН ЧАСТИЧНО первой строкой (AU-LOGIC M-1); оба найдены — ПРОЙДЕН без
// пометки; amnezia-wireguard не обязателен, но назван.
func TestRequiredFamilies(t *testing.T) {
	steps := []Result{{ID: "К3", Status: Pass}}
	for _, c := range []struct {
		name          string
		sel, skip     []string
		want          Status
		loud, missing bool
	}{
		{"только awg", []string{"amnezia-awg"}, nil, NotChecked, false, true},
		{"только awg + skip awg2", []string{"amnezia-awg"}, []string{"amnezia-awg2"}, PassPartial, true, false},
		{"awg и awg2", []string{"amnezia-awg", "amnezia-awg2"}, nil, Pass, false, false},
		{"только awg2", []string{"amnezia-awg2"}, nil, NotChecked, false, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			rows, skipped, notes, err := FamilyPlan(c.sel, c.skip)
			if err != nil {
				t.Fatal(err)
			}
			if (len(rows) > 0) != c.missing {
				t.Errorf("шаги ненайденных семейств: %+v", rows)
			}
			st, line := FinalSummary(append(append([]Result{}, steps...), rows...), nil, skipped)
			if st != c.want {
				t.Errorf("итог %s, ждали %s: %s", st, c.want, line)
			}
			// AU-LOGIC M-1: частичность — в ПЕРВОЙ строке итога, не во второй
			first := strings.SplitN(line, "\n", 2)[0]
			if got := strings.HasPrefix(first, "ИТОГ: ПРОЙДЕН ЧАСТИЧНО — без живой проверки: amnezia-awg2"); got != c.loud {
				t.Errorf("строка «без живой проверки» = %v, ждали %v: %s", got, c.loud, line)
			}
			wg := false
			for _, n := range notes {
				wg = wg || strings.Contains(n, "amnezia-wireguard")
			}
			if !wg {
				t.Errorf("необязательный amnezia-wireguard не назван: %v", notes)
			}
		})
	}
	for _, skip := range [][]string{{"amnezia-xray"}, {"amnezia-awg"}} {
		if _, _, _, err := FamilyPlan([]string{"amnezia-awg"}, skip); err == nil {
			t.Errorf("-skip-family %v: ждали отказ", skip)
		}
	}
}

// TestMountsCheck — SEC W-R2: общий каталог хоста — СТОП (НЕ ПРОЙДЕН);
// отказ inspect или неразобранный ответ — НЕ ПРОВЕРЕНО; разные каталоги или
// их нет — ПРОЙДЕН; одного контейнера нет — НЕ ПРИМЕНИМО.
func TestMountsCheck(t *testing.T) {
	both := []string{"amnezia-awg", "amnezia-awg2", "amnezia-xray"}
	for _, c := range []struct {
		name  string
		names []string
		out   string
		err   error
		want  Status
	}{
		{"общий каталог", both, `/amnezia-awg [{"Type":"bind","Source":"/srv/awg","Destination":"/opt/amnezia/awg"}]` + "\n" +
			`/amnezia-awg2 [{"Type":"bind","Source":"/srv/awg","Destination":"/opt/amnezia/awg/"}]`, nil, Fail},
		{"разные каталоги", both, `/amnezia-awg [{"Source":"/srv/a","Destination":"/opt/amnezia/awg"}]` + "\n" +
			`/amnezia-awg2 [{"Source":"/srv/b","Destination":"/opt/amnezia/awg"}]`, nil, Pass},
		{"монтирований нет", both, "/amnezia-awg []\n/amnezia-awg2 []\n", nil, Pass},
		{"inspect упал", both, "Error: No such object", errors.New("exit status 1"), NotChecked},
		{"ответ не разобран", both, "/amnezia-awg [{\n/amnezia-awg2 []", nil, NotChecked},
		{"один контейнер в ответе", both, "/amnezia-awg []", nil, NotChecked},
		{"нет amnezia-awg2", []string{"amnezia-awg"}, "", nil, NotApplicable},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := MountsCheck(func(string) (string, error) { return c.out, c.err }, c.names)
			if r.Status != c.want {
				t.Errorf("%s (%s), ждали %s", r.Status, r.Detail, c.want)
			}
		})
	}
}

// TestPartialNotPass — AU-LOGIC M-1: частичный итог не равен ПРОЙДЕН ни
// статусом, ни кодом выхода; провал при пропуске остаётся провалом.
func TestPartialNotPass(t *testing.T) {
	for _, c := range []struct {
		name string
		rs   []Result
		skip []string
		want Status
		code int
	}{
		{"всё пройдено, без пропуска", []Result{{Status: Pass}}, nil, Pass, 0},
		{"всё пройдено, пропуск", []Result{{Status: Pass}}, []string{"amnezia-awg2"}, PassPartial, 3},
		{"провал и пропуск", []Result{{Status: Pass}, {Status: Fail}}, []string{"amnezia-awg2"}, Fail, 1},
		{"не проверено и пропуск", []Result{{Status: Pass}, {Status: NotChecked}}, []string{"amnezia-awg2"}, NotChecked, 1},
	} {
		st, line := FinalSummary(c.rs, nil, c.skip)
		if st != c.want || ExitCode(st) != c.code {
			t.Errorf("%s: %s, код %d (ждали %s, %d): %s", c.name, st, ExitCode(st), c.want, c.code, line)
		}
		if st == PassPartial && strings.HasPrefix(line, "ИТОГ: ПРОЙДЕН (") {
			t.Errorf("%s: частичный итог начинается как полный: %s", c.name, line)
		}
	}
}
