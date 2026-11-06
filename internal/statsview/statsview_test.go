package statsview

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"amnezia-admin/core"
)

// Подмены, обязанные ронять эти тесты: «нет данных → 0 B» в CellText,
// Compare без ранга исходов, CSV с нулём на месте «нет данных».

const day0 = int64(20400)

// testLog — Alice: измерено; Bob: измеренный ноль; Carl: неполные; Abe
// (KD=) — в данных нет.
func testLog() *core.TrafficLog {
	hs := core.DayStart(day0).Add(10 * time.Hour).Unix()
	daily := fmt.Sprintf("D 1 %d amnezia-awg KA= 3000 5000 %d 5\n", day0, hs) +
		fmt.Sprintf("D 1 %d amnezia-awg KB= 0 0 0 5\n", day0) +
		fmt.Sprintf("D 1 %d amnezia-awg KC= 100000 1 0 5 1\n", day0) +
		fmt.Sprintf("N 1 %d amnezia-awg 5\n", day0)
	return core.ParseTrafficLog(daily, true, "", false)
}

var awg = core.Container{Name: "amnezia-awg", Dir: "/opt/amnezia/awg", Proto: "AmneziaWG", Support: core.SupportYes}

func testRows(l *core.TrafficLog) []Row {
	cl := func(id, n string) core.ClientEntry {
		return core.ClientEntry{ClientID: id, UserData: map[string]any{"clientName": n}}
	}
	rows, _ := Rows([]ContainerClients{{C: awg, Read: true, Clients: []core.ClientEntry{
		cl("KD=", "Abe"), cl("KB=", "Bob"), cl("KA=", "Alice"), cl("KC=", "Carl")}}}, l)
	return rows
}

func cellOf(t *testing.T, l *core.TrafficLog, r core.DayRange, pub string) core.TrafficCell {
	t.Helper()
	return l.Cell(core.TrafficKey{Container: "amnezia-awg", PubKey: pub}, r, core.CollectorInstalled)
}

// TestCellTextThreeStates — различение (табличный случай «данных нет»
// отличается от измеренного нуля) и доезд: ячейка «нет данных» получена из
// разбора журнала, а не присваиванием.
func TestCellTextThreeStates(t *testing.T) {
	l := testLog()
	cases := []struct {
		pub  string
		want [4]string
	}{
		{"KA=", [4]string{"3.0 KB", "5.0 KB", "8.0 KB", "2025-11-08 10:00"}},
		{"KB=", [4]string{"0 B", "0 B", "0 B", "не подключался"}},
		{"KC=", [4]string{"≥ 100.0 KB", "≥ 1 B", "≥ 100.0 KB", "не подключался"}},
		{"KD=", [4]string{"нет данных", "нет данных", "нет данных", "нет данных"}},
	}
	for _, c := range cases {
		cell := cellOf(t, l, core.AllTime, c.pub)
		got := [4]string{CellText(cell, Rx), CellText(cell, Tx), CellText(cell, Total), SeenText(cell)}
		if got != c.want {
			t.Errorf("%s: %q, ждали %q", c.pub, got, c.want)
		}
	}
	// Период без снимков: у измеренного раньше клиента — «нет данных».
	if got := CellText(cellOf(t, l, core.DayRange{From: day0 + 5, To: day0 + 9}, "KB="), Total); got != "нет данных" {
		t.Errorf("Bob вне периода: %q", got)
	}
	// Сборщик не установлен и данных нет — не ноль и не «нет данных».
	empty := core.ParseTrafficLog("", false, "", false)
	if got := CellText(empty.Cell(core.TrafficKey{Container: "amnezia-awg", PubKey: "KA="}, core.AllTime, core.CollectorNotInstalled), Total); got != "не собиралось" {
		t.Errorf("не установлен: %q", got)
	}
	if got := CellText(empty.Cell(core.TrafficKey{}, core.AllTime, core.CollectorUnknown), Total); got != "?" {
		t.Errorf("неизвестно: %q", got)
	}
}

// TestCompareRanksFixed — «нет данных» ниже нуля, «≥» между, в любом
// столбце и направлении.
func TestCompareRanksFixed(t *testing.T) {
	l := testLog()
	a, b, c, d := cellOf(t, l, core.AllTime, "KA="), cellOf(t, l, core.AllTime, "KB="), cellOf(t, l, core.AllTime, "KC="), cellOf(t, l, core.AllTime, "KD=")
	for _, col := range []Col{ColRx, ColTx, ColTotal, ColSeen} {
		for _, desc := range []bool{true, false} {
			for _, m := range []core.TrafficCell{a, b} {
				if Compare(m, c, col, desc) >= 0 || Compare(c, m, col, desc) <= 0 {
					t.Errorf("col %d desc=%v: измеренное не выше «≥»", col, desc)
				}
				if Compare(m, d, col, desc) >= 0 {
					t.Errorf("col %d desc=%v: измеренное не выше «нет данных»", col, desc)
				}
			}
			if Compare(c, d, col, desc) >= 0 {
				t.Errorf("col %d desc=%v: «≥» не выше «нет данных»", col, desc)
			}
		}
	}
	if Compare(a, b, ColTotal, true) >= 0 || Compare(a, b, ColTotal, false) <= 0 {
		t.Error("направление внутри измеренных не работает")
	}
	// Порядок CLI.
	rows := testRows(l)
	cells := map[core.TrafficKey]core.TrafficCell{}
	for _, r := range rows {
		cells[r.Key] = l.Cell(r.Key, core.AllTime, core.CollectorInstalled)
	}
	SortByTotal(rows, cells)
	var names []string
	for _, r := range rows {
		names = append(names, r.Name)
	}
	if got := strings.Join(names, ","); got != "Alice,Bob,Carl,Abe" {
		t.Errorf("порядок: %s", got)
	}
}

// TestCollectorTextStates — все исходы различимы; «неизвестно» не
// выдаётся ни за «не установлен», ни за «работает».
func TestCollectorTextStates(t *testing.T) {
	h := Hints{Install: "X"}
	next := time.Date(2026, 11, 6, 14, 35, 0, 0, time.UTC)
	cases := []struct {
		st   core.CollectorStatus
		want string
	}{
		{core.CollectorStatus{State: core.CollectorInstalled, Collect: core.CollectWorking, SnapshotAge: 3 * time.Minute}, "сбор работает (последний снимок 3 мин назад"},
		{core.CollectorStatus{State: core.CollectorInstalled, Collect: core.CollectPending, NextRun: next}, "ожидается до 14:35 UTC"},
		{core.CollectorStatus{State: core.CollectorInstalled, Collect: core.CollectPending}, "время срабатывания таймера неизвестно"},
		{core.CollectorStatus{State: core.CollectorInstalled, Collect: core.CollectStopped, CollectWhy: "упала"}, "НЕ работает: упала"},
		{core.CollectorStatus{State: core.CollectorInstalled, Collect: core.CollectUnknown, CollectWhy: "молчит"}, "неизвестно: молчит"},
		{core.CollectorStatus{State: core.CollectorNotInstalled}, "не установлен (установить: X)"},
		{core.CollectorStatus{State: core.CollectorPartial, Detail: []string{"нет таймера"}}, "не полностью или другой версии: нет таймера (переустановить: X)"},
		{core.CollectorStatus{Err: errors.New("ssh: обрыв")}, "узнать не удалось: ssh: обрыв"},
		{core.CollectorStatus{}, "узнать не удалось: причина неизвестна"},
	}
	for _, c := range cases {
		if got := CollectorText(c.st, h); !strings.Contains(got, c.want) {
			t.Errorf("%+v: %q, ждали %q", c.st, got, c.want)
		}
	}
}

// TestCSVNoDataEmptyNotZero — «нет данных» в CSV: пустые цифры и слово.
func TestCSVNoDataEmptyNotZero(t *testing.T) {
	l := testLog()
	data, n, err := CSV(testRows(l), l, core.CollectorInstalled, Periods(l, core.AllTime, "за всё время", ""))
	if err != nil || n != 4 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	s := string(data)
	for _, want := range []string{
		UTF8BOM + "Период;Протокол;Клиент;Публичный ключ;Принято, байт;Отправлено, байт;Всего, байт;Последнее подключение (UTC);Состояние\r\n",
		"за всё время;AmneziaWG;Abe;KD=;;;;;нет данных\r\n",
		"за всё время;AmneziaWG;Bob;KB=;0;0;0;;измерено\r\n",
		"за всё время;AmneziaWG;Alice;KA=;3000;5000;8000;2025-11-08 10:00;измерено\r\n",
		"за всё время;AmneziaWG;Carl;KC=;100000;1;100001;;неполные (не меньше)\r\n",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("нет %q в\n%s", want, s)
		}
	}
	if CSVSafe("=1+1") != "'=1+1" || CSVSafe("+AB=") != "'+AB=" || CSVSafe("Ёж") != "Ёж" {
		t.Error("CSVSafe")
	}
	if ps := Periods(l, core.AllTime, "x", "month"); len(ps) != 1 || ps[0].Name != "2025-11" {
		t.Errorf("по месяцам: %+v", ps)
	}
}

// TestDataNotesLevels — пометки о неполноте — предупреждения, не обычный
// текст (CLI красит их, GUI ставит ⚠).
func TestDataNotesLevels(t *testing.T) {
	l := testLog()
	ns := DataNotes(l, core.AllTime)
	var partial bool
	for _, n := range ns {
		if strings.Contains(n.Text, "помечены «≥»") {
			partial = n.Level == Warn
		}
	}
	if !partial {
		t.Errorf("пометка о «≥» не предупреждение: %+v", ns)
	}
	ns = DataNotes(l, core.DayRange{From: day0 + 1, To: day0 + 2})
	if len(ns) == 0 || !strings.Contains(ns[0].Text, "Учтённых интервалов за период нет") {
		t.Errorf("пустой период: %+v", ns)
	}
}
