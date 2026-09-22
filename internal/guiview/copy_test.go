package guiview

import (
	"strings"
	"testing"

	"amnezia-admin/core"
)

// Таблица копирования (GUI-КОПИРОВАНИЕ). Главный случай здесь — НЕ «обычная
// строка», а строки, в которых чего-то не знают: «статистику получить не
// удалось» обязано отличаться от «статистики не спрашивали» и от «нулевого
// трафика», и отличаться ОДИНАКОВО на экране и в буфере обмена.

// sample — строка со всеми заполненными данными.
func sample() Row {
	return Row{
		Num:       3,
		Name:      "Ноутбук",
		Created:   "2026-09-22T12:34:56.789Z",
		ClientID:  "aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789+/aBcD1=",
		CanManage: true,
		Handshake: "2 минуты назад",
		Stats:     core.PeerStat{RxBytes: 1200000, TxBytes: 900000},
	}
}

func TestCellTextTable(t *testing.T) {
	cases := []struct {
		name string
		row  Row
		col  int
		want string
	}{
		{"номер", sample(), 0, "3"},
		{"имя", sample(), 1, "Ноутбук"},
		{"дата обрезана до 19 знаков", sample(), 2, "2026-09-22T12:34:5"[:18] + "6"},
		{"активность", sample(), 3, "2 минуты назад"},
		{"ключ целиком", sample(), 5, sample().ClientID},
		{"колонки вне диапазона", sample(), 6, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := CellText(c.row, c.col); got != c.want {
				t.Errorf("CellText(col=%d) = %q, ожидалось %q", c.col, got, c.want)
			}
		})
	}
}

// TestCopyKeepsUnknownUnknown — ТЕСТ РАЗЛИЧЕНИЯ: три состояния трафика и
// активности в БУФЕРЕ ОБМЕНА различны. Вставленная в переписку строка не
// имеет права превратить «узнать не удалось» в измеренный ноль.
func TestCopyKeepsUnknownUnknown(t *testing.T) {
	notAsked := sample()
	notAsked.CanManage = false

	failed := sample()
	failed.StatsFailed = true
	failed.ActivityFailed = true

	zero := sample()
	zero.Stats = core.PeerStat{}
	zero.Handshake = "—"

	traffic := map[string]string{
		"не спрашивали": CopyValue(notAsked, 4),
		"не удалось":    CopyValue(failed, 4),
		"измеренный 0":  CopyValue(zero, 4),
	}
	if traffic["не удалось"] == traffic["измеренный 0"] {
		t.Errorf("трафик: «узнать не удалось» копируется как измеренное значение (%q) — "+
			"ровно тот дефект, ради которого написан A1", traffic["не удалось"])
	}
	if traffic["не удалось"] == traffic["не спрашивали"] {
		t.Errorf("трафик: «не удалось» и «не спрашивали» копируются одинаково (%q)", traffic["не удалось"])
	}
	if traffic["не удалось"] != "?" {
		t.Errorf("трафик при неудавшемся запросе копируется как %q, ожидалось \"?\" — "+
			"то же, что видно в таблице", traffic["не удалось"])
	}
	if strings.Contains(traffic["не удалось"], "B") {
		t.Errorf("трафик при неудавшемся запросе копируется с единицами измерения (%q) — "+
			"в переписку уедет число, которого никто не измерял", traffic["не удалось"])
	}

	act := map[string]string{
		"не спрашивали": CopyValue(notAsked, 3),
		"не удалось":    CopyValue(failed, 3),
		"не подключался": CopyValue(func() Row {
			r := sample()
			r.Handshake = "—"
			return r
		}(), 3),
	}
	if act["не удалось"] == act["не подключался"] {
		t.Errorf("активность: «узнать не удалось» копируется как «не подключался» (%q)", act["не удалось"])
	}
	if act["не удалось"] == act["не спрашивали"] {
		t.Errorf("активность: «не удалось» и «не спрашивали» копируются одинаково (%q)", act["не удалось"])
	}
}

// TestCopyValueIsFullValue — копируется ПОЛНОЕ значение, даже если в ячейке
// оно обрезано. Отличие ровно одно и оно здесь названо: дата создания.
func TestCopyValueIsFullValue(t *testing.T) {
	r := sample()
	if got, want := CopyValue(r, 2), r.Created; got != want {
		t.Errorf("CopyValue(«Создан») = %q, ожидалось полное %q", got, want)
	}
	if CellText(r, 2) == CopyValue(r, 2) {
		t.Errorf("ячейка и буфер совпали (%q) — значит либо ячейка перестала обрезать дату, "+
			"либо в буфер уходит обрезок; таблицу ожиданий надо приводить в соответствие",
			CellText(r, 2))
	}
	if got, want := CopyValue(r, 5), r.ClientID; got != want || len(got) != 44 {
		t.Errorf("CopyValue(«Публичный ключ») = %q (%d знаков), ожидался ключ целиком (44)", got, len(got))
	}
	// Остальные колонки в буфере совпадают с видимым.
	for _, col := range []int{0, 1, 3, 4, 5} {
		if CopyValue(r, col) != CellText(r, col) {
			t.Errorf("колонка %d: в буфер уходит не то, что видно (%q против %q)",
				col, CopyValue(r, col), CellText(r, col))
		}
	}
}

// TestCopyRowFormat — строка целиком: одна строка, все колонки, ничего
// сверх видимого в таблице.
func TestCopyRowFormat(t *testing.T) {
	r := sample()
	got := CopyRow(r)
	want := "3 | Ноутбук | 2026-09-22T12:34:56.789Z | 2 минуты назад | 1.2 MB / 900.0 KB | " + r.ClientID
	if got != want {
		t.Errorf("CopyRow() =\n%q\nожидалось\n%q", got, want)
	}
	if strings.ContainsAny(got, "\n\r\t") {
		t.Errorf("CopyRow() содержит перевод строки или табуляцию: %q — вставка в переписку развалится", got)
	}
	if n := len(strings.Split(got, RowSeparator)); n != CopyColumnCount {
		t.Errorf("CopyRow() даёт %d полей вместо %d колонок таблицы", n, CopyColumnCount)
	}
	// Полный ключ обязан быть в строке целиком — ради этого весь пункт.
	if !strings.Contains(got, r.ClientID) {
		t.Errorf("CopyRow() не содержит полного ключа: %q", got)
	}
}

// TestCopyRowUnknownStaysUnknown — та же проверка различения для «строки
// целиком»: ветвление живёт в CopyValue, но пункт меню человек нажимает
// этот, и он обязан быть проверен отдельно.
func TestCopyRowUnknownStaysUnknown(t *testing.T) {
	failed := sample()
	failed.StatsFailed = true
	zero := sample()
	zero.Stats = core.PeerStat{}
	if CopyRow(failed) == CopyRow(zero) {
		t.Errorf("строка целиком: «статистику получить не удалось» неотличима от нулевого трафика: %q",
			CopyRow(failed))
	}
	if !strings.Contains(CopyRow(failed), RowSeparator+"?"+RowSeparator) {
		t.Errorf("строка целиком при неудавшемся запросе не содержит «?» отдельным полем: %q", CopyRow(failed))
	}
}
