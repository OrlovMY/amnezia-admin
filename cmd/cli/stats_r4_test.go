package main

// Раунд 4: Н4 (ожидание первого снимка), Н6 (≥ по периоду).

import (
	"strings"
	"testing"
	"time"

	"amnezia-admin/core"
)

func TestStatusPendingText(t *testing.T) {
	at := time.Date(2026, 11, 5, 12, 35, 0, 0, time.UTC)
	got := collectorText(core.CollectorStatus{State: core.CollectorInstalled, Collect: core.CollectPending, NextRun: at})
	if !strings.Contains(got, "первый снимок ожидается до 12:35 UTC") || strings.Contains(got, "НЕ работает") {
		t.Errorf("с временем: %q", got)
	}
	got = collectorText(core.CollectorStatus{State: core.CollectorInstalled, Collect: core.CollectPending})
	if !strings.Contains(got, "первый снимок ожидается") || strings.Contains(got, "НЕ работает") || strings.Contains(got, "до ") {
		t.Errorf("без времени: %q", got)
	}
}

// TestStatsPartialNoteByPeriod — Н6: пометка о «≥» — только если такие
// интервалы есть в выбранном периоде.
func TestStatsPartialNoteByPeriod(t *testing.T) {
	d := tDay * 86400
	raw := "H v1 0\n" +
		tBlk(d, "amnezia-awg", "KB= 900 900 0") +
		tBlk(d+4000, "amnezia-awg", "KB= 1 1 0") + // ≥ в сутках tDay
		tBlk(d+5*86400, "amnezia-awg", "KB= 5 5 0") +
		tBlk(d+5*86400+300, "amnezia-awg", "KB= 9 9 0")
	f := sampleStats()
	f.log = core.ParseTrafficLog("", false, raw, true)
	out, _ := showLines(t, f, statsFlags{})
	if !strings.Contains(out, "помечены «≥»") {
		t.Errorf("за всё время пометки нет:\n%s", out)
	}
	out, _ = showLines(t, f, statsFlags{from: "2024-10-09"})
	if strings.Contains(out, "помечены «≥»") || strings.Contains(out, "≥ ") {
		t.Errorf("в периоде без ≥ есть пометка:\n%s", out)
	}
}
