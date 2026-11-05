package core

// Раунд 4 — дополнение аудита AU-1 к 127ff74: Н4 (до первого запуска —
// «ожидается», а не «не работает»), Н6 (≥-интервалы по периоду).

import (
	"fmt"
	"strings"
	"testing"
)

// withUnit — вывод статуса без журнала, с полями systemctl show в
// настоящем формате.
func withUnit(result, active, execMono, next string) string {
	out := statusOut("active", result, active, 1_800_000_000, "-")
	extra := "ExecMainStartTimestampMonotonic=" + execMono + "\n"
	if next != "" {
		extra += "NextElapseUSecRealtime=" + next + "\n"
	}
	return strings.Replace(out, "AA_STATUS_END\n", extra+"AA_STATUS_END\n", 1)
}

// TestCollectPending — тест различения: журнала нет; служба не
// запускалась / запущена впервые сейчас — «ожидается»; служба отработала
// success — «не работает».
func TestCollectPending(t *testing.T) {
	cases := []struct {
		name string
		out  string
		want CollectState
		next string
	}{
		{"не запускалась, время UTC", withUnit("success", "inactive", "0", "Thu 2026-11-05 12:35:00 UTC"), CollectPending, "12:35"},
		{"не запускалась, время @unix", withUnit("success", "inactive", "0", "@1800000300"), CollectPending, "08:05"},
		{"не запускалась, пояс не UTC — без времени", withUnit("success", "inactive", "0", "Thu 2026-11-05 15:35:00 MSK"), CollectPending, ""},
		{"первый запуск идёт", withUnit("success", "activating", "123456", ""), CollectPending, ""},
		{"отработала, журнала нет", withUnit("success", "inactive", "123456", "Thu 2026-11-05 12:35:00 UTC"), CollectStopped, ""},
		{"не запускалась, но упала?", withUnit("exit-code", "failed", "123456", ""), CollectStopped, ""},
	}
	for _, c := range cases {
		st := parseCollectorStatus(c.out)
		if st.Collect != c.want {
			t.Errorf("%s: %v %q, ждали %v", c.name, st.Collect, st.CollectWhy, c.want)
			continue
		}
		got := ""
		if !st.NextRun.IsZero() {
			got = st.NextRun.UTC().Format("15:04")
		}
		if c.want == CollectPending && got != c.next {
			t.Errorf("%s: время %q, ждали %q", c.name, got, c.next)
		}
	}
}

// TestCollectPendingReaches — доезд через Session.StatsStatus.
func TestCollectPendingReaches(t *testing.T) {
	s := NewSessionWithRunner(statusRunner{withUnit("success", "inactive", "0", "Thu 2026-11-05 12:35:00 UTC")}, &ServerCreds{Host: "h", User: "root"})
	if st := s.StatsStatus(); st.Collect != CollectPending || st.NextRun.IsZero() {
		t.Errorf("сразу после установки: %v %v", st.Collect, st.NextRun)
	}
}

func TestPartialInPeriod(t *testing.T) {
	daily := fmt.Sprintf("D 1 %d amnezia-awg A 10 10 0 1 1\nD 1 %d amnezia-awg A 10 10 0 1 0\n", day0, day0+5)
	l := ParseTrafficLog(daily, true, "", false)
	if l.PartialIn(DayRange{day0 + 5, day0 + 5}) != 0 || l.PartialIn(AllTime) != 1 {
		t.Errorf("≥-интервалы по периоду: %d / %d", l.PartialIn(DayRange{day0 + 5, day0 + 5}), l.PartialIn(AllTime))
	}
}
