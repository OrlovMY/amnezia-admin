package core

import (
	"strings"
	"testing"

	"amnezia-admin/core/provision"
)

// TestPlanInstallFallbackNamed — ревью-1 M1/M2: откат на не первую ревизию
// называет отвергнутую и причину; разные отказы — разный текст. Свежая
// подошла — об откате ни слова.
func TestPlanInstallFallbackNamed(t *testing.T) {
	b := &Backup{Containers: []BackupContainer{wgCtr("amnezia-awg2", "2", VersionKnown)}}
	noData := PlanInstall(b, []string{"нет-такой", provision.RevDev94b51df}).Items[0]
	if noData.Compat != CompatMatch || !strings.Contains(noData.Reason, "нет-такой: нет данных о семействе") ||
		!strings.Contains(noData.Reason, sourceRevisionNote) {
		t.Errorf("откат из-за «нет данных» не назван: %q", noData.Reason)
	}
	// Отказ по существу (Partial): у 1.5 обе ревизии — Partial; текст иной,
	// чем «нет данных».
	b15 := &Backup{Containers: []BackupContainer{wgCtr("amnezia-awg2", "1.5", VersionKnown)}}
	partial := PlanInstall(b15, nil).Items[0]
	if !strings.Contains(partial.Reason, provision.Rev5106+": "+provision.SupportPartial.String()) ||
		strings.Contains(partial.Reason, "нет данных") {
		t.Errorf("Partial не назван: %q", partial.Reason)
	}
	// Откат «Partial у свежей, ставит у старой» в нынешней таблице
	// недостижим (1.5 — Partial в обеих); третий вид отказа — чужой контейнер.
	other := PlanInstall(&Backup{Containers: []BackupContainer{wgCtr("amnezia-wireguard", "2", VersionKnown)}}, nil).Items[0]
	if !strings.Contains(other.Reason, "ставит amnezia-awg2, а не amnezia-wireguard") || other.Reason == partial.Reason {
		t.Errorf("чужой контейнер: %q", other.Reason)
	}
	fresh := PlanInstall(b, nil).Items[0]
	if strings.Contains(fresh.Reason, "не самая свежая") {
		t.Errorf("свежая подошла, а сказано об откате: %q", fresh.Reason)
	}
}

// TestInstallVerdictNotBareMatch — ревью-1 L1: Match с NeedsMeasurement не
// печатается голым «совпало».
func TestInstallVerdictNotBareMatch(t *testing.T) {
	b := &Backup{Containers: []BackupContainer{wgCtr("amnezia-awg2", "2", VersionKnown)}}
	it := PlanInstall(b, nil).Items[0]
	if !it.NeedsMeasurement || it.Verdict() == "совпало" ||
		!strings.Contains(it.Verdict(), "версия бинаря не закреплена и не измеряется") {
		t.Errorf("вердикт %q при NeedsMeasurement=%v", it.Verdict(), it.NeedsMeasurement)
	}
	if v := (InstallItem{Compat: CompatMatch}).Verdict(); v != "совпало" {
		t.Errorf("закреплённый Match: %q", v)
	}
	if (InstallItem{}).Verdict() != "нет данных" || (InstallItem{Compat: CompatMismatch}).Verdict() == "нет данных" {
		t.Error("нулевой вердикт не «нет данных» или Mismatch совпал с ним")
	}
}
