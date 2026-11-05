package core

import (
	"strings"
	"testing"

	"amnezia-admin/core/provision"
	"amnezia-admin/internal/fakesrv"
)

// TestPlanInstallEmptyPrefs — аудит AU-1 M1: пустой (не nil) список ревизий
// — «не проверена ни одна», Unknown, а не Mismatch. Отличие от Mismatch по
// существу (1.5 при списке по умолчанию) — в той же таблице.
func TestPlanInstallEmptyPrefs(t *testing.T) {
	for _, fam := range []string{"2", "1.5"} {
		b := &Backup{Containers: []BackupContainer{wgCtr("amnezia-awg2", fam, VersionKnown)}}
		if it := PlanInstall(b, []string{}).Items[0]; it.Compat != CompatUnknown || !strings.Contains(it.Reason, "не проверена ни одна") {
			t.Errorf("%s, пустой prefs: %v (%s)", fam, it.Compat, it.Reason)
		}
	}
	b := &Backup{Containers: []BackupContainer{wgCtr("amnezia-awg2", "1.5", VersionKnown)}}
	if it := PlanInstall(b, nil).Items[0]; it.Compat != CompatMismatch {
		t.Errorf("1.5 по умолчанию: %v", it.Compat)
	}
	// Смесь «незакреплённая + Partial» — Unknown.
	if it := PlanInstall(b, []string{"нет-такой", provision.Rev5106}).Items[0]; it.Compat != CompatUnknown {
		t.Errorf("незакреплённая + Partial: %v", it.Compat)
	}
}

// TestPlanInstallNeedsMeasurement — аудит AU-1 M2: план из одних ScriptOnly готов
// только с оговоркой; признак плана различает закреплённый Match.
func TestPlanInstallNeedsMeasurement(t *testing.T) {
	p := PlanInstall(&Backup{Containers: []BackupContainer{
		wgCtr("amnezia-awg2", "2", VersionKnown), wgCtr("amnezia-wireguard", "WireGuard", VersionKnown),
	}}, nil)
	if !p.Ready() || !p.NeedsMeasurement() {
		t.Errorf("ScriptOnly-план: Ready=%v NeedsMeasurement=%v", p.Ready(), p.NeedsMeasurement())
	}
	pinned := InstallPlan{Items: []InstallItem{{Compat: CompatMatch}}}
	if !pinned.Ready() || pinned.NeedsMeasurement() {
		t.Errorf("закреплённый план: Ready=%v NeedsMeasurement=%v", pinned.Ready(), pinned.NeedsMeasurement())
	}
	mixed := InstallPlan{Items: []InstallItem{{Compat: CompatMatch}, {Compat: CompatMatch, NeedsMeasurement: true}}}
	if !mixed.NeedsMeasurement() {
		t.Error("один контейнер с измерением — план без оговорки")
	}
}

// TestPlanInstallXRayConfByName — аудит AU-1 L2: server.json ищется по имени
// и статусу; не на первом месте — найден; не сохранён или нет — Unknown.
// N1: подпись XRay называет копию источником server.json.
func TestPlanInstallXRayConfByName(t *testing.T) {
	b, _ := backupSession(t, fakesrv.NewXRay("master")).CollectBackup("t", backupNow, okResolver)
	bc := ctrOf(t, b, XRayContainer)
	moved := bc
	moved.Files = append(append([]BackupFile{}, bc.Files[1:]...), bc.Files[0])
	it := PlanInstall(&Backup{Containers: []BackupContainer{moved}}, nil).Items[0]
	if it.Compat != CompatMatch || it.SNI == "" {
		t.Errorf("server.json не первым: %v (%s)", it.Compat, it.Reason)
	}
	if v := it.Verdict(); !strings.Contains(v, "server.json и ключи — из копии") || !strings.Contains(v, "подтвердится после установки") {
		t.Errorf("подпись XRay: %q", v)
	}
	unread := bc
	unread.Files = append([]BackupFile{}, bc.Files...)
	unread.Files[0].Status = FileUnreadable
	if it := PlanInstall(&Backup{Containers: []BackupContainer{unread}}, nil).Items[0]; it.Compat != CompatUnknown {
		t.Errorf("server.json не сохранён: %v", it.Compat)
	}
	none := bc
	none.Files = append([]BackupFile{}, bc.Files[1:]...)
	if it := PlanInstall(&Backup{Containers: []BackupContainer{none}}, nil).Items[0]; it.Compat != CompatUnknown {
		t.Errorf("server.json нет: %v", it.Compat)
	}
}

// TestPlanInstallTablesDiverge — аудит AU-1 L3: таблица provision ставит
// другой контейнер для семейства — Unknown, а не Mismatch.
func TestPlanInstallTablesDiverge(t *testing.T) {
	b := &Backup{Containers: []BackupContainer{wgCtr("amnezia-wireguard", "2", VersionKnown)}}
	if it := PlanInstall(b, nil).Items[0]; it.Compat != CompatUnknown || !strings.Contains(it.Reason, "а не amnezia-wireguard") {
		t.Errorf("расхождение таблиц: %v (%s)", it.Compat, it.Reason)
	}
}
