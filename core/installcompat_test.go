package core

import (
	"strings"
	"testing"

	"amnezia-admin/core/provision"
	"amnezia-admin/internal/fakesrv"
)

func wgCtr(name, family, state string) BackupContainer {
	return BackupContainer{Name: name, Status: CtrSaved, Version: family, VersionState: state,
		VersionReason: "причина копии", Port: "51820", Subnet: "10.8.1.0/24"}
}

// TestPlanInstallFamilies — таблица «семейство → ревизия → вердикт»,
// включая обязательные случаи «данных нет».
func TestPlanInstallFamilies(t *testing.T) {
	noPort := wgCtr("amnezia-awg2", "2", VersionKnown)
	noPort.Port = ""
	noSubnet := wgCtr("amnezia-awg2", "2", VersionKnown)
	noSubnet.Subnet = ""
	unread := wgCtr("amnezia-awg2", "2", VersionKnown)
	unread.Status = CtrUnreadable
	cases := []struct {
		name    string
		c       BackupContainer
		want    CompatState
		rev     string
		measure bool
	}{
		{"3.1", wgCtr("amnezia-awg2", "3.1", VersionKnown), CompatMatch, provision.Rev5106, true},
		{"2", wgCtr("amnezia-awg2", "2", VersionKnown), CompatMatch, provision.Rev5106, true},
		{"1.5 — Partial не Match", wgCtr("amnezia-awg2", "1.5", VersionKnown), CompatMismatch, "", false},
		{"старый AWG", wgCtr("amnezia-awg", "старый AWG", VersionKnown), CompatMatch, provision.Rev5106, true},
		{"WireGuard", wgCtr("amnezia-wireguard", "WireGuard", VersionKnown), CompatMatch, provision.Rev5106, true},
		{"не тот контейнер", wgCtr("amnezia-wireguard", "2", VersionKnown), CompatMismatch, "", false},
		// «данных нет»
		{"версия не known, хотя Version задано", wgCtr("amnezia-awg2", "2", VersionUnknown), CompatUnknown, "", false},
		{"семейство вне таблицы", wgCtr("amnezia-awg2", "4.0", VersionKnown), CompatUnknown, "", false},
		{"нет порта", noPort, CompatUnknown, "", false},
		{"нет подсети", noSubnet, CompatUnknown, "", false},
		{"контейнер не прочитан", unread, CompatUnknown, "", false},
		{"XRay без server.json", BackupContainer{Name: XRayContainer, Status: CtrSaved, Version: "XRay", VersionState: VersionKnown, Port: "443"}, CompatUnknown, "", false},
	}
	for _, tc := range cases {
		p := PlanInstall(&Backup{Containers: []BackupContainer{tc.c}}, nil)
		it := p.Items[0]
		if it.Compat != tc.want || it.Revision != tc.rev || it.NeedsMeasurement != tc.measure {
			t.Errorf("%s: %v rev=%q measure=%v (%s); ждали %v rev=%q measure=%v",
				tc.name, it.Compat, it.Revision, it.NeedsMeasurement, it.Reason, tc.want, tc.rev, tc.measure)
		}
		if it.Compat != CompatMatch && it.Reason == "" {
			t.Errorf("%s: не Match без причины", tc.name)
		}
		if p.Ready() != (tc.want == CompatMatch) {
			t.Errorf("%s: Ready=%v", tc.name, p.Ready())
		}
	}
}

// TestPlanInstallUnknownNotMismatch — тест различения: клетка «нет данных»
// у всех ревизий — Unknown, а не Mismatch; «нет данных» у свежей — берём
// следующую, а не стоп.
func TestPlanInstallUnknownNotMismatch(t *testing.T) {
	b := &Backup{Containers: []BackupContainer{wgCtr("amnezia-awg2", "2", VersionKnown)}}
	if it := PlanInstall(b, []string{"нет-такой"}).Items[0]; it.Compat != CompatUnknown {
		t.Errorf("ревизия вне таблицы: %v — ждали «нет данных»", it.Compat)
	}
	if it := PlanInstall(b, []string{"нет-такой", provision.RevDev94b51df}).Items[0]; it.Compat != CompatMatch || it.Revision != provision.RevDev94b51df {
		t.Errorf("откат на закреплённую: %v %q", it.Compat, it.Revision)
	}
	b15 := &Backup{Containers: []BackupContainer{wgCtr("amnezia-awg2", "1.5", VersionKnown)}}
	if it := PlanInstall(b15, []string{provision.Rev5106, "нет-такой"}).Items[0]; it.Compat != CompatUnknown {
		t.Errorf("Partial + нет данных: %v — ждали «нет данных» (не «несовместимо»)", it.Compat)
	}
	if it := PlanInstall(b15, nil).Items[0]; it.Compat != CompatMismatch {
		t.Errorf("1.5 во всех ревизиях Partial: %v — ждали «несовместимо»", it.Compat)
	}
	if (InstallPlan{}).Ready() {
		t.Error("пустой план готов")
	}
}

// TestPlanInstallReachUnknown — тест доезда (долг L1 PR #65): Unknown
// возникает из реальной копии через protoVersion (awg0.conf без признаков
// версии), а не присваиванием.
func TestPlanInstallReachUnknown(t *testing.T) {
	a := fakesrv.NewAWG2()
	conf, _ := a.File("/opt/amnezia/awg/awg0.conf")
	var plain []string
	for _, l := range strings.Split(string(conf), "\n") {
		k := strings.TrimSpace(strings.SplitN(l, "=", 2)[0])
		switch k {
		case "S3", "S4", "H1", "H2", "H3", "H4", "HeaderProtectionKey", "ContentPaddingAddition", "RekeyAfterTime", "RekeyTimeout",
			"RejectAfterTime", "KeepaliveTimeout", "MaxHandshakeAttempts", "RandomTrailers", "DisableCookies":
			continue
		}
		if strings.HasPrefix(strings.TrimSpace(l), "# I") {
			continue
		}
		plain = append(plain, l)
	}
	a.SetFile("/opt/amnezia/awg/awg0.conf", []byte(strings.Join(plain, "\n")))
	b, err := backupSession(t, a).CollectBackup("t", backupNow, okResolver)
	if err != nil {
		t.Fatal(err)
	}
	c := ctrOf(t, b, "amnezia-awg2")
	if c.VersionState != VersionUnknown {
		t.Fatalf("копия: %q — подготовка не дала «не определена»", c.VersionState)
	}
	var it *InstallItem
	p := PlanInstall(b, nil)
	for i := range p.Items {
		if p.Items[i].Container == "amnezia-awg2" {
			it = &p.Items[i]
		}
	}
	if it == nil || it.Compat != CompatUnknown || !strings.Contains(it.Reason, c.VersionReason) || it.Revision != "" {
		t.Fatalf("доезд: %+v — ждали «нет данных» с причиной копии %q", it, c.VersionReason)
	}
	if p.Ready() {
		t.Error("план с «нет данных» готов к установке")
	}
	// Та же копия с признаками версии — Match: различение доезжает обоими путями.
	b, _ = backupSession(t, fakesrv.NewAWG2()).CollectBackup("t", backupNow, okResolver)
	if it := PlanInstall(b, nil).Items[0]; it.Container == "amnezia-awg2" && it.Compat != CompatMatch {
		t.Errorf("awg2 с признаками: %v (%s)", it.Compat, it.Reason)
	}
}

// TestPlanInstallXRay — параметры установки XRay из реальной копии.
func TestPlanInstallXRay(t *testing.T) {
	b, _ := backupSession(t, fakesrv.NewXRay("master")).CollectBackup("t", backupNow, okResolver)
	var it InstallItem
	for _, x := range PlanInstall(b, nil).Items {
		if x.Container == XRayContainer {
			it = x
		}
	}
	if it.Compat != CompatMatch || it.Revision != provision.Rev5106 || !it.NeedsMeasurement ||
		it.Port != "443" || it.Transport != "tcp/reality" || it.SNI == "" || it.Subnet != "" {
		t.Errorf("xray: %+v", it)
	}
	// Повреждённый server.json — «нет данных», а не «несовместимо».
	bc := ctrOf(t, b, XRayContainer)
	bc.Files = append([]BackupFile{{Name: "server.json", Status: FileSaved, Data: NewSecret([]byte("{"))}}, bc.Files[1:]...)
	if it := PlanInstall(&Backup{Containers: []BackupContainer{bc}}, nil).Items[0]; it.Compat != CompatUnknown || it.SNI != "" {
		t.Errorf("битый server.json: %v %q", it.Compat, it.SNI)
	}
}

// TestPlanInstallSkipsNotIncluded — «не входит» не ставится и называется.
func TestPlanInstallSkipsNotIncluded(t *testing.T) {
	b := &Backup{Containers: []BackupContainer{
		{Name: "amnezia-openvpn", Status: CtrNotIncluded, Reason: "протокол копией не поддерживается"},
		wgCtr("amnezia-awg2", "2", VersionKnown),
	}}
	p := PlanInstall(b, nil)
	if len(p.Items) != 1 || len(p.Skipped) != 1 || p.Skipped[0].Container != "amnezia-openvpn" || !p.Ready() {
		t.Errorf("%+v", p)
	}
}
