package main

import (
	"context"
	"errors"
	"io"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"amnezia-admin/core"
	"amnezia-admin/internal/fakesrv"
)

// Живая проверка migrate -to-host: источник с XRay на 443/tcp, на цели
// 443/tcp занят чужим nginx. -skip-xray обязан исключать XRay из
// предпроверки портов, плана, установки, переноса и ключа vpn://; итог —
// «частично» (код 1, как migrate -to-key -skip-xray), не «полная копия».

// skipXRaySource — копия источника: awg2 из thBackup + XRay, снятый
// НАСТОЯЩИМ CollectBackupCtx с fakesrv (доезд: клиенты XRay — из
// прочитанной clientsTable, а не присвоены в тесте). failTable — чтение
// clientsTable XRay падает (третье состояние «не удалось прочитать»).
func skipXRaySource(t *testing.T, failTable bool) *core.Backup {
	t.Helper()
	srv := fakesrv.NewXRay("master")
	if failTable {
		srv.Configure(func(x *fakesrv.Server) {
			x.FailRead = map[string]error{fakesrv.XRayDir + "/clientsTable": errors.New("Permission denied")}
		})
	}
	s := core.NewSessionWithRunner(srv, &core.ServerCreds{Host: "198.51.100.7", Port: "22", User: "root"})
	xb, err := s.CollectBackupCtx(context.Background(), "test", time.Unix(1700000000, 0), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	var xc *core.BackupContainer
	for i := range xb.Containers {
		if xb.Containers[i].Name == core.XRayContainer {
			xc = &xb.Containers[i]
		}
	}
	if xc == nil {
		t.Fatal("fakesrv: XRay не попал в копию — тест ничего не доказывает")
	}
	b := thBackup()
	b.Containers = append(b.Containers, *xc)
	return b
}

// 443/tcp занят чужой программой (nginx), 51820/udp свободен.
const busy443 = "SSRC=0\nL=tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\nL=tcp LISTEN 0 511 0.0.0.0:443 0.0.0.0:*\nEND\n"

func TestToHostSkipXRay(t *testing.T) {
	ap := migrateFlags{apply: true, noPw: true}
	apSkip := ap
	apSkip.skipXRay = true
	cases := []struct {
		name      string
		failTable bool
		mf        migrateFlags
		stdin     string
		code      int
		inst      int
		want      []string
		notWant   []string
	}{
		{"без -skip-xray: порт XRay занят — нельзя", false, ap, "", 1, 0,
			[]string{"НЕ годится", "освободите порт или перенесите без XRay", "-skip-xray"},
			[]string{"выберите другой порт", "XRay НЕ перенесён"}},
		{"-skip-xray, сухой прогон: порт XRay не проверяется", false, migrateFlags{skipXRay: true}, "", 0, 0,
			[]string{"XRay НЕ перенесён по -skip-xray", "Клиенты XRay (3): Admin [Android  (16.0)], Alice, Bob.", "не полная копия", "сухой прогон"},
			[]string{"amnezia-xray 443", "НЕ годится"}},
		{"-skip-xray, перенос: частично, код 1", false, apSkip, "y\ny\n", 1, 1,
			[]string{"ИТОГ: ПЕРЕНЕСЕНО ЧАСТИЧНО — без XRay", "Клиенты XRay (3): Admin [Android  (16.0)], Alice, Bob.", "БЕЗ XRay"},
			[]string{"Клиенты XRay: нет"}},
		{"-skip-xray, clientsTable не прочитана: не «клиентов нет»", true, apSkip, "y\ny\n", 1, 1,
			[]string{"ИТОГ: ПЕРЕНЕСЕНО ЧАСТИЧНО", "не удалось прочитать", "это не «клиентов нет»"},
			[]string{"Клиенты XRay: нет"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newTHEnv(t)
			e.backup = skipXRaySource(t, c.failTable)
			e.dst.f[core.ProvPortsTag] = busy443
			var installed []string
			var keyNames []string
			var migSrc *core.Backup
			toHostInstall = func(_ *core.Session, p core.InstallPlan, _ core.InstallOptions) core.InstallResult {
				e.installed++
				for _, it := range p.Items {
					installed = append(installed, it.Container)
				}
				return e.install
			}
			toHostMigrate = func(_ context.Context, _ io.Reader, _ io.Writer, _ io.Writer, _ bool, _ *core.Session, _ *core.Session, mf migrateFlags, _ time.Time) int {
				e.migrated++
				if mf.pre != nil {
					migSrc = mf.pre.source
				}
				return 0
			}
			toHostKeyContainers = func(_ *core.Session, names []string) ([]core.AdminKeyContainer, []string, error) {
				keyNames = names
				return []core.AdminKeyContainer{{Name: "amnezia-awg2", Protocol: thParams()}}, nil, nil
			}
			code, out, errOut := e.run(true, c.stdin, c.mf)
			if code != c.code || e.installed != c.inst {
				t.Fatalf("код %d (ждали %d), установок %d (ждали %d)\n%s\n%s", code, c.code, e.installed, c.inst, out, errOut)
			}
			for _, w := range c.want {
				if !strings.Contains(out, w) {
					t.Errorf("нет %q:\n%s", w, out)
				}
			}
			for _, w := range c.notWant {
				if strings.Contains(out, w) {
					t.Errorf("лишнее %q:\n%s", w, out)
				}
			}
			if c.mf.skipXRay && c.mf.apply {
				for _, n := range append(append([]string{}, installed...), keyNames...) {
					if n == core.XRayContainer {
						t.Errorf("XRay попал в установку или ключ: %v / %v", installed, keyNames)
					}
				}
				if migSrc == nil {
					t.Fatal("перенос не получил копию источника")
				}
				for _, bc := range migSrc.Containers {
					if bc.Name == core.XRayContainer {
						t.Error("XRay попал в перенос")
					}
				}
				// итог — последним: громкая строка после всего прочего
				if i := strings.LastIndex(out, "ИТОГ: ПЕРЕНЕСЕНО ЧАСТИЧНО"); i < 0 || strings.Contains(out[i:], "Перенос выполнен,") {
					t.Errorf("итог о XRay не последний:\n%s", out)
				}
			}
			// исходная копия не тронута (XRay остался в e.backup)
			found := false
			for _, bc := range e.backup.Containers {
				found = found || bc.Name == core.XRayContainer
			}
			if !found {
				t.Error("BackupWithout изменил исходную копию")
			}
		})
	}
}

// Доезд флага: -to-host передаёт в политику, что отпечаток цели взят из
// -to-hostkey, а источника — из -hostkey; без флага — пусто («сохранённый»).
func TestToHostHostKeyFlagOrigin(t *testing.T) {
	cases := []struct {
		name, srcFP, dstFP       string
		wantSrcFrom, wantDstFrom string
	}{
		{"оба переданы", "SHA256:s", "SHA256:d", "-hostkey", "-to-hostkey"},
		{"не переданы", "", "", "", ""},
	}
	for _, c := range cases {
		newTHEnv(t)
		gotSrc, gotDst := "x", "x"
		d0, d1 := migrateDial, toHostConnectNew
		migrateDial = func(cr *core.ServerCreds, p core.HostKeyPolicy) (*core.Session, error) {
			gotSrc = p.ExpectedFrom
			return d0(cr, p)
		}
		toHostConnectNew = func(h, port, u string, a core.AuthSource, p core.HostKeyPolicy) (*core.Session, core.KeyAttempt, error) {
			gotDst = p.ExpectedFrom
			return d1(h, port, u, a, p)
		}
		var out, errOut strings.Builder
		o := toHostOpts{srcKey: thSrcKey(t), srcHostkey: c.srcFP, hostkey: c.dstFP, host: thHost, port: "22", user: "root",
			knownHostsPath: filepath.Join(t.TempDir(), "kh"), noAgent: true}
		runMigrateToHost(context.Background(), strings.NewReader(""), &out, &errOut, true, o, time.Unix(1700000000, 0))
		if gotSrc != c.wantSrcFrom || gotDst != c.wantDstFrom {
			t.Errorf("%s: источник %q (ждали %q), цель %q (ждали %q)\n%s%s", c.name, gotSrc, c.wantSrcFrom, gotDst, c.wantDstFrom, out.String(), errOut.String())
		}
	}
}
