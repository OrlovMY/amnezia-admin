package core

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"amnezia-admin/internal/fakesrv"
)

// dnsRunner — fakesrv.Server плюс модель Docker для установки AmneziaDNS
// (команды с меткой instRC). failListAll — `docker ps -a` падает (третье
// состояние на боевом пути ProbeAmneziaDNS). failStep — шаг установки
// отвечает кодом 1; dropStep — связь обрывается на шаге.
type dnsRunner struct {
	*fakesrv.Server
	mu                 sync.Mutex
	failListAll        bool
	failStep, dropStep string
	dead               bool
	ctrs, imgs         map[string]bool
	steps              []string
}

func newDNSRunner(s *fakesrv.Server) *dnsRunner {
	return &dnsRunner{Server: s, ctrs: map[string]bool{}, imgs: map[string]bool{}}
}

func (r *dnsRunner) Run(cmd string, stdin []byte) (string, error) {
	if !strings.Contains(cmd, instRC) {
		if r.failListAll && strings.HasSuffix(cmd, dnsListCmd) {
			return "", errors.New("ssh: связь оборвалась (модель)")
		}
		return r.Server.Run(cmd, stdin)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	in := string(stdin)
	key := "?"
	switch {
	case strings.Contains(cmd, "sudo -n true"):
		key = "sudo"
	case strings.Contains(cmd, "docker ps -a"):
		key = "list"
	case strings.Contains(cmd, "docker images"):
		key = "images"
	case strings.Contains(cmd, "docker inspect"):
		key = "inspect"
	case strings.Contains(cmd, "/Dockerfile"):
		key = "dockerfile"
	case strings.Contains(in, "docker network create"):
		key = "prepare"
	case strings.Contains(in, "docker build"):
		key = "build"
	case strings.Contains(in, "--ip=172.29.172.254"):
		key = "run"
	case strings.Contains(in, "docker rm -fv"):
		key = "remove"
	}
	r.steps = append(r.steps, key)
	if r.dead {
		return "", errors.New("связь оборвалась")
	}
	if key == r.dropStep {
		r.dead = true
		return "", errors.New("связь оборвалась")
	}
	if key == r.failStep {
		return "boom\n" + instRC + "1\n", nil
	}
	join := func(m map[string]bool) string {
		var o []string
		for k := range m {
			o = append(o, k)
		}
		return strings.Join(o, "\n") + "\n"
	}
	switch key {
	case "list":
		return instOK(join(r.ctrs)), nil
	case "images":
		return instOK(join(r.imgs)), nil
	case "build":
		r.imgs[DNSContainer] = true
	case "run":
		r.ctrs[DNSContainer] = true
	case "remove":
		delete(r.ctrs, DNSContainer)
		delete(r.imgs, DNSContainer)
	case "inspect":
		return instOK("true/0\ntrue/0\n"), nil
	case "?":
		return "", errors.New("неизвестная команда установки: " + cmd)
	}
	return instOK(""), nil
}

func dnsOut(outs []RestoreOutcome) (RestoreOutcome, bool) {
	for _, o := range outs {
		if o.Container == DNSContainer {
			return o, true
		}
	}
	return RestoreOutcome{}, false
}

// TestMigrateAmneziaDNS — таблица: AmneziaDNS на источнике есть / нет /
// узнать не удалось; на цели — нет / есть / не удалось; установка — успех,
// отказ с откатом, обрыв. Весь путь боевой: CollectBackupCtx →
// PrepareMigration → Apply. Различение: «узнать не удалось» даёт строку
// «не записано» с причиной и «ЧАСТИЧНО», а «нет» — ни строки, ни частичности.
func TestMigrateAmneziaDNS(t *testing.T) {
	cases := []struct {
		name                string
		srcRun, srcStop     bool // amnezia-dns на источнике запущен / остановлен
		srcFail, dstFail    bool // docker ps -a падает
		dstHas              bool
		failStep, dropStep  string
		want                RestoreState
		wantLine, installed bool
		wantText            string
	}{
		{name: "нет на источнике", wantLine: false},
		{name: "источник: узнать не удалось", srcFail: true, wantLine: true, want: RestoreNotWritten, wantText: "узнать не удалось"},
		{name: "запущен → ставится", srcRun: true, wantLine: true, want: RestoreDone, installed: true, wantText: "поставлен официальными скриптами"},
		{name: "остановлен → тоже ставится", srcStop: true, wantLine: true, want: RestoreDone, installed: true},
		{name: "на цели уже есть", srcRun: true, dstHas: true, wantLine: true, want: RestoreDone, wantText: "уже был"},
		{name: "цель: узнать не удалось", srcRun: true, dstFail: true, wantLine: true, want: RestoreNotWritten, wantText: "на новом сервере, узнать не удалось"},
		{name: "run упал → откат", srcRun: true, failStep: "run", wantLine: true, want: RestoreRolledBack, wantText: "снят откатом"},
		{name: "обрыв на сборке", srcRun: true, dropStep: "build", wantLine: true, want: RestoreUnknown},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			src, tgt := migrationPair(t)
			if c.srcRun {
				src.Names = append(src.Names, DNSContainer)
			}
			if c.srcStop {
				src.Stopped = append(src.Stopped, DNSContainer)
			}
			if c.dstHas {
				tgt.Stopped = append(tgt.Stopped, DNSContainer)
			}
			sr, tr := newDNSRunner(src), newDNSRunner(tgt)
			sr.failListAll, tr.failListAll = c.srcFail, c.dstFail
			tr.failStep, tr.dropStep = c.failStep, c.dropStep
			t.Cleanup(SetXRayWaits(0, 0))
			ss := NewSessionWithRunner(sr, &ServerCreds{Host: migSrcHost})
			ss.ClientHostDecided = true
			ts := NewSessionWithRunner(tr, &ServerCreds{Host: migDstHost})
			m, err := PrepareMigration(context.Background(), ss, ts, migOpts())
			if err != nil || m.Plan == nil {
				t.Fatalf("подготовка: %v", err)
			}
			if (m.DNSLines() != nil) != c.wantLine {
				t.Errorf("строка предпросмотра: %v", m.DNSLines())
			}
			auto, outs, err := m.Apply(migApply(t.TempDir()))
			if err != nil {
				t.Fatal(err)
			}
			o, has := dnsOut(outs)
			if has != c.wantLine {
				t.Fatalf("строка amnezia-dns в итоге: %v, ждали %v (%+v)", has, c.wantLine, outs)
			}
			lines := strings.Join(MigrationOutcomeLines(auto, false, outs), "\n")
			if !c.wantLine {
				if strings.Contains(lines, "ЧАСТИЧНО") || strings.Contains(lines, DNSContainer) {
					t.Errorf("без AmneziaDNS на источнике итог не должен его упоминать:\n%s", lines)
				}
				return
			}
			if o.State != c.want {
				t.Errorf("исход %v, ждали %v (%v)", o.State, c.want, o.Err)
			}
			text := o.Checked
			if o.Err != nil {
				text = o.Err.Error()
			}
			if c.wantText != "" && !strings.Contains(text, c.wantText) {
				t.Errorf("текст %q без %q", text, c.wantText)
			}
			if got := tr.ctrs[DNSContainer]; got != c.installed {
				t.Errorf("контейнер на цели: %v, ждали %v (шаги %v)", got, c.installed, tr.steps)
			}
			if (o.State != RestoreDone) != strings.Contains(lines, "ЧАСТИЧНО") {
				t.Errorf("частичность итога не совпала с исходом %v:\n%s", o.State, lines)
			}
			if len(sr.steps) != 0 {
				t.Errorf("на источник ушли команды установки: %v", sr.steps)
			}
		})
	}
}

// TestPlanInstallDNS — план установки: AmneziaDNS не в «Не ставится», а в
// DNS; у копии без пробы (из файла) — «узнать не удалось», не «нет».
func TestPlanInstallDNS(t *testing.T) {
	b := instBackup()
	b.Containers = append(b.Containers, BackupContainer{Name: DNSContainer, Status: CtrNotIncluded, Reason: "протокол копией не поддерживается"})
	b.SourceDNS = DNSProbe{State: DNSPresent, Running: CompatMatch}
	p := PlanInstall(b, nil)
	for _, s := range p.Skipped {
		if s.Container == DNSContainer {
			t.Errorf("amnezia-dns в «Не ставится»: %+v", s)
		}
	}
	if l := strings.Join(SourceDNSLines(p.DNS), ""); !strings.Contains(l, "будет поставлен") {
		t.Errorf("есть: %q", l)
	}
	b.SourceDNS = DNSProbe{}
	if l := strings.Join(SourceDNSLines(PlanInstall(b, nil).DNS), ""); !strings.Contains(l, "узнать не удалось") || strings.Contains(l, "не ставится.") {
		t.Errorf("не знаем: %q", l)
	}
	b.SourceDNS = DNSProbe{State: DNSAbsent}
	if l := strings.Join(SourceDNSLines(PlanInstall(b, nil).DNS), ""); !strings.Contains(l, "нет") {
		t.Errorf("нет: %q", l)
	}
}
