package main

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"amnezia-admin/core"
)

// Снос Amnezia на НЕчистой цели перед установкой (-wipe-target).

func thDirty(e *thEnv) {
	e.dst.f[core.ProvDockerTag] = "DOCKER=yes\nSRVRC=0\nSRV=27.1.1\nEND\n"
	e.dst.f[core.ProvCtrTag] = "RC=0\nN=amnezia-awg2|0.0.0.0:51820->51820/udp\nEND\n"
}

func thTDPlan(clientsKnown bool, copy bool, foreign ...string) *core.TeardownPlan {
	tc := core.TargetClients{Container: "amnezia-awg2", Known: clientsKnown, Names: []string{"Иван"}}
	if !clientsKnown {
		tc.Names, tc.Why = nil, "не удалось прочитать (копия не снята)"
	}
	p := &core.TeardownPlan{Inv: &core.TargetInventory{Containers: []string{"amnezia-awg2"}, Images: []string{"amnezia-awg2"},
		Ports: map[string]string{"amnezia-awg2": "0.0.0.0:51820->51820/udp"}, PortsKnown: true, Foreign: foreign, Clients: []core.TargetClients{tc}}}
	if copy {
		p.Copy = &core.Backup{Containers: []core.BackupContainer{{Name: "amnezia-awg2", Status: core.CtrSaved}}}
	} else {
		p.CopyWhy = "копия не снята: docker ps"
	}
	return p
}

type tdEnv struct {
	*thEnv
	plan      *core.TeardownPlan
	planErr   error
	res       core.TeardownResult
	tdCalls   int
	tdOpt     core.TeardownOptions
	stayDirty bool
	host      string // "" — thHost
}

func newTDEnv(t *testing.T) *tdEnv {
	e := &tdEnv{thEnv: newTHEnv(t), plan: thTDPlan(true, true)}
	thDirty(e.thEnv)
	e.res = core.TeardownResult{State: core.TeardownDone, CopyPath: "/копии/203.0.113.9-перед-сносом.aabk"}
	o1, o2, o3 := toHostTeardownPlan, toHostTeardown, userBackupsDirFn
	t.Cleanup(func() { toHostTeardownPlan, toHostTeardown, userBackupsDirFn = o1, o2, o3 })
	dir := t.TempDir()
	userBackupsDirFn = func() (string, error) { return dir, nil }
	toHostTeardownPlan = func(context.Context, *core.Session, time.Time) (*core.TeardownPlan, error) { return e.plan, e.planErr }
	toHostTeardown = func(_ *core.Session, _ *core.TeardownPlan, opt core.TeardownOptions) core.TeardownResult {
		e.tdCalls++
		e.tdOpt = opt
		if !e.stayDirty && e.res.State == core.TeardownDone {
			h := healthyProvCLI()
			for k := range e.dst.f {
				delete(e.dst.f, k)
			}
			for k, v := range h {
				e.dst.f[k] = v
			}
		}
		return e.res
	}
	return e
}

func (e *tdEnv) runW(tty bool, stdin string, mf migrateFlags, wipe, noCopy bool) (int, string) {
	var out, errOut bytes.Buffer
	host := thHost
	if e.host != "" {
		host = e.host
	}
	o := toHostOpts{srcKey: thSrcKey(e.t), host: host, port: "22", user: "root", knownHostsPath: filepath.Join(e.t.TempDir(), "kh"), mf: mf, noAgent: true,
		wipe: wipe, wipeNoCopy: noCopy}
	code := runMigrateToHost(context.Background(), strings.NewReader(stdin), &out, &errOut, tty, o, time.Unix(1700000000, 0))
	return code, out.String() + errOut.String()
}

func TestToHostWipe(t *testing.T) {
	ap := migrateFlags{apply: true, noPw: true}
	apY := migrateFlags{apply: true, noPw: true, yes: true}
	cases := []struct {
		name         string
		mod          func(*tdEnv)
		tty          bool
		stdin        string
		mf           migrateFlags
		wipe, noCopy bool
		code         int
		td, inst     int
		want, notOut []string
	}{
		{name: "сухой прогон: состав и подсказка, сноса нет", mf: migrateFlags{}, code: 0,
			want: []string{"не чистый", "контейнер amnezia-awg2", "клиенты (1): Иван", "-wipe-target", "сухой прогон"}},
		{name: "-yes без -wipe-target — остановка", mf: apY, code: 2,
			want: []string{"-wipe-target (-yes его не даёт)", "Ничего не изменено"}},
		{name: "-yes -wipe-target — снос, установка", mf: apY, wipe: true, code: 0, td: 1, inst: 1,
			want: []string{"Копия нового сервера перед сносом: /копии/", "Снос: снесено", "Предпроверка после сноса: можно ставить"}},
		{name: "терминал: снос отклонён", tty: true, stdin: "n\nn\n", mf: ap, code: 2, want: []string{"Снос не подтверждён"}},
		{name: "терминал: снос «y», установка «y»", tty: true, stdin: "n\ny\ny\n", mf: ap, code: 0, td: 1, inst: 1},
		{name: "частичная копия без -wipe-without-copy", mod: func(e *tdEnv) { e.plan = thTDPlan(false, false) }, mf: apY, wipe: true, code: 2,
			want: []string{"-wipe-without-copy", "клиенты: не удалось прочитать", "Копии нового сервера НЕ БУДЕТ"}, notOut: []string{"клиенты: нет"}},
		{name: "без копии с -wipe-without-copy", mod: func(e *tdEnv) { e.plan = thTDPlan(false, false) }, mf: apY, wipe: true, noCopy: true, code: 0, td: 1, inst: 1},
		{name: "терминал: без копии — отдельный вопрос отклонён", mod: func(e *tdEnv) { e.plan = thTDPlan(false, false) }, tty: true, stdin: "n\ny\nn\n", mf: ap, code: 2,
			want: []string{"Полной копии НЕ БУДЕТ", "Снос без копии не подтверждён"}},
		{name: "копия не записана — сноса нет", mod: func(e *tdEnv) {
			e.res = core.TeardownResult{State: core.TeardownRefused, Why: "копия нового сервера не записана: диск полон — снос не выполнялся"}
		}, mf: apY, wipe: true, code: 1, td: 1, want: []string{"снос не выполнялся", "Установка не начиналась"}},
		{name: "итог сноса неизвестен", mod: func(e *tdEnv) { e.res = core.TeardownResult{State: core.TeardownUnknown, Why: "связь"} }, mf: apY, wipe: true, code: 4, td: 1,
			want: []string{"НЕИЗВЕСТЕН", "Маркер незавершённой операции оставлен"}},
		{name: "осталось после сноса", mod: func(e *tdEnv) {
			e.res = core.TeardownResult{State: core.TeardownFailed, Why: "на сервере осталось: контейнер amnezia-awg2"}
		}, mf: apY, wipe: true, code: 1, td: 1, want: []string{"снесено НЕ всё"}},
		{name: "после сноса предпроверка не «можно»", mod: func(e *tdEnv) { e.stayDirty = true }, mf: apY, wipe: true, code: 1, td: 1,
			want: []string{"Предпроверка после сноса:", "установка не начиналась"}},
		{name: "состав не прочитан", mod: func(e *tdEnv) {
			e.planErr = errors.New("состав нового сервера прочитать не удалось: список контейнеров не получен")
		}, mf: apY, wipe: true, code: 4,
			want: []string{"клиенты — неизвестно (это не «клиентов нет»)"}},
		{name: "посторонний amnezia-*", mod: func(e *tdEnv) { e.plan = thTDPlan(true, true, "контейнер amnezia-mystery") }, mf: apY, wipe: true, code: 1,
			want: []string{"Снос невозможен", "amnezia-mystery"}},
		{name: "кроме Amnezia занят чужой порт — снос не предлагается", mod: func(e *tdEnv) {
			e.dst.f[core.ProvPortsTag] = "SSRC=0\nL=tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\nL=udp UNCONN 0 0 0.0.0.0:51820 0.0.0.0:*\nEND\n"
			e.dst.f[core.ProvCtrTag] = "RC=0\nN=amnezia-awg2|\nEND\n"
		}, mf: apY, wipe: true, code: 1, want: []string{"снос их не устранит"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newTDEnv(t)
			e.keyAuth = !c.tty // без терминала пароль не спрашивается
			if c.mod != nil {
				c.mod(e)
			}
			code, out := e.runW(c.tty, c.stdin, c.mf, c.wipe, c.noCopy)
			if code != c.code || e.tdCalls != c.td || e.installed != c.inst {
				t.Fatalf("код %d (ждали %d), сносов %d (%d), установок %d (%d)\n%s", code, c.code, e.tdCalls, c.td, e.installed, c.inst, out)
			}
			for _, w := range c.want {
				if !strings.Contains(out, w) {
					t.Errorf("нет %q в выводе:\n%s", w, out)
				}
			}
			for _, w := range c.notOut {
				if strings.Contains(out, w) {
					t.Errorf("лишнее %q в выводе:\n%s", w, out)
				}
			}
			if e.tdCalls > 0 && (!e.tdOpt.Confirmed || e.tdOpt.Layer == nil || e.tdOpt.CopyDir == "") {
				t.Errorf("снос без подтверждения/слоя/каталога копии: %+v", e.tdOpt)
			}
		})
	}
}

// L1 (ревью-1): согласие «без копии» доходит до ядра только при флаге или
// ответе «да»; при полной копии — не передаётся.
func TestToHostWipeNoCopyConsentPassedOnlyWhenGiven(t *testing.T) {
	apY := migrateFlags{apply: true, noPw: true, yes: true}
	for _, c := range []struct {
		name         string
		full         bool
		tty          bool
		stdin        string
		noCopy, want bool
	}{
		{"полная копия, без флага", true, false, "", false, false},
		{"полная копия, флаг лишний — согласия нет и не нужно", true, false, "", true, false},
		{"без копии, флаг", false, false, "", true, true},
		{"без копии, ответ «y»", false, true, "n\ny\ny\ny\n", false, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			e := newTDEnv(t)
			e.keyAuth = !c.tty
			e.plan = thTDPlan(c.full, c.full)
			mf := apY
			if c.tty {
				mf = migrateFlags{apply: true, noPw: true}
			}
			code, out := e.runW(c.tty, c.stdin, mf, !c.tty, c.noCopy)
			if code != 0 || e.tdCalls != 1 {
				t.Fatalf("код %d, сносов %d\n%s", code, e.tdCalls, out)
			}
			if e.tdOpt.NoCopyConfirmed != c.want {
				t.Errorf("NoCopyConfirmed = %v, ждали %v", e.tdOpt.NoCopyConfirmed, c.want)
			}
		})
	}
}

// M1 (ревью-1): «один ли сервер» — три исхода; продолжаем только при
// «разные». Отпечаток цели не получен и адреса не сверить — НЕ «разные»:
// остановка до предпроверки и тем более до сноса.
func TestToHostSameServerThreeStates(t *testing.T) {
	for _, c := range []struct {
		name  string
		dstFP string
		host  string
		code  int
		want  string
	}{
		{"разные (отпечатки различны)", "SHA256:dst", "", 0, "сухой прогон"},
		{"тот же отпечаток", "SHA256:src", "", exitToHostUnknown, "ПЕРЕЕЗД ОСТАНОВЛЕН"},
		{"отпечаток не получен, адрес — разные IP: измеренное «разные»", "", "", 0, "сухой прогон"},
		{"отпечаток не получен, имя не разрешилось — неизвестно", "", "new.example.invalid", exitToHostUnknown, "узнать не удалось"},
	} {
		t.Run(c.name, func(t *testing.T) {
			e := newTDEnv(t)
			e.keyAuth = true
			e.dstFP, e.host = c.dstFP, c.host
			code, out := e.runW(false, "", migrateFlags{}, true, true)
			if code != c.code || !strings.Contains(out, c.want) {
				t.Fatalf("код %d (ждали %d), нет %q:\n%s", code, c.code, c.want, out)
			}
			if c.code != 0 && (e.tdCalls != 0 || strings.Contains(out, "Предпроверка")) {
				t.Errorf("после остановки шли дальше:\n%s", out)
			}
		})
	}
}
