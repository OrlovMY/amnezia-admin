package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"amnezia-admin/core"
	"amnezia-admin/internal/fakesrv"
)

// Сквозной тест -to-host на поддельных серверах с НАСТОЯЩИМИ CollectBackupCtx,
// ProvisionCheckFor, Install, runMigrate (PrepareMigration/Apply/Restore) и
// AdminKeyContainersFromServer (ревью PR #70, «Покрытие»). Подменены только
// вход по SSH (сессии — поверх runner'ов) и проверка ключа входом.
//
// Новый сервер — гибрид: предпроверка отвечает «чистый хост», шаги установки
// (команды с меткой AMNEZIA_ADMIN_RC=) — эмуляция установщика, а после шага
// run контейнер «появляется» в fakesrv, который дальше обслуживает
// измерение и перенос клиентов как настоящий сервер Amnezia.

type e2eTarget struct {
	mu        sync.Mutex
	prov      provCLIFake
	srv       *fakesrv.Server
	installed []string
	steps     []string // команды установки (с меткой RC)
}

var reE2ECtr = regexp.MustCompile(`amnezia-(awg2|awg|wireguard|xray)\b`)

func (t *e2eTarget) Run(cmd string, stdin []byte) (string, error) {
	for _, tag := range []string{core.ProvOSTag, core.ProvKernelTag, core.DiagHostTag, core.ProvSudoTag, core.ProvDockerTag, core.ProvCtrTag, core.ProvPortsTag, core.ProvDiskTag, core.ProvDiskAtTag} {
		if strings.Contains(cmd, tag) {
			return t.prov.Run(cmd, stdin)
		}
	}
	const rc = "AMNEZIA_ADMIN_RC="
	if !strings.Contains(cmd, rc) {
		return t.srv.Run(cmd, stdin)
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.steps = append(t.steps, cmd)
	ok := func(body string) (string, error) { return body + rc + "0\n", nil }
	in := string(stdin)
	switch {
	case strings.Contains(cmd, "docker ps -a"):
		return ok(strings.Join(t.installed, "\n") + "\n")
	case strings.Contains(cmd, "docker volume ls"), strings.Contains(cmd, "docker images"):
		return ok("\n")
	case strings.Contains(cmd, "docker --version"):
		return ok("Docker version 27.5.1, build abc\nactive\n")
	case strings.Contains(cmd, "listen-port"):
		return ok("51820\n")
	case strings.Contains(cmd, "ip_forward"):
		return ok("1\n")
	case strings.Contains(cmd, "docker inspect"):
		return ok("true/0\ntrue/0\n")
	case strings.Contains(cmd, `cat > "$t"`) && strings.Contains(in, "docker run -d"):
		c := reE2ECtr.FindString(in)
		t.installed = append(t.installed, c)
		names := append([]string(nil), t.installed...)
		t.srv.Configure(func(s *fakesrv.Server) { s.Names = names })
	}
	return ok("")
}

// e2eEmptyAWG2 — сервер amnezia-awg2 «как после установки»: интерфейс без
// клиентов, clientsTable пуст, контейнера ещё нет (Names пуст).
func e2eEmptyAWG2(t *testing.T) *fakesrv.Server {
	s := fakesrv.NewAWG2()
	conf, ok := s.File(migAwg + "awg0.conf")
	if !ok {
		t.Fatal("в fakesrv.NewAWG2 нет awg0.conf")
	}
	iface, _, _ := strings.Cut(string(conf), "[Peer]")
	s.SetFile(migAwg+"awg0.conf", []byte(strings.TrimRight(iface, "\n")+"\n"))
	s.SetFile(migAwg+"clientsTable", []byte("[]"))
	s.SetFile(migAwg+"wireguard_psk.key", []byte("NEW-PSK\n"))
	s.Configure(func(x *fakesrv.Server) { x.Names = nil })
	return s
}

func newE2E(t *testing.T) (*thEnv, *e2eTarget, *fakesrv.Server) {
	e := newTHEnv(t)
	src := fakesrv.NewAWG2()
	src.SetFile(migAwg+"wireguard_psk.key", []byte("OLD-PSK\n"))
	tgt := &e2eTarget{prov: healthyProvCLI(), srv: e2eEmptyAWG2(t)}
	e.dst = &thRec{f: provCLIFake{}} // не используется
	migrateDial = func(c *core.ServerCreds, _ core.HostKeyPolicy) (*core.Session, error) {
		s := core.NewSessionWithRunner(src, c)
		s.HostKeyFingerprint = "SHA256:src"
		return s, nil
	}
	toHostConnectNew = func(host, port, user string, a core.AuthSource, _ core.HostKeyPolicy) (*core.Session, core.KeyAttempt, error) {
		if a.Password != nil {
			b, _ := a.Password(core.KeyAttempt{Outcome: core.KeysRejected})
			clear(b)
		}
		s := core.NewSessionWithRunner(tgt, &core.ServerCreds{Host: host, Port: port, User: user})
		s.HostKeyFingerprint = "SHA256:dst"
		return s, core.KeyAttempt{Outcome: core.KeysRejected}, nil
	}
	// настоящие: сбор копии, установка, перенос, параметры для ключа
	toHostCollect = func(ctx context.Context, s *core.Session, now time.Time, p core.ProgressFunc) (*core.Backup, error) {
		return s.CollectBackupCtx(ctx, "test", now, nil, p)
	}
	toHostInstall = core.Install
	toHostMigrate = runMigrate
	toHostKeyContainers = func(s *core.Session, names []string) ([]core.AdminKeyContainer, []string, error) {
		return s.AdminKeyContainersFromServer(names)
	}
	return e, tgt, src
}

func TestToHostEndToEndFakeServers(t *testing.T) {
	e, tgt, _ := newE2E(t)
	var out, errOut bytes.Buffer
	o := toHostOpts{srcKey: thSrcKey(t), host: thHost, port: "22", user: "root", knownHostsPath: filepath.Join(t.TempDir(), "kh"),
		mf: migrateFlags{apply: true, noPw: true, addrOK: true}, noAgent: true}
	code := runMigrateToHost(context.Background(), strings.NewReader("y\ny\n"), &out, &errOut, true, o, time.Unix(1700000000, 0))
	if code != 0 {
		t.Fatalf("код %d\n%s\n%s", code, out.String(), errOut.String())
	}
	if len(tgt.installed) != 1 || tgt.installed[0] != "amnezia-awg2" {
		t.Fatalf("установлено: %v", tgt.installed)
	}
	tbl, _ := tgt.srv.File(migAwg + "clientsTable")
	if !strings.Contains(string(tbl), "Alice") || !strings.Contains(string(tbl), "Bob") {
		t.Fatalf("клиенты не перенесены: %s", tbl)
	}
	// Вопросы задаются только до установки: после неё stdin не читался.
	after := out.String()[strings.Index(out.String(), "можно переносить клиентов"):]
	if strings.Contains(after, "(y/n)") {
		t.Fatalf("после установки задан вопрос:\n%s", after)
	}
	files := e.keyFiles()
	if len(files) != 1 {
		t.Fatalf("файлов ключа %d\n%s", len(files), out.String())
	}
	data, _ := os.ReadFile(files[0])
	cfg, err := core.DecodeVpnKey(strings.TrimSpace(string(data)))
	if err != nil {
		t.Fatal(err)
	}
	if bad := leaks(out.String()+errOut.String(), thPw, strings.TrimSpace(string(data))); len(bad) > 0 {
		t.Fatalf("утечка: %v", bad)
	}
	if !strings.Contains(core.Str(cfg, "defaultContainer"), "amnezia-awg2") {
		t.Fatalf("в ключе нет контейнера: %v", cfg["defaultContainer"])
	}
}

// H1а доезд: без терминала, -apply -yes без -no-password/-password-file —
// отказ 2 ДО единой команды установки (настоящий Install не вызван).
func TestToHostEndToEndNoLayerStopsBeforeInstall(t *testing.T) {
	_, tgt, _ := newE2E(t)
	var out, errOut bytes.Buffer
	o := toHostOpts{srcKey: thSrcKey(t), host: thHost, port: "22", user: "root", knownHostsPath: filepath.Join(t.TempDir(), "kh"),
		mf: migrateFlags{apply: true, yes: true, addrOK: true}, noAgent: true}
	code := runMigrateToHost(context.Background(), strings.NewReader(""), &out, &errOut, false, o, time.Unix(1700000000, 0))
	if code != 2 || len(tgt.steps) != 0 || len(tgt.installed) != 0 {
		t.Fatalf("код %d, шагов установки %d\n%s\n%s", code, len(tgt.steps), out.String(), errOut.String())
	}
}
