package core

// Р-4 (перенос XRay): запись до шести файлов под замком A3б — server.json,
// clientsTable и ключи XRay из закрытого списка casExtraFiles. Тесты идут
// через fakesrv, который исполняет НАСТОЯЩИЙ CASWriteScript системным sh.

import (
	"errors"
	"strings"
	"testing"

	"amnezia-admin/internal/fakesrv"
)

// TestCASExtrasClosedList — в команду не попадает ничего вне закрытого
// списка: ключи XRay — только при server.json, без повторов, суммы — hex
// или absent. Без дополнительных файлов хвост команды прежний.
func TestCASExtrasClosedList(t *testing.T) {
	good := strings.Repeat("a", 64)
	ok := []CASExtra{{"xray_uuid.key", good}, {"xray_short_id.key", CASAbsent}, {"xray_public.key", good}, {"xray_private.key", good}}
	cmd, err := CASWriteCommand(CASLabelApply, "amnezia-xray", "/opt/amnezia/xray", "server.json", good, good, ok...)
	if err != nil {
		t.Fatalf("допустимый список отвергнут: %v", err)
	}
	if !strings.HasSuffix(cmd, " server.json xray_uuid.key "+good+" xray_short_id.key absent xray_public.key "+good+" xray_private.key "+good) {
		t.Fatalf("хвост команды не тот: …%s", cmd[len(cmd)-120:])
	}
	plain, err := CASWriteCommand(CASLabelApply, "amnezia-awg", "/opt/amnezia/awg", "wg0.conf", good, good)
	if err != nil || !strings.HasSuffix(plain, " "+good+" "+good+" wg0.conf") {
		t.Fatalf("без дополнительных файлов хвост изменился: %v …%s", err, plain[len(plain)-80:])
	}
	for _, cf := range []string{"wg0.conf", "awg0.conf"} {
		if _, err := CASWriteCommand(CASLabelApply, "amnezia-awg", "/opt/amnezia/awg", cf, good, good,
			CASExtra{"wireguard_server_public_key.key", good}, CASExtra{"wireguard_psk.key", CASAbsent}); err != nil {
			t.Errorf("ключи WG при %s отвергнуты: %v", cf, err)
		}
	}
	bad := []struct {
		name, file string
		xs         []CASExtra
	}{
		{"ключ XRay при wg0.conf", "wg0.conf", []CASExtra{{"xray_uuid.key", good}}},
		{"ключ XRay при awg0.conf", "awg0.conf", []CASExtra{{"xray_private.key", good}}},
		{"имя вне списка", "server.json", []CASExtra{{"xray_other.key", good}}},
		{"путь вместо имени", "server.json", []CASExtra{{"../xray_uuid.key", good}}},
		{"clientsTable как дополнительный", "server.json", []CASExtra{{"clientsTable", good}}},
		{"повтор", "server.json", []CASExtra{{"xray_uuid.key", good}, {"xray_uuid.key", good}}},
		{"ключ WG при server.json", "server.json", []CASExtra{{"wireguard_psk.key", good}}},
		{"ключ XRay при awg0.conf рядом с ключом WG", "awg0.conf", []CASExtra{{"wireguard_psk.key", good}, {"xray_uuid.key", good}}},
		{"сумма не hex", "server.json", []CASExtra{{"xray_uuid.key", "zz"}}},
		{"сумма с пробелом", "server.json", []CASExtra{{"xray_uuid.key", good + " x"}}},
	}
	for _, b := range bad {
		if _, err := CASWriteCommand(CASLabelApply, "amnezia-xray", "/opt/amnezia/xray", b.file, good, good, b.xs...); err == nil {
			t.Errorf("%s: ждали отказ", b.name)
		}
	}
}

const xdir = "/opt/amnezia/xray"

// extrasFixture — сервер XRay с четырьмя ключами и план «server.json не
// меняется, clientsTable та же, xray_public.key и xray_private.key —
// новые; xray_short_id.key — прежний; xray_uuid.key — прежний».
func extrasFixture(t *testing.T) (*fakesrv.Server, *Session, *Plan) {
	t.Helper()
	t.Cleanup(SetXRayWaits(0, 0))
	srv := fakesrv.NewXRay("master")
	srv.SetFile(xdir+"/xray_short_id.key", []byte("abcd1234\n"))
	srv.SetFile(xdir+"/xray_public.key", []byte("PUB-OLD\n"))
	srv.SetFile(xdir+"/xray_private.key", []byte("PRIV-OLD\n"))
	s := NewSessionWithRunner(srv, &ServerCreds{Host: "127.0.0.1", Port: "22", User: "root"})
	cs, err := s.FindContainers()
	if err != nil {
		t.Fatal(err)
	}
	var c *Container
	for i := range cs {
		if cs[i].Name == XRayContainer {
			c = &cs[i]
		}
	}
	if c == nil {
		t.Fatal("amnezia-xray не найден")
	}
	conf, _ := srv.File(xdir + "/server.json")
	tbl, _ := srv.File(xdir + "/clientsTable")
	uuid, _ := srv.File(xdir + "/xray_uuid.key")
	p := &Plan{Container: c, Action: "test", wgBefore: conf, wgAfter: conf, tblBefore: tbl, tblAfter: tbl, tblExisted: true,
		extra: []planExtra{
			{name: "xray_uuid.key", before: uuid, after: uuid, existed: true},
			{name: "xray_short_id.key", before: []byte("abcd1234\n"), after: []byte("abcd1234\n"), existed: true},
			{name: "xray_public.key", before: []byte("PUB-OLD\n"), after: []byte("PUB-NEW\n"), existed: true},
			{name: "xray_private.key", before: []byte("PRIV-OLD\n"), after: []byte("PRIV-NEW\n"), existed: true},
		}}
	s.fillSHA(p)
	return srv, s, p
}

func fileIs(t *testing.T, srv *fakesrv.Server, name, want string) {
	t.Helper()
	got, ok := srv.File(xdir + "/" + name)
	if !ok || string(got) != want {
		t.Errorf("%s = %q (есть=%v), ждали %q", name, got, ok, want)
	}
}

// TestCASExtrasApplyWritesKeys — изменившиеся ключи записаны, прежние не
// тронуты, резервные копии ключей сделаны, XRay не перезапускался
// (server.json не менялся).
func TestCASExtrasApplyWritesKeys(t *testing.T) {
	srv, s, p := extrasFixture(t)
	if _, err := s.Apply(p); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	fileIs(t, srv, "xray_public.key", "PUB-NEW\n")
	fileIs(t, srv, "xray_private.key", "PRIV-NEW\n")
	fileIs(t, srv, "xray_short_id.key", "abcd1234\n")
	if srv.XRayRestarts() != 0 {
		t.Errorf("перезапусков %d, ждали 0", srv.XRayRestarts())
	}
	backups := 0
	for _, c := range srv.Commands() {
		if strings.Contains(c, "/backup/xray_public.key.$ts") || strings.Contains(c, "/backup/xray_private.key.$ts") {
			backups++
		}
	}
	if backups != 2 {
		t.Errorf("резервных копий ключей %d, ждали 2 (public, private)", backups)
	}
	if srv.TempLeft != 0 {
		t.Errorf("остались временные файлы: %d", srv.TempLeft)
	}
}

// TestCASExtrasForeignKeyChange — тест различения: ключ изменён другим
// между чтением и записью → «изменился» с именем ключа, ничего не записано.
// Подмена «сверка дополнительных файлов выпала» роняет его.
func TestCASExtrasForeignKeyChange(t *testing.T) {
	srv, s, p := extrasFixture(t)
	srv.ForeignWrite = map[int]map[string][]byte{1: {xdir + "/xray_public.key": []byte("FOREIGN\n")}}
	_, err := s.Apply(p)
	if !errors.Is(err, ErrCASMismatch) {
		t.Fatalf("ждали ErrCASMismatch, получили %v", err)
	}
	if !strings.Contains(err.Error(), "xray_public.key") {
		t.Errorf("в ошибке нет имени ключа: %v", err)
	}
	fileIs(t, srv, "xray_public.key", "FOREIGN\n")
	fileIs(t, srv, "xray_private.key", "PRIV-OLD\n")
}

// TestCASExtrasPartial — mv ключа не удался после замены предыдущего ключа:
// код 6, «записано частично», названо что заменено и что нет (третье
// состояние, не «ничего не записано» и не «записано»).
func TestCASExtrasPartial(t *testing.T) {
	srv, s, p := extrasFixture(t)
	srv.FailMvTo = "xray_private.key"
	_, err := s.Apply(p)
	if !errors.Is(err, ErrWritePartial) || !errors.Is(err, ErrWriteUnknown) {
		t.Fatalf("ждали ErrWritePartial, получили %v", err)
	}
	want := "заменены: xray_public.key; НЕ заменены: xray_private.key, clientsTable"
	if !strings.Contains(err.Error(), want) {
		t.Errorf("в ошибке нет %q: %v", want, err)
	}
	fileIs(t, srv, "xray_public.key", "PUB-NEW\n")
	fileIs(t, srv, "xray_private.key", "PRIV-OLD\n")
}

// TestCASExtrasRefuseCreate — ключа на сервере нет, а план его меняет:
// отказ до записи (вернуть отсутствие откат не умеет).
func TestCASExtrasRefuseCreate(t *testing.T) {
	srv, s, p := extrasFixture(t)
	p.extra[1].existed, p.extra[1].before = false, nil
	before := len(srv.Commands())
	_, err := s.Apply(p)
	if !errors.Is(err, ErrWriteNotStarted) {
		t.Fatalf("ждали «запись не начиналась», получили %v", err)
	}
	for _, c := range srv.Commands()[before:] {
		if strings.Contains(c, "flock") || strings.Contains(c, "backup") {
			t.Errorf("до отказа ушла команда записи: %.80s", c)
		}
	}
}

// TestCASExtrasRollback — проверка после записи не прошла (ключ изменён
// после нашей записи) → откат НЕ стирает чужое (ErrRollbackForeign); а при
// сбое проверки server.json (XRay не поднялся) ключи возвращаются откатом.
func TestCASExtrasRollback(t *testing.T) {
	t.Run("чужая запись после нашей — откат не трогает", func(t *testing.T) {
		srv, s, p := extrasFixture(t)
		srv.ForeignWriteAfter = map[int]map[string][]byte{1: {xdir + "/xray_private.key": []byte("FOREIGN\n")}}
		_, err := s.Apply(p)
		if !errors.Is(err, ErrRollbackForeign) {
			t.Fatalf("ждали ErrRollbackForeign, получили %v", err)
		}
		fileIs(t, srv, "xray_private.key", "FOREIGN\n")
	})
	t.Run("XRay не поднялся — ключи откатаны", func(t *testing.T) {
		srv, s, p := extrasFixture(t)
		ids := fakesrv.XRayIDs(p.wgBefore)
		p.wgAfter = []byte(fakesrv.XRayWithClients(string(p.wgBefore), ids[:len(ids)-1]...))
		srv.XRay.DeadOnRestart = map[int]bool{1: true}
		_, err := s.Apply(p)
		if err == nil {
			t.Fatal("ждали ошибку")
		}
		fileIs(t, srv, "xray_public.key", "PUB-OLD\n")
		fileIs(t, srv, "xray_private.key", "PRIV-OLD\n")
		got, _ := srv.File(xdir + "/server.json")
		if string(got) != string(p.wgBefore) {
			t.Error("server.json не откатан")
		}
	})
}
