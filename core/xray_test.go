package core_test

// AL-01: XRay (amnezia-xray). Стенд — fakesrv.NewXRay (шаблоны server.json
// из исходников amnezia-client, testdata/xray). Только публичный API.

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"testing"

	"amnezia-admin/core"
	"amnezia-admin/internal/fakesrv"
	"amnezia-admin/internal/guiview"

	"golang.org/x/crypto/curve25519"
)

const xrayConf = "/opt/amnezia/xray/server.json"
const xrayTbl = "/opt/amnezia/xray/clientsTable"

var reFullUUID = regexp.MustCompile(`[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)

func xraySession(t *testing.T, srv *fakesrv.Server) (*core.Session, *core.Container) {
	t.Helper()
	t.Cleanup(core.SetXRayWaits(0, 0))
	sess := core.NewSessionWithRunner(srv, raceCreds())
	cs, err := sess.FindContainers()
	if err != nil {
		t.Fatal(err)
	}
	for i := range cs {
		if cs[i].Name == core.XRayContainer {
			return sess, &cs[i]
		}
	}
	t.Fatalf("amnezia-xray не найден: %+v", cs)
	return nil, nil
}

func fileOf(t *testing.T, srv *fakesrv.Server, p string) []byte {
	t.Helper()
	b, ok := srv.File(p)
	if !ok {
		t.Fatalf("нет файла %s", p)
	}
	return b
}

func clientsOf(t *testing.T, srv *fakesrv.Server) map[string]map[string]any {
	t.Helper()
	var list []core.ClientEntry
	if err := json.Unmarshal(fileOf(t, srv, xrayTbl), &list); err != nil {
		t.Fatal(err)
	}
	out := map[string]map[string]any{}
	for _, c := range list {
		out[c.Name()] = map[string]any{"id": c.ClientID, "disabled": c.UserData["disabled"]}
	}
	return out
}

func writeCmds(srv *fakesrv.Server) int {
	n := 0
	for _, c := range srv.Commands() {
		if strings.Contains(c, "flock") || strings.HasPrefix(c, "docker restart") {
			n++
		}
	}
	return n
}

func contains(ids []string, id string) bool {
	for _, x := range ids {
		if x == id {
			return true
		}
	}
	return false
}

// TestXRayKnownBothTemplates — обе формы server.json из исходников
// (master и dev) опознаются, XRay управляется.
func TestXRayKnownBothTemplates(t *testing.T) {
	for _, v := range []string{"master", "dev"} {
		t.Run(v, func(t *testing.T) {
			_, c := xraySession(t, fakesrv.NewXRay(v))
			if !c.Managed() || c.Reason != "" || guiview.ProtoLabel(*c) != "XRay" {
				t.Fatalf("%+v, подпись %q", c, guiview.ProtoLabel(*c))
			}
		})
	}
}

// TestXRayFormatTable — закрытый список формы: каждое отступление —
// «формат не знаком» с названной причиной (без значений), не прочитанный
// файл — «не удалось прочитать». Тест различения: ни одно из них не
// «клиентов нет».
func TestXRayFormatTable(t *testing.T) {
	edit := func(f func(root map[string]any)) func(*fakesrv.Server) {
		return func(srv *fakesrv.Server) {
			b, _ := srv.File(xrayConf)
			var root map[string]any
			if err := json.Unmarshal(b, &root); err != nil {
				panic(err)
			}
			f(root)
			out, _ := json.MarshalIndent(root, "", "    ")
			srv.SetFile(xrayConf, out)
		}
	}
	in := func(root map[string]any) map[string]any { return root["inbounds"].([]any)[0].(map[string]any) }
	rs := func(root map[string]any) map[string]any {
		return in(root)["streamSettings"].(map[string]any)["realitySettings"].(map[string]any)
	}
	for _, c := range []struct {
		name   string
		mutate func(*fakesrv.Server)
		state  string // known | unknown | unreadable
		reason string
	}{
		{"как есть", func(*fakesrv.Server) {}, "known", ""},
		{"второй inbound", edit(func(r map[string]any) { r["inbounds"] = append(r["inbounds"].([]any), map[string]any{}) }), "unknown", "2 inbound"},
		{"протокол trojan", edit(func(r map[string]any) { in(r)["protocol"] = "trojan" }), "unknown", "не vless"},
		{"клиент с email", edit(func(r map[string]any) {
			cl := in(r)["settings"].(map[string]any)["clients"].([]any)[0].(map[string]any)
			cl["email"] = "x@y"
		}), "unknown", "поле email"},
		{"клиент с level", edit(func(r map[string]any) {
			cl := in(r)["settings"].(map[string]any)["clients"].([]any)[1].(map[string]any)
			cl["level"] = 0
		}), "unknown", "поле level"},
		{"xhttp", edit(func(r map[string]any) { in(r)["streamSettings"].(map[string]any)["network"] = "xhttp" }), "unknown", "не tcp"},
		{"tls вместо reality", edit(func(r map[string]any) { in(r)["streamSettings"].(map[string]any)["security"] = "tls" }), "unknown", "не reality"},
		{"лишнее поле inbound", edit(func(r map[string]any) { in(r)["sniffing"] = map[string]any{} }), "unknown", "поле sniffing"},
		{"api вверху", edit(func(r map[string]any) { r["api"] = map[string]any{} }), "unknown", "поле api"},
		{"два shortIds", edit(func(r map[string]any) { rs(r)["shortIds"] = []any{"ab", "cd"} }), "unknown", "shortIds"},
		{"privateKey не ключ", edit(func(r map[string]any) { rs(r)["privateKey"] = "zz" }), "unknown", "privateKey"},
		{"разный flow", edit(func(r map[string]any) {
			cl := in(r)["settings"].(map[string]any)["clients"].([]any)[1].(map[string]any)
			delete(cl, "flow")
		}), "unknown", "разный flow"},
		{"flow незнакомый у всех", edit(func(r map[string]any) {
			for _, c := range in(r)["settings"].(map[string]any)["clients"].([]any) {
				c.(map[string]any)["flow"] = "xtls-rprx-direct"
			}
		}), "unknown", "flow клиента №1"},
		{"id не UUID", edit(func(r map[string]any) {
			cl := in(r)["settings"].(map[string]any)["clients"].([]any)[2].(map[string]any)
			cl["id"] = "Alice"
		}), "unknown", "не UUID"},
		{"не JSON", func(s *fakesrv.Server) { s.SetFile(xrayConf, []byte("{")) }, "unknown", "не разбирается"},
		{"server.json не читается", func(s *fakesrv.Server) {
			s.FailRead = map[string]error{xrayConf: errors.New("i/o timeout")}
		}, "unreadable", "не удалось прочитать server.json"},
		{"нет xray_uuid.key", func(s *fakesrv.Server) { s.DeleteFile("/opt/amnezia/xray/xray_uuid.key") }, "unreadable", "xray_uuid.key"},
		{"xray_uuid.key не UUID", func(s *fakesrv.Server) { s.SetFile("/opt/amnezia/xray/xray_uuid.key", []byte("x\n")) }, "unknown", "xray_uuid.key не UUID"},
	} {
		t.Run(c.name, func(t *testing.T) {
			srv := fakesrv.NewXRay("dev")
			c.mutate(srv)
			sess, x := xraySession(t, srv)
			label := guiview.ProtoLabel(*x)
			switch c.state {
			case "known":
				if !x.Managed() {
					t.Fatalf("ждали управление: %q", label)
				}
				return
			case "unknown":
				if !strings.HasPrefix(label, "XRay — только просмотр: формат не знаком этой версии программы: ") || !strings.Contains(label, c.reason) {
					t.Errorf("подпись %q, ждали «формат не знаком … %s»", label, c.reason)
				}
			case "unreadable":
				if !strings.HasPrefix(label, "XRay — только просмотр: не удалось прочитать") || !strings.Contains(label, c.reason) {
					t.Errorf("подпись %q, ждали «не удалось прочитать … %s»", label, c.reason)
				}
			}
			if x.Managed() {
				t.Error("незнание формата дало управление")
			}
			// ни одной записи: план отказывает, перезапуска нет
			if _, err := sess.PlanAddUser(x, "Carol"); err == nil {
				t.Error("план создан при незнакомом формате")
			}
			if writeCmds(srv) != 0 || reFullUUID.MatchString(label) {
				t.Errorf("записей %d; подпись %q", writeCmds(srv), label)
			}
		})
	}
}

// TestXRayUnknownNotEmpty — различение: «формат не знаком» ≠ «клиентов
// нет». Пустая clientsTable при известном формате — управление и 0
// клиентов; незнакомый формат — только просмотр, а не «0».
func TestXRayUnknownNotEmpty(t *testing.T) {
	srv := fakesrv.NewXRay("master")
	srv.DeleteFile(xrayTbl)
	sess, x := xraySession(t, srv)
	v, err := sess.LoadXRayView(x)
	if err != nil || !x.Managed() || len(v.Clients) != 0 || len(v.Orphans) != 2 {
		t.Fatalf("нет clientsTable: %+v %v %v", v, err, x.Managed())
	}
	srv2 := fakesrv.NewXRay("master")
	b, _ := srv2.File(xrayConf)
	srv2.SetFile(xrayConf, []byte(strings.Replace(string(b), `"vless"`, `"vmess"`, 1)))
	sess2, x2 := xraySession(t, srv2)
	if x2.Managed() {
		t.Fatal("vmess управляется")
	}
	if _, err := sess2.LoadXRayView(x2); err == nil || !strings.Contains(err.Error(), "только просмотр") {
		t.Fatalf("LoadXRayView: %v", err)
	}
}

// TestXRayAddRestartsOnce — добавление: ровно 1 перезапуск, UUID в
// server.json и clientsTable, конфиг и ссылка с этим UUID и ключами сервера.
func TestXRayAddRestartsOnce(t *testing.T) {
	srv := fakesrv.NewXRay("master")
	sess, x := xraySession(t, srv)
	nu, err := sess.AddUser(x, "Carol")
	if err != nil {
		t.Fatal(err)
	}
	if srv.XRayRestarts() != 1 {
		t.Fatalf("перезапусков %d, ждали 1", srv.XRayRestarts())
	}
	id := clientsOf(t, srv)["Carol"]["id"].(string)
	if !contains(fakesrv.XRayIDs(fileOf(t, srv, xrayConf)), id) || !contains(srv.XRayRuntimeIDs(), id) {
		t.Fatal("UUID нового клиента нет в server.json или в работающем xray")
	}
	// ключ Reality — выведен из privateKey сервера
	var root map[string]any
	_ = json.Unmarshal(fileOf(t, srv, xrayConf), &root)
	priv := root["inbounds"].([]any)[0].(map[string]any)["streamSettings"].(map[string]any)["realitySettings"].(map[string]any)["privateKey"].(string)
	raw, _ := base64.RawURLEncoding.DecodeString(priv)
	pub, _ := curve25519.X25519(raw, curve25519.Basepoint)
	pbk := base64.RawURLEncoding.EncodeToString(pub)
	if !strings.HasPrefix(nu.Link, "vless://"+id+"@"+raceCreds().Host+":443?") || !strings.Contains(nu.Link, "pbk="+pbk) ||
		!strings.Contains(nu.Link, "flow=xtls-rprx-vision") || !strings.HasSuffix(nu.Link, "#AmneziaVPN") {
		t.Errorf("ссылка %q", nu.Link)
	}
	if !strings.Contains(nu.Config, id) || !strings.Contains(nu.Config, pbk) || nu.FileExt() != ".json" || nu.QRText() != nu.Link || !json.Valid([]byte(nu.Config)) {
		t.Errorf("конфиг %q ext %q", nu.Config, nu.FileExt())
	}
}

// TestXRayRenameNoRestart — переименование: server.json байт в байт
// прежний, 0 перезапусков.
func TestXRayRenameNoRestart(t *testing.T) {
	srv := fakesrv.NewXRay("dev")
	before := fileOf(t, srv, xrayConf)
	sess, x := xraySession(t, srv)
	id := clientsOf(t, srv)["Alice"]["id"].(string)
	p, err := sess.PlanRename(x, id, "Алиса")
	if err != nil {
		t.Fatal(err)
	}
	if p.RestartsXRay() {
		t.Error("переименование обещает перезапуск")
	}
	if err := sess.RenameUser(x, id, "Алиса"); err != nil {
		t.Fatal(err)
	}
	if srv.XRayRestarts() != 0 || string(fileOf(t, srv, xrayConf)) != string(before) {
		t.Fatalf("перезапусков %d; server.json изменён: %v", srv.XRayRestarts(), string(fileOf(t, srv, xrayConf)) != string(before))
	}
	if clientsOf(t, srv)["Алиса"] == nil {
		t.Fatal("имя не изменилось")
	}
}

// TestXRayDisableEnableDeleteRekey — остальные действия: каждое меняет
// server.json и перезапускает XRay один раз.
func TestXRayDisableEnableDeleteRekey(t *testing.T) {
	srv := fakesrv.NewXRay("dev")
	sess, x := xraySession(t, srv)
	alice := clientsOf(t, srv)["Alice"]["id"].(string)
	bob := clientsOf(t, srv)["Bob"]["id"].(string)

	if err := sess.SetEnabled(x, alice, false); err != nil {
		t.Fatal(err)
	}
	if contains(fakesrv.XRayIDs(fileOf(t, srv, xrayConf)), alice) || clientsOf(t, srv)["Alice"]["disabled"] != true || srv.XRayRestarts() != 1 {
		t.Fatalf("отключение: %v %v %d", fakesrv.XRayIDs(fileOf(t, srv, xrayConf)), clientsOf(t, srv)["Alice"], srv.XRayRestarts())
	}
	v, _ := sess.LoadXRayView(x)
	if v.Access[alice] != core.XRayDisabled || v.Access[bob] != core.XRayActive {
		t.Errorf("доступ: %v", v.Access)
	}
	if _, err := sess.RegenerateUser(x, alice); err == nil {
		t.Error("перевыпуск отключённого")
	}
	if _, err := sess.XRayClientConfig(x, alice); err == nil {
		t.Error("конфиг отключённого выдан")
	}
	if err := sess.SetEnabled(x, alice, true); err != nil {
		t.Fatal(err)
	}
	if !contains(fakesrv.XRayIDs(fileOf(t, srv, xrayConf)), alice) || clientsOf(t, srv)["Alice"]["disabled"] != nil || srv.XRayRestarts() != 2 {
		t.Fatalf("включение: %d", srv.XRayRestarts())
	}
	nu, err := sess.RegenerateUser(x, bob)
	if err != nil {
		t.Fatal(err)
	}
	nb := clientsOf(t, srv)["Bob"]["id"].(string)
	ids := fakesrv.XRayIDs(fileOf(t, srv, xrayConf))
	if nb == bob || contains(ids, bob) || !contains(ids, nb) || nu.Replaces != bob || !strings.Contains(nu.Link, nb) || srv.XRayRestarts() != 3 {
		t.Fatalf("перевыпуск: %v %d", ids, srv.XRayRestarts())
	}
	if err := sess.DeleteByID(x, alice); err != nil {
		t.Fatal(err)
	}
	if contains(fakesrv.XRayIDs(fileOf(t, srv, xrayConf)), alice) || clientsOf(t, srv)["Alice"] != nil || srv.XRayRestarts() != 4 {
		t.Fatal("удаление")
	}
	// конфиг существующего — с сервера, без записи
	before := len(srv.Commands())
	got, err := sess.XRayClientConfig(x, nb)
	if err != nil || !strings.Contains(got.Link, nb) {
		t.Fatalf("конфиг: %v", err)
	}
	for _, c := range srv.Commands()[before:] {
		if strings.Contains(c, "flock") || strings.Contains(c, "restart") {
			t.Errorf("показ конфига пишет: %q", c)
		}
	}
}

// TestXRayServiceUntouchable — служебный UUID: ни одно действие над ним
// не строит план (ни по строке списка, ни по самому UUID).
func TestXRayServiceUntouchable(t *testing.T) {
	srv := fakesrv.NewXRay("master")
	sess, x := xraySession(t, srv)
	key, _ := srv.File("/opt/amnezia/xray/xray_uuid.key")
	service := strings.TrimSpace(string(key))
	for _, id := range []string{core.XRayServiceRowID, service} {
		for name, f := range map[string]func() error{
			"delete":  func() error { _, err := sess.PlanDelete(x, id); return err },
			"disable": func() error { _, err := sess.PlanSetEnabled(x, id, false); return err },
			"rekey":   func() error { _, err := sess.PlanRekey(x, id); return err },
			"rename":  func() error { _, err := sess.PlanRename(x, id, "X"); return err },
		} {
			err := f()
			if err == nil || !strings.Contains(err.Error(), "служебный") || strings.Contains(err.Error(), service) {
				t.Errorf("%s(%s): %v", name, core.UUIDPrint(id), err)
			}
		}
	}
	v, err := sess.LoadXRayView(x)
	if err != nil || !v.ServiceListed || v.ServicePrint != core.UUIDPrint(service) || len(v.Orphans) != 0 {
		t.Fatalf("%+v %v", v, err)
	}
	// служебный UUID, записанный в clientsTable как клиент, — только просмотр
	tbl := fileOf(t, srv, xrayTbl)
	srv.SetFile(xrayTbl, []byte(strings.Replace(string(tbl), clientsOf(t, srv)["Alice"]["id"].(string), service, 1)))
	if _, err := sess.PlanAddUser(x, "Carol"); err == nil || !strings.Contains(err.Error(), "только просмотр") {
		t.Errorf("служебный в clientsTable: %v", err)
	}
}

// TestXRayRollbackTable — исходы перезапуска: третьи состояния возникают
// боевым путём (хуки fakesrv), откат — второй перезапуск.
func TestXRayRollbackTable(t *testing.T) {
	for _, c := range []struct {
		name     string
		hooks    fakesrv.XRayHooks
		restarts int
		want     error
		same     bool // файлы вернулись к прежним
	}{
		{"xray не поднялся, откат поднял", fakesrv.XRayHooks{DeadOnRestart: map[int]bool{1: true}}, 2, core.ErrRolledBack, true},
		{"не поднялся и после отката", fakesrv.XRayHooks{DeadOnRestart: map[int]bool{1: true, 2: true}}, 2, core.ErrRolledBackNotApplied, true},
		// проверка живости: 1 — перед записью (есть чем проверить), дальше — отказ
		{"проверить после перезапуска нечем", fakesrv.XRayHooks{FailLivenessFrom: 2}, 2, core.ErrRollbackUnverified, true},
		{"перезапуск отказал", fakesrv.XRayHooks{FailRestart: errors.New("Error response from daemon: boom")}, 0, core.ErrRolledBack, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			srv := fakesrv.NewXRay("master")
			srv.XRay = c.hooks
			conf0, tbl0 := fileOf(t, srv, xrayConf), fileOf(t, srv, xrayTbl)
			sess, x := xraySession(t, srv)
			_, err := sess.AddUser(x, "Carol")
			if !errors.Is(err, c.want) {
				t.Fatalf("ждали %v, получено %v", c.want, err)
			}
			if srv.XRayRestarts() != c.restarts {
				t.Errorf("перезапусков %d, ждали %d", srv.XRayRestarts(), c.restarts)
			}
			same := string(fileOf(t, srv, xrayConf)) == string(conf0) && string(fileOf(t, srv, xrayTbl)) == string(tbl0)
			if same != c.same {
				t.Errorf("файлы вернулись: %v", same)
			}
			if reFullUUID.MatchString(err.Error()) {
				t.Errorf("UUID в тексте ошибки: %v", err)
			}
		})
	}
}

// TestXRayPrecheckNoTool — проверить живость нечем (нет pidof, мусор в
// ответе) — запись не начинается: ни одной записи, ни одного перезапуска.
func TestXRayPrecheckNoTool(t *testing.T) {
	for name, h := range map[string]fakesrv.XRayHooks{
		"нет pidof":    {NoPidof: true},
		"мусор":        {Garbage: "zombie\n"},
		"exec отказал": {FailLivenessFrom: 1},
	} {
		t.Run(name, func(t *testing.T) {
			srv := fakesrv.NewXRay("dev")
			srv.XRay = h
			sess, x := xraySession(t, srv)
			_, err := sess.AddUser(x, "Carol")
			if !errors.Is(err, core.ErrWriteNotStarted) || writeCmds(srv) != 0 {
				t.Fatalf("%v; записей %d", err, writeCmds(srv))
			}
		})
	}
	// переименование живость не проверяет вовсе — работает и без pidof
	srv := fakesrv.NewXRay("dev")
	srv.XRay.NoPidof = true
	sess, x := xraySession(t, srv)
	if err := sess.RenameUser(x, clientsOf(t, srv)["Bob"]["id"].(string), "Боб"); err != nil {
		t.Fatal(err)
	}
}

// TestXRayPartialNoRestart — код 6: server.json заменён, clientsTable — нет;
// перезапуска нет, исход — «частично», текст называет server.json.
func TestXRayPartialNoRestart(t *testing.T) {
	srv := fakesrv.NewXRay("master")
	srv.FailMvTo = "clientsTable"
	sess, x := xraySession(t, srv)
	_, err := sess.AddUser(x, "Carol")
	if !errors.Is(err, core.ErrWritePartial) || srv.XRayRestarts() != 0 {
		t.Fatalf("%v; перезапусков %d", err, srv.XRayRestarts())
	}
	if !strings.Contains(err.Error(), "server.json заменён") || !strings.Contains(err.Error(), "XRay не перезапускался") {
		t.Errorf("текст: %v", err)
	}
}

// TestXRaySecretsNotShown — UUID и privateKey не попадают в предпросмотр и
// ошибки; граница maskFreeText прячет UUID.
func TestXRaySecretsNotShown(t *testing.T) {
	srv := fakesrv.NewXRay("dev")
	sess, x := xraySession(t, srv)
	alice := clientsOf(t, srv)["Alice"]["id"].(string)
	var plans []*core.Plan
	for _, f := range []func() (*core.Plan, error){
		func() (*core.Plan, error) { return sess.PlanAddUser(x, "Carol") },
		func() (*core.Plan, error) { return sess.PlanDelete(x, alice) },
		func() (*core.Plan, error) { return sess.PlanRekey(x, alice) },
		func() (*core.Plan, error) { return sess.PlanSetEnabled(x, alice, false) },
		func() (*core.Plan, error) { return sess.PlanRename(x, alice, "A") },
	} {
		p, err := f()
		if err != nil {
			t.Fatal(err)
		}
		plans = append(plans, p)
	}
	for _, p := range plans {
		a, b := p.Diff()
		if reFullUUID.MatchString(a+b) || strings.Contains(a+b, "privateKey") || b == "" {
			t.Errorf("%s: предпросмотр %q / %q", p.Action, a, b)
		}
	}
	if _, err := sess.PlanDelete(x, "11111111-2222-4333-8444-555555555555"); err == nil || reFullUUID.MatchString(err.Error()) {
		t.Errorf("ошибка с UUID: %v", err)
	}
	if got := core.MaskFreeTextForTest("bad id 11111111-2222-4333-8444-555555555555 in config"); reFullUUID.MatchString(got) {
		t.Errorf("maskFreeText: %q", got)
	}
}

// TestXRayOrphansAndMismatch — UUID без записи — сирота (не дописывается);
// запись без UUID в server.json — «нет доступа», а не «включён».
func TestXRayOrphansAndMismatch(t *testing.T) {
	srv := fakesrv.NewXRay("master")
	key, _ := srv.File("/opt/amnezia/xray/xray_uuid.key")
	service := strings.TrimSpace(string(key))
	alice := clientsOf(t, srv)["Alice"]["id"].(string)
	stray := fakesrv.RandUUID()
	srv.SetFile(xrayConf, []byte(fakesrv.XRayWithClients(string(fileOf(t, srv, xrayConf)), service, stray, clientsOf(t, srv)["Bob"]["id"].(string))))
	sess, x := xraySession(t, srv)
	v, err := sess.LoadXRayView(x)
	if err != nil {
		t.Fatal(err)
	}
	if v.Access[alice] != core.XRayNoAccess || core.XRayAccessText(v.Access[alice]) == core.XRayAccessText(core.XRayActive) {
		t.Errorf("Alice: %v", v.Access[alice])
	}
	if len(v.Orphans) != 1 || v.Orphans[0] != core.UUIDPrint(stray) {
		t.Errorf("сироты: %v", v.Orphans)
	}
	notes := strings.Join(core.XRayNotes(v), "\n")
	if !strings.Contains(notes, core.UUIDPrint(stray)) || strings.Contains(notes, stray) {
		t.Errorf("заметки: %q", notes)
	}
	if _, err := sess.XRayClientConfig(x, alice); err == nil {
		t.Error("конфиг выдан клиенту без доступа")
	}
	if core.XRayAccessText(core.XRayAccess(0)) != "неизвестно" {
		t.Error("нулевое состояние доступа — не «неизвестно»")
	}
}

// TestXRayWriteListClosed — server.json в закрытом списке команды записи,
// прочее — нет.
func TestXRayWriteListClosed(t *testing.T) {
	if _, err := core.CASWriteCommand(core.CASLabelApply, "amnezia-xray", "/opt/amnezia/xray", "server.json", strings.Repeat("a", 64), "absent"); err != nil {
		t.Fatal(err)
	}
	if _, err := core.CASWriteCommand(core.CASLabelApply, "amnezia-xray", "/opt/amnezia/xray", "config.json", strings.Repeat("a", 64), "absent"); err == nil {
		t.Fatal("config.json принят")
	}
}

// TestXRaySaveConfigJSON — файл конфига XRay: .json; чужой файл с тем же
// именем (другой UUID) не затирается; свой (rekey: прежний UUID) —
// перезаписывается.
func TestXRaySaveConfigJSON(t *testing.T) {
	srv := fakesrv.NewXRay("master")
	sess, x := xraySession(t, srv)
	dir := t.TempDir()
	bob := clientsOf(t, srv)["Bob"]["id"].(string)
	nu, err := sess.XRayClientConfig(x, bob)
	if err != nil {
		t.Fatal(err)
	}
	r, err := core.SaveUserConfig(dir, nu)
	if err != nil || !strings.HasSuffix(r.Path, "Bob.json") {
		t.Fatalf("%+v %v", r, err)
	}
	// другой клиент с тем же именем — файл занят
	other, err := sess.XRayClientConfig(x, clientsOf(t, srv)["Alice"]["id"].(string))
	if err != nil {
		t.Fatal(err)
	}
	other.Name = "Bob"
	r2, err := core.SaveUserConfig(dir, other)
	if err != nil || r2.Occupied == "" || !strings.HasSuffix(r2.Path, "Bob (2).json") {
		t.Fatalf("чужой файл: %+v %v", r2, err)
	}
	// перевыпуск Bob — свой файл перезаписывается
	nu2, err := sess.RegenerateUser(x, bob)
	if err != nil {
		t.Fatal(err)
	}
	r3, err := core.SaveUserConfig(dir, nu2)
	if err != nil || r3.Occupied != "" || !strings.HasSuffix(r3.Path, "Bob.json") {
		t.Fatalf("rekey: %+v %v", r3, err)
	}
	b, _ := os.ReadFile(r3.Path)
	if !strings.Contains(string(b), clientsOf(t, srv)["Bob"]["id"].(string)) {
		t.Fatal("в файле не новый UUID")
	}
	_ = fmt.Sprint
}
