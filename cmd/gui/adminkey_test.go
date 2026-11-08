package main

import (
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"fyne.io/fyne/v2/storage"
	"fyne.io/fyne/v2/test"

	"amnezia-admin/core"
	"amnezia-admin/internal/fakesrv"
)

const guiAKPw = "Canary-GUI-AK-5d1e!"

var guiAKBody = regexp.MustCompile(`vpn://[A-Za-z0-9_-]{8}`)

// guiAKFixture — открытый сервер поверх fakesrv (настоящий
// AdminKeyReissuePlan), проверка входом и окно сохранения — подменные.
type guiAKFixture struct {
	u       *ui
	srv     *fakesrv.Server
	out     string
	verify  error
	written string
}

func newGUIAKFixture(t *testing.T, setup func(*fakesrv.Server)) *guiAKFixture {
	f := &guiAKFixture{srv: fakesrv.NewAWG2()}
	if setup != nil {
		setup(f.srv)
	}
	f.u = backupUI(t, f.srv, "203.0.113.31")
	f.u.sess.Creds.Password, f.u.sess.Creds.Port = guiAKPw, "22"
	f.out = filepath.Join(t.TempDir(), "admin.vpn.txt")
	v0, s0 := guiAdminKeyVerify, guiAdminKeySave
	t.Cleanup(func() { guiAdminKeyVerify, guiAdminKeySave = v0, s0 })
	guiAdminKeyVerify = func(core.AdminKey, core.AdminKeyInput, string, string) error { return f.verify }
	guiAdminKeySave = func(_ *ui, _ string, key core.AdminKey, done func(string, error)) {
		w, err := storage.Writer(storage.NewFileURI(f.out))
		if err != nil {
			done("", err)
			return
		}
		done(writeChosenAdminKey(w, key))
	}
	return f
}

// run — пункт меню «Копия» → «Выдать ключ vpn://…» и, если окно согласия
// есть, кнопка ok ("" — окна согласия быть не должно).
func (f *guiAKFixture) run(t *testing.T, ok string) string {
	t.Helper()
	f.u.backupMenu()
	test.Tap(buttonByText(t, topPopup(t, f.u.win.Canvas()), adminKeyMenuText))
	guiGoroutines.Wait()
	if ok != "" {
		b := findEsc(f.u.win.Canvas().Overlays().Top(), ok)
		if b == nil {
			t.Fatalf("нет кнопки %q в окне:\n%s", ok, topOverlay(t, f.u))
		}
		for _, other := range []string{adminKeyOKFull, adminKeyOKPartial} {
			if other != ok && findEsc(f.u.win.Canvas().Overlays().Top(), other) != nil {
				t.Fatalf("в окне и %q, и %q", ok, other)
			}
		}
		test.Tap(b)
		guiGoroutines.Wait()
	}
	all := topOverlay(t, f.u)
	if b, err := os.ReadFile(f.out); err == nil {
		f.written = strings.TrimSpace(string(b))
	}
	if strings.Contains(all, guiAKPw) || guiAKBody.MatchString(all) || (f.written != "" && strings.Contains(all, f.written)) {
		t.Fatal("ключ или пароль на экране")
	}
	return all
}

func TestGUIAdminKey(t *testing.T) {
	const conf = "/opt/amnezia/awg/awg0.conf"
	cases := []struct {
		name     string
		setup    func(*fakesrv.Server)
		verify   error
		ok       string
		wantFile bool
		want     []string
	}{
		{name: "полный: записан и проверен", ok: adminKeyOKFull, wantFile: true, want: []string{"Ключ vpn:// записан в файл", "Ключ проверен"}},
		// доезд: «не прочитан» — ошибка cat с сервера; протоколов не осталось
		{name: "параметры не прочитаны — не выдаётся", setup: func(s *fakesrv.Server) {
			s.FailRead = map[string]error{conf: errors.New("Permission denied")}
		}, want: []string{"НЕ в ключ: amnezia-awg2", "Ключ не выдаётся"}},
		{name: "часть не прочитана — только явная кнопка неполного", setup: func(s *fakesrv.Server) {
			s.Names = []string{"amnezia-awg2", "amnezia-foo"}
		}, ok: adminKeyOKPartial, wantFile: true, want: []string{"Ключ НЕПОЛНЫЙ: в нём нет amnezia-foo"}},
		{name: "список контейнеров не прочитан", setup: func(s *fakesrv.Server) { s.Names = nil }, want: []string{"состояние сервера неизвестно"}},
		{name: "сервер не принял пароль", verify: core.ErrAdminKeyAuthRejected, ok: adminKeyOKFull, want: []string{"НЕ годится"}},
		{name: "проверить не удалось — записан с оговоркой", verify: errors.New("сеть"), ok: adminKeyOKFull, wantFile: true,
			want: []string{"Ключ проверить не удалось", "записан в файл"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newGUIAKFixture(t, tc.setup)
			f.verify = tc.verify
			all := f.run(t, tc.ok)
			for _, w := range tc.want {
				if !strings.Contains(all, w) {
					t.Errorf("нет %q в окне:\n%s", w, all)
				}
			}
			if (f.written != "") != tc.wantFile {
				t.Fatalf("файл ключа: есть=%v, ожидалось %v", f.written != "", tc.wantFile)
			}
			if !tc.wantFile {
				return
			}
			cfg, err := core.DecodeVpnKey(f.written)
			if err != nil {
				t.Fatal("ключ в файле не разбирается")
			}
			if c, err := core.CredsFromConfig(cfg); err != nil || c.Password != guiAKPw {
				t.Fatal("в ключе не тот пароль")
			}
			if n := len(cfg["containers"].([]any)); n != 1 {
				t.Fatalf("контейнеров в ключе %d", n)
			}
		})
	}
}

// adminKeyPlanLines: третье состояние (не прочитано) отличается от полного
// и надписью кнопки, и текстом.
func TestGUIAdminKeyPlanLines(t *testing.T) {
	full := core.AdminKeyReissue{Containers: []core.AdminKeyContainer{{Name: "amnezia-awg2"}}, Default: "amnezia-awg2"}
	part := full
	part.Gaps = []core.AdminKeyGap{{Container: "amnezia-xray", Reason: "server.json не прочитан"}}
	none := core.AdminKeyReissue{Gaps: part.Gaps}
	for _, tc := range []struct {
		name string
		r    core.AdminKeyReissue
		ok   string
		can  bool
	}{{"полный", full, adminKeyOKFull, true}, {"неполный", part, adminKeyOKPartial, true}, {"нет протоколов", none, "", false}} {
		lines, ok, can := adminKeyPlanLines(tc.r, "root", "h")
		if ok != tc.ok || can != tc.can {
			t.Errorf("%s: ok=%q can=%v", tc.name, ok, can)
		}
		if len(tc.r.Gaps) > 0 && !strings.Contains(strings.Join(lines, "\n"), "НЕ в ключ: amnezia-xray") {
			t.Errorf("%s: пробел не назван", tc.name)
		}
	}
}
