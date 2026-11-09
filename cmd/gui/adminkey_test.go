package main

import (
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/storage"
	"fyne.io/fyne/v2/test"
	"fyne.io/fyne/v2/widget"

	"amnezia-admin/core"
	"amnezia-admin/internal/fakesrv"
)

const guiAKPw = "Canary-GUI-AK-5d1e!"

var guiAKNow = time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)

var guiAKBody = regexp.MustCompile(`vpn://[A-Za-z0-9_-]{8}`)

// guiAKFixture — открытый сервер поверх fakesrv (настоящий
// AdminKeyReissuePlan), проверка входом и окно сохранения — подменные.
type guiAKFixture struct {
	u       *ui
	srv     *fakesrv.Server
	out     string
	verify  error
	written string
	// savedName — имя файла, переданное в окно сохранения
	savedName string
	// okDisabled — кнопка выдачи была погашена в момент нажатия
	okDisabled bool
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
	f.u.keyMeta = adminKeyMeta{Description: "Мой сервер", DNS1: "9.9.9.9", DNS2: "1.0.0.1", Default: "amnezia-awg2"}
	guiAdminKeySave = func(_ *ui, name string, key core.AdminKey, done func(string, error)) {
		f.savedName = name
		p, err := adminKeySaveTo(storage.NewFileURI(filepath.Dir(f.out)), name, key)
		if err == nil {
			err = os.Rename(p, f.out)
		}
		done(f.out, err)
	}
	return f
}

// akChecks — флажки окна согласия по надписи.
func akChecks(root fyne.CanvasObject) map[string]*widget.Check {
	m := map[string]*widget.Check{}
	walkObjects(root, func(o fyne.CanvasObject) {
		if c, ok := o.(*widget.Check); ok {
			m[c.Text] = c
		}
	})
	return m
}

// run — пункт меню «Копия» → «Выдать ключ vpn://…» и, если окно согласия
// есть, отметить флажки tick и нажать ok ("" — окна согласия быть не
// должно). Нажатие на погашенную кнопку ничего не делает — как у человека.
func (f *guiAKFixture) run(t *testing.T, ok string, tick ...string) string {
	t.Helper()
	f.u.backupMenu()
	test.Tap(buttonByText(t, topPopup(t, f.u.win.Canvas()), adminKeyMenuText))
	guiGoroutines.Wait()
	if ok != "" {
		top := f.u.win.Canvas().Overlays().Top()
		b := findEsc(top, ok)
		if b == nil {
			t.Fatalf("нет кнопки %q в окне:\n%s", ok, topOverlay(t, f.u))
		}
		for _, other := range []string{adminKeyOKFull, adminKeyOKPartial} {
			if other != ok && findEsc(top, other) != nil {
				t.Fatalf("в окне и %q, и %q", ok, other)
			}
		}
		checks := akChecks(top)
		for _, c := range checks {
			if c.Checked {
				t.Fatalf("флажок %q отмечен заранее", c.Text)
			}
		}
		for _, n := range tick {
			c := checks[n]
			if c == nil {
				t.Fatalf("нет флажка %q", n)
			}
			test.Tap(c)
		}
		f.okDisabled = b.Disabled()
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
		tick     []string
		wantFile bool
		// head — итог первой строкой: одно из четырёх состояний кодов CLI
		head adminKeyOutcome
		// noHead — окна итога нет (кнопка погашена — окно согласия на месте)
		noHead bool
		want   []string
	}{
		{name: "полный: записан и проверен", ok: adminKeyOKFull, tick: []string{adminKeyPwCheck}, wantFile: true, head: akIssued,
			want: []string{"Ключ vpn:// записан в файл", "Ключ проверен"}},
		// доезд: «не прочитан» — ошибка cat с сервера; протоколов не осталось
		{name: "параметры не прочитаны — не выдаётся, неизвестно", setup: func(s *fakesrv.Server) {
			s.FailRead = map[string]error{conf: errors.New("Permission denied")}
		}, head: akUnknown, want: []string{"НЕ в ключ: amnezia-awg2", "Ключ не выдаётся"}},
		{name: "часть не прочитана — флажок и явная кнопка неполного", setup: func(s *fakesrv.Server) {
			s.Names = []string{"amnezia-awg2", "amnezia-foo"}
		}, ok: adminKeyOKPartial, tick: []string{adminKeyPwCheck, adminKeyPartialCheck}, wantFile: true, head: akIssued,
			want: []string{"Ключ НЕПОЛНЫЙ: в нём нет amnezia-foo"}},
		{name: "часть не прочитана, без согласия на неполный — кнопка погашена", setup: func(s *fakesrv.Server) {
			s.Names = []string{"amnezia-awg2", "amnezia-foo"}
		}, ok: adminKeyOKPartial, tick: []string{adminKeyPwCheck}, noHead: true, want: []string{adminKeyNeedPartial}},
		{name: "без согласия на пароль — кнопка погашена, ключа нет", ok: adminKeyOKFull, noHead: true, want: []string{adminKeyNeedPw}},
		// доезд третьего состояния: ошибка docker ps с сервера
		{name: "список контейнеров не прочитан", setup: func(s *fakesrv.Server) { s.Names = nil }, head: akUnknown, want: []string{"состояние сервера неизвестно"}},
		{name: "сервер не принял пароль", verify: core.ErrAdminKeyAuthRejected, ok: adminKeyOKFull, tick: []string{adminKeyPwCheck}, head: akNotIssued, want: []string{"НЕ годится"}},
		// доезд: VerifyAdminKey вернул не-«нет» и не-«да» — итог «неизвестно», не «выдан и проверен»
		{name: "проверить не удалось — записан, итог неизвестно", verify: errors.New("сеть"), ok: adminKeyOKFull, tick: []string{adminKeyPwCheck}, wantFile: true,
			head: akUnknown, want: []string{"Ключ проверить не удалось", "записан в файл"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newGUIAKFixture(t, tc.setup)
			f.verify = tc.verify
			all := f.run(t, tc.ok, tc.tick...)
			for _, w := range tc.want {
				if !strings.Contains(all, w) {
					t.Errorf("нет %q в окне:\n%s", w, all)
				}
			}
			heads := 0
			for _, o := range []adminKeyOutcome{akIssued, akNotIssued, akNoConsent, akUnknown} {
				if strings.Contains(all, adminKeyOutcomeHead(o)) {
					heads++
					if tc.noHead || o != tc.head {
						t.Errorf("итог %q, ожидался %v (нет итога: %v):\n%s", adminKeyOutcomeHead(o), adminKeyOutcomeHead(tc.head), tc.noHead, all)
					}
				}
			}
			if !tc.noHead && heads != 1 {
				t.Errorf("строк итога %d, нужна одна:\n%s", heads, all)
			}
			if tc.noHead != f.okDisabled && tc.ok != "" {
				t.Errorf("кнопка погашена=%v, ожидалось %v", f.okDisabled, tc.noHead)
			}
			if tc.wantFile && !strings.HasPrefix(f.savedName, "admin-203.0.113.31-") {
				t.Errorf("имя файла по умолчанию: %q", f.savedName)
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
			// M1: описание и DNS — из ключа открытого сервера, как в CLI
			if core.Str(cfg, "description") != "Мой сервер" || core.Str(cfg, "dns1") != "9.9.9.9" || core.Str(cfg, "dns2") != "1.0.0.1" {
				t.Fatalf("не перенесены description/dns: %q %q %q", core.Str(cfg, "description"), core.Str(cfg, "dns1"), core.Str(cfg, "dns2"))
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

// M2/L1 (ревью PR #75): существующий файл не перезаписывается (содержимое
// цело), место не в файловой системе — отказ, а не «записан, 0600».
func TestGUIAdminKeySaveTo(t *testing.T) {
	key, err := core.BuildAdminKey(core.AdminKeyInput{Host: "h", Port: 22, User: "root", Password: core.NewSecret([]byte(guiAKPw)), PasswordConsent: true})
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	prev := filepath.Join(dir, core.AdminKeyFileName("h", guiAKNow))
	if err := os.WriteFile(prev, []byte("прежнее"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := adminKeySaveTo(storage.NewFileURI(dir), filepath.Base(prev), key); err == nil || !strings.Contains(err.Error(), "не перезаписываю") {
		t.Fatalf("существующий файл: %v", err)
	}
	if b, _ := os.ReadFile(prev); string(b) != "прежнее" {
		t.Fatal("прежнее содержимое файла потеряно")
	}
	other, _ := storage.ParseURI("content://provider/dir")
	if _, err := adminKeySaveTo(other, "k.txt", key); !errors.Is(err, errAdminKeyNotFS) {
		t.Fatalf("не file: %v", err)
	}
	// имя с каталогом — отказ, файл вне выбранного каталога не создаётся
	for _, bad := range []string{"", "  ", ".", "..", "../k.txt", `..\k.txt`, "sub/k.txt", "C:k.txt"} {
		if _, err := adminKeySaveTo(storage.NewFileURI(dir), bad, key); err == nil {
			t.Errorf("имя %q принято", bad)
		}
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(dir), "k.txt")); err == nil {
		t.Fatal("файл записан вне выбранного каталога")
	}
	p, err := adminKeySaveTo(storage.NewFileURI(dir), " мой-ключ.txt ", key)
	if err != nil {
		t.Fatal(err)
	}
	if p != filepath.Join(dir, "мой-ключ.txt") {
		t.Fatalf("путь %q", p)
	}
	if b, _ := os.ReadFile(p); strings.TrimSpace(string(b)) != key.Reveal() {
		t.Fatal("в файле не тот ключ")
	}
	if runtime.GOOS != "windows" {
		if st, _ := os.Stat(p); st.Mode().Perm() != 0o600 {
			t.Fatalf("права %v", st.Mode().Perm())
		}
	}
}

// Тест различения: четыре итога (коды CLI 0/1/2/4) различимы первой строкой;
// «записан, но не проверен» — НЕИЗВЕСТНО, а не «выдан и проверен».
func TestGUIAdminKeyResultOutcome(t *testing.T) {
	p := filepath.Join(t.TempDir(), "k.txt")
	for _, tc := range []struct {
		name     string
		path     string
		err      error
		verified adminKeyOutcome
		want     adminKeyOutcome
	}{
		{"записан и проверен", p, nil, akIssued, akIssued},
		{"записан, проверить не удалось", p, nil, akUnknown, akUnknown},
		{"не записан", "", errors.New("диск"), akIssued, akNotIssued},
		{"не записан, не проверен", "", errors.New("диск"), akUnknown, akNotIssued},
		{"каталог не выбран", "", nil, akIssued, akNoConsent},
	} {
		o, text := adminKeyResultText(tc.path, tc.err, "root", nil, tc.verified, nil)
		if o != tc.want || !strings.HasPrefix(text, adminKeyOutcomeHead(tc.want)+"\n") {
			t.Errorf("%s: итог %d, текст:\n%s", tc.name, o, text)
		}
	}
	seen := map[string]bool{}
	for _, o := range []adminKeyOutcome{akIssued, akNotIssued, akNoConsent, akUnknown} {
		seen[adminKeyOutcomeHead(o)] = true
	}
	if len(seen) != 4 {
		t.Fatal("строки итога совпадают")
	}
}

// Согласие на пароль: без него adminKeyIssue ключ не собирает (даже если
// кнопку как-то нажали), а погашенная кнопка называет причину.
func TestGUIAdminKeyConsent(t *testing.T) {
	f := newGUIAKFixture(t, nil)
	r, err := guiAdminKeyPlan(f.u.sess, "")
	if err != nil {
		t.Fatal(err)
	}
	if k, o, _ := adminKeyIssue(f.u.sess, r, adminKeyMeta{}, false); k.Len() != 0 || o != akNoConsent {
		t.Fatalf("без согласия: len=%d итог=%d", k.Len(), o)
	}
	if k, o, _ := adminKeyIssue(f.u.sess, r, adminKeyMeta{}, true); k.Len() == 0 || o != akIssued {
		t.Fatalf("с согласием: len=%d итог=%d", k.Len(), o)
	}
	for _, tc := range []struct {
		pw, part bool
		name     string
		want     string
	}{
		{false, true, "k.txt", adminKeyNeedPw},
		{true, false, "k.txt", adminKeyNeedPartial},
		{true, true, "../k.txt", "Кнопка погашена: имя файла"},
		{true, true, "k.txt", ""},
	} {
		got := adminKeyGate(tc.pw, tc.part, tc.name)
		if (tc.want == "") != (got == "") || !strings.HasPrefix(got, tc.want) {
			t.Errorf("%+v: %q", tc, got)
		}
	}
}
